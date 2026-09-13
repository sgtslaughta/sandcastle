package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func fakeCoder(t *testing.T, roles string) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth2/tokens":
			r.ParseForm()
			if r.Form.Get("code") != "good" || r.Form.Get("code_verifier") == "" || r.Form.Get("client_secret") != "sec" {
				http.Error(w, "bad exchange", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"access_token":"at","token_type":"bearer"}`))
		case "/api/v2/users/me":
			if r.Header.Get("Authorization") != "Bearer at" {
				http.Error(w, "unauthorized", 401)
				return
			}
			w.Write([]byte(`{"id":"u1","username":"alice","roles":[` + roles + `]}`))
		default:
			http.NotFound(w, r)
		}
	}))
}

func newAuth(t *testing.T, coder *httptest.Server) *Auth {
	a, err := New(Config{CoderURL: coder.URL, CoderInternalURL: coder.URL, ClientID: "cid", ClientSecret: "sec",
		CallbackURL: "http://admin/callback", Key: []byte(strings.Repeat("k", 32)), TestToken: "hook"})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func cookies(rec *httptest.ResponseRecorder) []*http.Cookie { return rec.Result().Cookies() }

func login(t *testing.T, a *Auth) []*http.Cookie {
	rec := httptest.NewRecorder()
	a.Login(rec, httptest.NewRequest("GET", "/login?next=/queue", nil))
	loc, _ := url.Parse(rec.Header().Get("Location"))
	if rec.Code != 302 || !strings.HasSuffix(loc.Path, "/oauth2/authorize") || loc.Query().Get("code_challenge_method") != "S256" {
		t.Fatalf("login redirect = %d %s", rec.Code, loc)
	}
	req := httptest.NewRequest("GET", "/callback?code=good&state="+loc.Query().Get("state"), nil)
	for _, c := range cookies(rec) {
		req.AddCookie(c)
	}
	rec = httptest.NewRecorder()
	a.Callback(rec, req)
	if rec.Code != 302 || rec.Header().Get("Location") != "/queue" {
		t.Fatalf("callback = %d %s %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	return cookies(rec)
}

func withCookies(req *http.Request, cs []*http.Cookie) *http.Request {
	for _, c := range cs {
		req.AddCookie(c)
	}
	return req
}

func TestLoginFlowAdmin(t *testing.T) {
	coder := fakeCoder(t, `{"name":"owner"}`)
	defer coder.Close()
	a := newAuth(t, coder)
	u, ok := a.User(withCookies(httptest.NewRequest("GET", "/", nil), login(t, a)))
	if !ok || u.Name != "alice" || u.ID != "u1" || !u.Admin || u.CSRF == "" || u.Exp < time.Now().Unix() {
		t.Fatalf("user = %+v %v", u, ok)
	}
}

func TestCallbackRejectsWrongState(t *testing.T) {
	coder := fakeCoder(t, `{"name":"owner"}`)
	defer coder.Close()
	a := newAuth(t, coder)
	rec := httptest.NewRecorder()
	a.Login(rec, httptest.NewRequest("GET", "/login", nil))
	req := withCookies(httptest.NewRequest("GET", "/callback?code=good&state=forged", nil), cookies(rec))
	rec = httptest.NewRecorder()
	a.Callback(rec, req)
	if rec.Code != 400 {
		t.Fatalf("forged state = %d", rec.Code)
	}
}

func TestRequire(t *testing.T) {
	coder := fakeCoder(t, `{"name":"member"}`)
	defer coder.Close()
	a := newAuth(t, coder)
	sess := login(t, a)
	u, _ := a.User(withCookies(httptest.NewRequest("GET", "/", nil), sess))
	if u.Admin {
		t.Fatal("member must not be admin")
	}
	called := false
	h := func(w http.ResponseWriter, r *http.Request, u User) { called = true }

	run := func(admin bool, req *http.Request) int {
		called = false
		rec := httptest.NewRecorder()
		a.Require(admin, h)(rec, req)
		return rec.Code
	}
	if code := run(false, httptest.NewRequest("GET", "/mine", nil)); code != 302 || called {
		t.Errorf("anonymous GET = %d", code)
	}
	if code := run(true, withCookies(httptest.NewRequest("GET", "/queue", nil), sess)); code != 403 || called {
		t.Errorf("member on admin page = %d", code)
	}
	post := func(form string) *http.Request {
		r := httptest.NewRequest("POST", "/requests", strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return withCookies(r, sess)
	}
	if code := run(false, post("csrf=wrong")); code != 403 || called {
		t.Errorf("bad csrf = %d", code)
	}
	if run(false, post("csrf="+url.QueryEscape(u.CSRF))); !called {
		t.Error("valid csrf rejected")
	}
	bearer := httptest.NewRequest("POST", "/zones", nil)
	bearer.Header.Set("Authorization", "Bearer hook")
	if run(true, bearer); !called {
		t.Error("test hook bearer rejected")
	}
	bearer.Header.Set("Authorization", "Bearer nope")
	if code := run(true, bearer); code != 401 || called {
		t.Errorf("wrong bearer = %d", code)
	}
}

func TestTamperedSessionAndOpenRedirect(t *testing.T) {
	coder := fakeCoder(t, `{"name":"owner"}`)
	defer coder.Close()
	a := newAuth(t, coder)
	sess := login(t, a)
	for _, c := range sess {
		if c.Name == sessionCookie {
			payload, _ := json.Marshal(User{ID: "u2", Name: "mallory", Admin: true, Exp: time.Now().Add(time.Hour).Unix()})
			c.Value = b64(payload) + c.Value[strings.Index(c.Value, "."):]
		}
	}
	if _, ok := a.User(withCookies(httptest.NewRequest("GET", "/", nil), sess)); ok {
		t.Fatal("tampered session accepted")
	}
	rec := httptest.NewRecorder()
	a.Login(rec, httptest.NewRequest("GET", "/login?next=//evil.example", nil))
	var f flow
	req := withCookies(httptest.NewRequest("GET", "/", nil), cookies(rec))
	if !a.getSigned(req, flowCookie, &f) || f.Next != "/" {
		t.Fatalf("open redirect not neutralized: %+v", f)
	}
}
