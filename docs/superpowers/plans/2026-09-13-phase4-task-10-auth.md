# Phase 4 Build — Task 10: Coder OAuth2 login, signed sessions, CSRF, test hook

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 10: Coder OAuth2 login, signed sessions, CSRF, test hook

**Files:**
- Create: `admin/internal/auth/auth.go`, `admin/internal/auth/auth_test.go`

**Interfaces:**
- Produces (used by Tasks 11, 12):
  - `type Config struct { CoderURL, CoderInternalURL, ClientID, ClientSecret, CallbackURL string; Key []byte; TestToken string }`
  - `type User struct { ID, Name string; Admin bool; CSRF string; Exp int64; Bearer bool }`
  - `func New(c Config) (*Auth, error)`
  - `func (a *Auth) Login(w http.ResponseWriter, r *http.Request)`: GET `/login?next=`
  - `func (a *Auth) Callback(w http.ResponseWriter, r *http.Request)`: GET `/callback`
  - `func (a *Auth) Logout(w http.ResponseWriter, r *http.Request, _ User)`: POST `/logout`, wrap with `Require(false, ...)`
  - `func (a *Auth) User(r *http.Request) (User, bool)`
  - `func (a *Auth) Issue(w http.ResponseWriter, u User) User`: sets the session cookie; returns u with CSRF/Exp filled
  - `func (a *Auth) Require(admin bool, h func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc`

Facts from spike S1:
- Coder authorize is at `CoderURL/oauth2/authorize` (browser-facing) with PKCE S256.
- The token exchange is `POST /oauth2/tokens` with form params `client_id`/`client_secret`/`code`/`code_verifier`/`redirect_uri`. The server calls it on the in-cluster URL.
- `GET /api/v2/users/me` with `Authorization: Bearer <access_token>` returns `id`, `username`, and `roles[].name`.
- Admin = a role named `owner` or `user-admin`.

- [ ] **Step 1: Write the failing test** — `admin/internal/auth/auth_test.go`

```go
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
```

- [ ] **Step 2: Run to verify it fails**

Run: `make admin-go ARGS='get golang.org/x/oauth2' && make admin-test`
Expected: FAIL, `undefined: New`.

- [ ] **Step 3: Implement** — `admin/internal/auth/auth.go`

```go
// Package auth logs users in through Coder's OAuth2 provider (DR-4.1) and
// keeps them in an HMAC-signed cookie. No server-side session store: the
// cookie holds the Coder user ID, name, admin flag, CSRF token and expiry.
package auth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"
)

const (
	sessionCookie = "sc_session"
	flowCookie    = "sc_oauth"
	sessionTTL    = 8 * time.Hour
)

type Config struct {
	CoderURL         string // browser-facing, e.g. http://192.168.122.124:30080
	CoderInternalURL string // server-side, e.g. http://coder.coder.svc.cluster.local
	ClientID         string
	ClientSecret     string
	CallbackURL      string // e.g. http://192.168.122.124:30081/callback
	Key              []byte // cookie HMAC key, at least 32 bytes
	TestToken        string // bearer for infra/tests; empty disables the hook
}

type User struct {
	ID, Name string
	Admin    bool
	CSRF     string
	Exp      int64
	Bearer   bool `json:"-"`
}

// testUser is who the test-hook bearer acts as; audit rows show "test-hook".
var testUser = User{ID: "test-hook", Name: "test-hook", Admin: true, Bearer: true}

type flow struct {
	State, Verifier, Next string
	Exp                   int64
}

type Auth struct {
	c     Config
	oauth *oauth2.Config
	hc    *http.Client
}

func New(c Config) (*Auth, error) {
	if len(c.Key) < 32 {
		return nil, errors.New("session key must be at least 32 bytes")
	}
	return &Auth{c: c, hc: &http.Client{Timeout: 10 * time.Second}, oauth: &oauth2.Config{
		ClientID: c.ClientID, ClientSecret: c.ClientSecret, RedirectURL: c.CallbackURL,
		Endpoint: oauth2.Endpoint{
			AuthURL:   strings.TrimRight(c.CoderURL, "/") + "/oauth2/authorize",
			TokenURL:  strings.TrimRight(c.CoderInternalURL, "/") + "/oauth2/tokens",
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}}, nil
}

func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !strings.HasPrefix(next, "/") || strings.HasPrefix(next, "//") || strings.HasPrefix(next, "/\\") {
		next = "/"
	}
	f := flow{State: random(), Verifier: oauth2.GenerateVerifier(), Next: next, Exp: time.Now().Add(10 * time.Minute).Unix()}
	a.setSigned(w, flowCookie, f, 10*time.Minute)
	http.Redirect(w, r, a.oauth.AuthCodeURL(f.State, oauth2.S256ChallengeOption(f.Verifier)), http.StatusFound)
}

func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	var f flow
	state := r.URL.Query().Get("state")
	if !a.getSigned(r, flowCookie, &f) || f.Exp < time.Now().Unix() || subtle.ConstantTimeCompare([]byte(state), []byte(f.State)) != 1 {
		http.Error(w, "login expired or invalid; start again at /login", http.StatusBadRequest)
		return
	}
	a.setSigned(w, flowCookie, flow{}, -1)
	ctx := context.WithValue(r.Context(), oauth2.HTTPClient, a.hc)
	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(f.Verifier))
	if err != nil {
		http.Error(w, "coder token exchange failed", http.StatusBadGateway)
		return
	}
	u, err := a.me(ctx, tok.AccessToken)
	if err != nil {
		http.Error(w, "coder user lookup failed", http.StatusBadGateway)
		return
	}
	a.Issue(w, u)
	http.Redirect(w, r, f.Next, http.StatusFound)
}

// Issue starts a session for u with a fresh CSRF token and expiry. Callback
// uses it; web tests use it to act as a signed-in member.
func (a *Auth) Issue(w http.ResponseWriter, u User) User {
	u.CSRF, u.Exp, u.Bearer = random(), time.Now().Add(sessionTTL).Unix(), false
	a.setSigned(w, sessionCookie, u, sessionTTL)
	return u
}

func (a *Auth) Logout(w http.ResponseWriter, r *http.Request, _ User) {
	a.setSigned(w, sessionCookie, User{}, -1)
	http.Redirect(w, r, "/", http.StatusFound)
}

func (a *Auth) me(ctx context.Context, token string) (User, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", strings.TrimRight(a.c.CoderInternalURL, "/")+"/api/v2/users/me", nil)
	if err != nil {
		return User{}, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := a.hc.Do(req)
	if err != nil {
		return User{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return User{}, fmt.Errorf("users/me: %s", resp.Status)
	}
	var me struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Roles    []struct {
			Name string `json:"name"`
		} `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&me); err != nil || me.ID == "" {
		return User{}, fmt.Errorf("users/me: bad body: %v", err)
	}
	u := User{ID: me.ID, Name: me.Username}
	for _, role := range me.Roles {
		if role.Name == "owner" || role.Name == "user-admin" {
			u.Admin = true
		}
	}
	return u, nil
}

// User returns the caller from the test-hook bearer or the session cookie.
func (a *Auth) User(r *http.Request) (User, bool) {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		if a.c.TestToken != "" && subtle.ConstantTimeCompare([]byte(h[len("Bearer "):]), []byte(a.c.TestToken)) == 1 {
			return testUser, true
		}
		return User{}, false
	}
	var u User
	if !a.getSigned(r, sessionCookie, &u) || u.Exp < time.Now().Unix() {
		return User{}, false
	}
	return u, true
}

// Require enforces login, optional admin, and CSRF on every non-GET request.
// The bearer is CSRF-exempt: browsers never attach it on their own.
func (a *Auth) Require(admin bool, h func(http.ResponseWriter, *http.Request, User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, ok := a.User(r)
		if !ok {
			if r.Method == http.MethodGet {
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			http.Error(w, "login required", http.StatusUnauthorized)
			return
		}
		if admin && !u.Admin {
			http.Error(w, "admin only", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !u.Bearer &&
			subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(u.CSRF)) != 1 {
			http.Error(w, "invalid CSRF token; reload the page", http.StatusForbidden)
			return
		}
		h(w, r, u)
	}
}

// ponytail: cookies lack Secure because the lab UI is plain HTTP on a
// NodePort. Set Secure once the UI sits behind TLS.
func (a *Auth) setSigned(w http.ResponseWriter, name string, v any, ttl time.Duration) {
	payload, _ := json.Marshal(v)
	value := b64(payload) + "." + b64(a.mac(b64(payload)))
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, MaxAge: int(ttl.Seconds())})
}

func (a *Auth) getSigned(r *http.Request, name string, v any) bool {
	c, err := r.Cookie(name)
	if err != nil {
		return false
	}
	payload, sig, ok := strings.Cut(c.Value, ".")
	if !ok || !hmac.Equal([]byte(sig), []byte(b64(a.mac(payload)))) {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	return err == nil && json.Unmarshal(raw, v) == nil
}

func (a *Auth) mac(s string) []byte {
	m := hmac.New(sha256.New, a.c.Key)
	m.Write([]byte(s))
	return m.Sum(nil)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func random() string {
	b := make([]byte, 32)
	rand.Read(b)
	return b64(b)
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/auth` and all earlier packages.

- [ ] **Step 5: Commit**

```bash
git add admin/internal/auth admin/go.mod admin/go.sum
git commit -m "feat(admin): log in through coder oauth2 with signed sessions"
```
