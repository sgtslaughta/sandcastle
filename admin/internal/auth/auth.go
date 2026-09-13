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
