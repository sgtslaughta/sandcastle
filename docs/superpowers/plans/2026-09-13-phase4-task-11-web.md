# Phase 4 Build — Task 11: Web UI and form handlers

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 11: Web UI and form handlers

**Files:**
- Create: `admin/internal/store/storetest/storetest.go`
- Create: `admin/internal/web/web.go` (server, routes, helpers)
- Create: `admin/internal/web/handlers.go`
- Create: `admin/internal/web/templates/layout.html`, `request.html`, `mine.html`, `queue.html`, `zones.html`, `workspaces.html`, `audit.html`
- Create: `admin/internal/web/web_test.go`

**Interfaces:**
- Consumes: `store.*` (Task 9), `auth.Auth`, `auth.User`, `auth.Auth.Require`, `auth.Auth.Issue`, `Login`, `Callback`, `Logout` (Task 10), `policy.Workspace`, `policy.Rule`, `policy.ValidRule` (Task 4).
- Produces (used by Task 12):
  - `type Pods interface { Running() []policy.Workspace; ByIP(string) (policy.Workspace, bool); ByID(string) (policy.Workspace, bool) }` (satisfied by `*watch.Pods`)
  - `type Server struct { Store *store.Store; Auth *auth.Auth; Pods Pods; Changed func() }`
  - `func (s *Server) Routes() http.Handler`

Routes (all mutations are POST + CSRF via `Require`; success = 303 redirect):

| Route | Who | Does |
|---|---|---|
| `GET /healthz` | anyone | `ok` |
| `GET /login`, `GET /callback`, `POST /logout` | — | auth |
| `GET /{$}` | user | admin → `/queue`, else `/mine` |
| `GET /r?src=<ip>&host=<authority>` or `?ws=<id>&host=` | owner or admin | prefilled request form |
| `POST /requests` (ws, host, port, justification) | owner or admin | file → `/mine?filed=<id>` |
| `GET /mine` | user | own running workspaces, their denials and requests |
| `GET /queue` | admin | pending requests + recent denials |
| `POST /requests/{id}/approve` (ttl), `POST /requests/{id}/deny` | admin | decide → `/queue` |
| `GET /zones`; `POST /zones` (name); `POST /zones/{id}/clone` (name); `/rename` (name); `/delete`; `/default`; `/rules` (kind, value, port) | admin | zone admin → `/zones` |
| `POST /rules/{id}/delete` (back) | admin | delete zone rule / revoke grant → back (`/zones` or `/workspaces`) |
| `GET /workspaces`; `POST /workspaces/{id}/zone` (zone); `POST /workspaces/{id}/grants` (kind, value, port, ttl) | admin | move / direct grant → `/workspaces` |
| `GET /audit` | admin | newest 200 audit rows |

- [ ] **Step 1: Test helper** — `admin/internal/store/storetest/storetest.go`

```go
// Package storetest gives tests in other packages a migrated, seeded store
// on a fresh database. Needs ADMIN_TEST_DSN, set by `make admin-test`.
package storetest

import (
	"context"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sgtslaughta/sandcastle/admin/internal/store"
)

func New(t *testing.T, db string) *store.Store {
	t.Helper()
	dsn := os.Getenv("ADMIN_TEST_DSN")
	if dsn == "" {
		t.Skip("ADMIN_TEST_DSN not set")
	}
	ctx := context.Background()
	var conn *pgx.Conn
	var err error
	for i := 0; i < 30; i++ {
		if conn, err = pgx.Connect(ctx, dsn); err == nil {
			if err = conn.Ping(ctx); err == nil {
				break
			}
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"DROP DATABASE IF EXISTS " + db + " WITH (FORCE)", "CREATE DATABASE " + db} {
		if _, err := conn.Exec(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	conn.Close(ctx)
	u, _ := url.Parse(dsn)
	u.Path = "/" + db
	if err := store.Migrate(ctx, u.String(), "apppw"); err != nil {
		t.Fatal(err)
	}
	u.User = url.UserPassword("sandcastle_app", "apppw")
	s, err := store.Open(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	if err := s.Seed(ctx); err != nil {
		t.Fatal(err)
	}
	return s
}
```
ponytail: this duplicates `newStore` in `store_test.go`, which must stay in package `store` to reach the unexported pool for the audit-permission test.

- [ ] **Step 2: Write the failing test** — `admin/internal/web/web_test.go`

```go
package web

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/sgtslaughta/sandcastle/admin/internal/auth"
	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
	"github.com/sgtslaughta/sandcastle/admin/internal/store/storetest"
)

const wsAlice, wsBob = "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"

type fakePods []policy.Workspace

func (f fakePods) Running() []policy.Workspace { return f }
func (f fakePods) ByIP(ip string) (policy.Workspace, bool) {
	for _, w := range f {
		if w.IP == ip {
			return w, true
		}
	}
	return policy.Workspace{}, false
}
func (f fakePods) ByID(id string) (policy.Workspace, bool) {
	for _, w := range f {
		if w.ID == id {
			return w, true
		}
	}
	return policy.Workspace{}, false
}

func setup(t *testing.T) (*Server, *auth.Auth, *int) {
	a, err := auth.New(auth.Config{CoderURL: "http://coder.invalid", CoderInternalURL: "http://coder.invalid",
		ClientID: "c", ClientSecret: "s", CallbackURL: "http://admin.invalid/callback",
		Key: []byte(strings.Repeat("k", 32)), TestToken: "hook"})
	if err != nil {
		t.Fatal(err)
	}
	changes := 0
	s := &Server{Store: storetest.New(t, "sc_web"), Auth: a, Changed: func() { changes++ }, Pods: fakePods{
		{ID: wsAlice, Name: "alice-ws", OwnerID: "u-alice", IP: "10.42.0.9"},
		{ID: wsBob, Name: "bob-ws", OwnerID: "u-bob", IP: "10.42.0.7"},
	}}
	return s, a, &changes
}

func member(a *auth.Auth, id, name string) ([]*http.Cookie, string) {
	rec := httptest.NewRecorder()
	u := a.Issue(rec, auth.User{ID: id, Name: name})
	return rec.Result().Cookies(), u.CSRF
}

func do(h http.Handler, method, target string, form url.Values, cookies []*http.Cookie, bearer bool) *httptest.ResponseRecorder {
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req := httptest.NewRequest(method, target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for _, c := range cookies {
		req.AddCookie(c)
	}
	if bearer {
		req.Header.Set("Authorization", "Bearer hook")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestMemberRequestFlowAndAdminApproval(t *testing.T) {
	s, a, changes := setup(t)
	h, ctx := s.Routes(), context.Background()
	cookies, csrf := member(a, "u-alice", "alice")

	rec := do(h, "GET", "/r?src=10.42.0.9&host=pypi.org:443", nil, cookies, false)
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "pypi.org") || !strings.Contains(rec.Body.String(), "alice-ws") {
		t.Fatalf("request form = %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "default-src 'none'") {
		t.Error("missing CSP")
	}
	if rec := do(h, "GET", "/r?src=10.42.0.7&host=pypi.org:443", nil, cookies, false); rec.Code != 403 {
		t.Fatalf("other owner's workspace = %d", rec.Code)
	}
	if rec := do(h, "GET", "/r?src=10.42.0.9&host=10.0.0.1:443", nil, cookies, false); rec.Code != 400 {
		t.Fatalf("IP literal = %d", rec.Code)
	}

	form := url.Values{"csrf": {csrf}, "ws": {wsAlice}, "host": {"pypi.org"}, "port": {"443"}, "justification": {"packages"}}
	rec = do(h, "POST", "/requests", form, cookies, false)
	loc, _ := url.Parse(rec.Header().Get("Location"))
	id := loc.Query().Get("filed")
	if rec.Code != 303 || id == "" {
		t.Fatalf("file = %d %q %s", rec.Code, rec.Header().Get("Location"), rec.Body)
	}
	form.Set("ws", wsBob)
	if rec := do(h, "POST", "/requests", form, cookies, false); rec.Code != 403 {
		t.Fatalf("filing for bob's workspace = %d", rec.Code)
	}
	if rec := do(h, "GET", "/queue", nil, cookies, false); rec.Code != 403 {
		t.Fatalf("member on queue = %d", rec.Code)
	}
	if rec := do(h, "POST", "/requests/"+id+"/approve", url.Values{"csrf": {csrf}, "ttl": {"168h"}}, cookies, false); rec.Code != 403 {
		t.Fatalf("member approve = %d", rec.Code)
	}
	if rec := do(h, "POST", "/requests/"+id+"/approve", url.Values{"ttl": {"5m"}}, nil, true); rec.Code != 400 {
		t.Fatalf("unlisted ttl = %d", rec.Code)
	}
	before := *changes
	if rec := do(h, "POST", "/requests/"+id+"/approve", url.Values{"ttl": {"60s"}}, nil, true); rec.Code != 303 {
		t.Fatalf("approve = %d %s", rec.Code, rec.Body)
	}
	if *changes == before {
		t.Error("approval did not trigger a rebuild")
	}
	in, _ := s.Store.PolicyInput(ctx)
	if len(in.Grants[wsAlice]) != 1 {
		t.Fatalf("grants = %+v", in.Grants)
	}
	if body := do(h, "GET", "/mine", nil, cookies, false).Body.String(); !strings.Contains(body, "approved") {
		t.Error("mine page does not show the approved request")
	}
}

func TestAdminZonesAndWorkspaces(t *testing.T) {
	s, _, _ := setup(t)
	h, ctx := s.Routes(), context.Background()
	if rec := do(h, "POST", "/zones", url.Values{"name": {"restricted"}}, nil, true); rec.Code != 303 {
		t.Fatalf("create zone = %d %s", rec.Code, rec.Body)
	}
	zones, _ := s.Store.Zones(ctx)
	var restricted string
	for _, z := range zones {
		if z.Name == "restricted" {
			restricted = z.ID
		}
	}
	if rec := do(h, "POST", "/zones/"+restricted+"/rules", url.Values{"kind": {"dns"}, "value": {" Example.ORG "}, "port": {"443"}}, nil, true); rec.Code != 303 {
		t.Fatalf("add dns rule = %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/workspaces/"+wsBob+"/zone", url.Values{"zone": {restricted}}, nil, true); rec.Code != 303 {
		t.Fatalf("assign = %d %s", rec.Code, rec.Body)
	}
	if rec := do(h, "POST", "/workspaces/"+wsBob+"/grants", url.Values{"kind": {"host"}, "value": {"*"}, "port": {"443"}, "ttl": {"1h"}}, nil, true); rec.Code != 400 {
		t.Fatalf("bare * grant = %d", rec.Code)
	}
	in, _ := s.Store.PolicyInput(ctx)
	if in.Assign[wsBob] != restricted || len(in.ZoneRules[restricted]) != 1 || in.ZoneRules[restricted][0] != (policy.Rule{Kind: "dns", Value: "example.org"}) {
		t.Fatalf("policy input = %+v", in)
	}
	for _, page := range []string{"/zones", "/workspaces", "/audit", "/queue"} {
		if rec := do(h, "GET", page, nil, nil, true); rec.Code != 200 {
			t.Errorf("%s = %d %s", page, rec.Code, rec.Body)
		}
	}
	if body := do(h, "GET", "/workspaces", nil, nil, true).Body.String(); !strings.Contains(body, "bob-ws") || !strings.Contains(body, "restricted") {
		t.Error("workspaces page missing workspace or zone")
	}
	if rec := do(h, "GET", "/zones", nil, nil, false); rec.Code != 302 {
		t.Errorf("anonymous /zones = %d", rec.Code)
	}
}
```

- [ ] **Step 3: Run to verify it fails**

Run: `make admin-test`
Expected: FAIL, `undefined: Server`.

- [ ] **Step 4: Implement** — `admin/internal/web/web.go`

```go
// Package web serves sandcastle-admin's pages: server-rendered HTML with
// POST-redirect-GET forms and no JavaScript (DR-4.11).
package web

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/sgtslaughta/sandcastle/admin/internal/auth"
	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
	"github.com/sgtslaughta/sandcastle/admin/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

var pages = template.Must(template.ParseFS(tmplFS, "templates/*.html"))

// Pods is the running-workspace view; *watch.Pods satisfies it.
type Pods interface {
	Running() []policy.Workspace
	ByIP(ip string) (policy.Workspace, bool)
	ByID(id string) (policy.Workspace, bool)
}

type Server struct {
	Store   *store.Store
	Auth    *auth.Auth
	Pods    Pods
	Changed func() // policy may have changed: rebuild xDS and CNPs
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	user := func(p string, h func(http.ResponseWriter, *http.Request, auth.User)) { mux.HandleFunc(p, s.Auth.Require(false, h)) }
	admin := func(p string, h func(http.ResponseWriter, *http.Request, auth.User)) { mux.HandleFunc(p, s.Auth.Require(true, h)) }

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("ok\n")) })
	mux.HandleFunc("GET /login", s.Auth.Login)
	mux.HandleFunc("GET /callback", s.Auth.Callback)
	user("POST /logout", s.Auth.Logout)

	user("GET /{$}", s.home)
	user("GET /r", s.requestForm)
	user("POST /requests", s.fileRequest)
	user("GET /mine", s.mine)

	admin("GET /queue", s.queue)
	admin("POST /requests/{id}/approve", s.approve)
	admin("POST /requests/{id}/deny", s.deny)
	admin("GET /zones", s.zones)
	admin("POST /zones", s.createZone)
	admin("POST /zones/{id}/clone", s.cloneZone)
	admin("POST /zones/{id}/rename", s.renameZone)
	admin("POST /zones/{id}/delete", s.deleteZone)
	admin("POST /zones/{id}/default", s.defaultZone)
	admin("POST /zones/{id}/rules", s.addZoneRule)
	admin("POST /rules/{id}/delete", s.deleteRule)
	admin("GET /workspaces", s.workspaces)
	admin("POST /workspaces/{id}/zone", s.assign)
	admin("POST /workspaces/{id}/grants", s.grant)
	admin("GET /audit", s.audit)
	return secure(mux)
}

func secure(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		h.ServeHTTP(w, r)
	})
}

func render(w http.ResponseWriter, name string, data map[string]any) {
	var buf bytes.Buffer
	if err := pages.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, "render error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	buf.WriteTo(w)
}

// done ends a handler: 303 to `to` on success (after signalling a rebuild),
// otherwise a status matching the store error.
func (s *Server) done(w http.ResponseWriter, r *http.Request, err error, to string) {
	switch {
	case err == nil:
		s.Changed()
		http.Redirect(w, r, to, http.StatusSeeOther)
	case errors.Is(err, store.ErrInvalid):
		http.Error(w, "invalid input: "+err.Error(), http.StatusBadRequest)
	case errors.Is(err, store.ErrConflict):
		http.Error(w, "conflict: "+err.Error(), http.StatusConflict)
	case errors.Is(err, store.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	default:
		log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
		http.Error(w, "internal error", http.StatusInternalServerError)
	}
}

var ttls = map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "168h": 168 * time.Hour, "720h": 720 * time.Hour}

// ttlFor accepts the human TTL choices; 60s only for the test-hook bearer.
func ttlFor(r *http.Request, u auth.User) (time.Duration, error) {
	v := r.FormValue("ttl")
	if v == "" {
		v = "168h"
	}
	if d, ok := ttls[v]; ok {
		return d, nil
	}
	if v == "60s" && u.Bearer {
		return time.Minute, nil
	}
	return 0, fmt.Errorf("%w: ttl %q", store.ErrInvalid, v)
}

func ruleFrom(r *http.Request) policy.Rule {
	rule := policy.Rule{Kind: r.FormValue("kind"), Value: strings.ToLower(strings.TrimSpace(r.FormValue("value")))}
	if rule.Kind == "host" {
		rule.Port, _ = strconv.Atoi(r.FormValue("port"))
	}
	return rule
}

// hostPort splits an Envoy authority: CONNECT carries host:port, plain HTTP
// only the host.
func hostPort(authority string) (string, int) {
	authority = strings.ToLower(strings.TrimSpace(authority))
	if h, p, err := net.SplitHostPort(authority); err == nil {
		n, _ := strconv.Atoi(p)
		return h, n
	}
	return authority, 80
}

func own(u auth.User, ws policy.Workspace) bool { return u.Admin || ws.OwnerID == u.ID }

func (s *Server) names() map[string]string {
	m := map[string]string{}
	for _, w := range s.Pods.Running() {
		m[w.ID] = w.Name
	}
	return m
}

func back(r *http.Request) string {
	if b := r.FormValue("back"); b == "/workspaces" {
		return b
	}
	return "/zones"
}
```

- [ ] **Step 5: Implement** — `admin/internal/web/handlers.go`

```go
package web

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/sgtslaughta/sandcastle/admin/internal/auth"
	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
	"github.com/sgtslaughta/sandcastle/admin/internal/store"
)

func (s *Server) home(w http.ResponseWriter, r *http.Request, u auth.User) {
	if u.Admin {
		http.Redirect(w, r, "/queue", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/mine", http.StatusFound)
}

// requestForm is the landing page for the link in Envoy's 403 body.
func (s *Server) requestForm(w http.ResponseWriter, r *http.Request, u auth.User) {
	q := r.URL.Query()
	ws, ok := s.Pods.ByIP(q.Get("src"))
	if id := q.Get("ws"); id != "" {
		ws, ok = s.Pods.ByID(id)
	}
	if !ok {
		http.Error(w, "no running workspace matches this link; it may have restarted. Use My workspaces.", http.StatusNotFound)
		return
	}
	if !own(u, ws) {
		http.Error(w, "not your workspace", http.StatusForbidden)
		return
	}
	host, port := hostPort(q.Get("host"))
	if !policy.ValidRule(policy.Rule{Kind: "host", Value: host, Port: port}) {
		http.Error(w, "only host names on port 80 or 443 can be requested", http.StatusBadRequest)
		return
	}
	render(w, "request", map[string]any{"User": u, "WS": ws, "Host": host, "Port": port})
}

func (s *Server) fileRequest(w http.ResponseWriter, r *http.Request, u auth.User) {
	ws, ok := s.Pods.ByID(r.FormValue("ws"))
	if !ok {
		http.Error(w, "workspace not running", http.StatusNotFound)
		return
	}
	if !own(u, ws) {
		http.Error(w, "not your workspace", http.StatusForbidden)
		return
	}
	port, _ := strconv.Atoi(r.FormValue("port"))
	id, err := s.Store.FileRequest(r.Context(), u.Name, ws.ID, strings.ToLower(strings.TrimSpace(r.FormValue("host"))), port,
		strings.TrimSpace(r.FormValue("justification")))
	s.done(w, r, err, "/mine?filed="+url.QueryEscape(id))
}

func (s *Server) mine(w http.ResponseWriter, r *http.Request, u auth.User) {
	var mine []policy.Workspace
	ids, names := []string{}, map[string]string{} // non-nil ids: an empty filter matches nothing
	for _, ws := range s.Pods.Running() {
		if ws.OwnerID == u.ID {
			mine, ids, names[ws.ID] = append(mine, ws), append(ids, ws.ID), ws.Name
		}
	}
	denials, err := s.Store.Denials(r.Context(), ids)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	reqs, err := s.Store.Requests(r.Context(), "", ids)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	render(w, "mine", map[string]any{"User": u, "Workspaces": mine, "Denials": denials, "Requests": reqs, "Names": names, "Filed": r.URL.Query().Get("filed")})
}

func (s *Server) queue(w http.ResponseWriter, r *http.Request, u auth.User) {
	reqs, err := s.Store.Requests(r.Context(), "pending", nil)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	denials, err := s.Store.Denials(r.Context(), nil)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	render(w, "queue", map[string]any{"User": u, "Requests": reqs, "Denials": denials, "Names": s.names()})
}

func (s *Server) approve(w http.ResponseWriter, r *http.Request, u auth.User) {
	ttl, err := ttlFor(r, u)
	if err == nil {
		err = s.Store.Decide(r.Context(), u.Name, r.PathValue("id"), true, ttl)
	}
	s.done(w, r, err, "/queue")
}

func (s *Server) deny(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.Decide(r.Context(), u.Name, r.PathValue("id"), false, 0), "/queue")
}

func (s *Server) zones(w http.ResponseWriter, r *http.Request, u auth.User) {
	zones, err := s.Store.Zones(r.Context())
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	render(w, "zones", map[string]any{"User": u, "Zones": zones, "Names": s.names()})
}

func (s *Server) createZone(w http.ResponseWriter, r *http.Request, u auth.User) {
	_, err := s.Store.CreateZone(r.Context(), u.Name, strings.TrimSpace(r.FormValue("name")))
	s.done(w, r, err, "/zones")
}

func (s *Server) cloneZone(w http.ResponseWriter, r *http.Request, u auth.User) {
	_, err := s.Store.CloneZone(r.Context(), u.Name, r.PathValue("id"), strings.TrimSpace(r.FormValue("name")))
	s.done(w, r, err, "/zones")
}

func (s *Server) renameZone(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.RenameZone(r.Context(), u.Name, r.PathValue("id"), strings.TrimSpace(r.FormValue("name"))), "/zones")
}

func (s *Server) deleteZone(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.DeleteZone(r.Context(), u.Name, r.PathValue("id")), "/zones")
}

func (s *Server) defaultZone(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.SetDefaultZone(r.Context(), u.Name, r.PathValue("id")), "/zones")
}

func (s *Server) addZoneRule(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.AddZoneRule(r.Context(), u.Name, r.PathValue("id"), ruleFrom(r)), "/zones")
}

func (s *Server) deleteRule(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.DeleteRule(r.Context(), u.Name, r.PathValue("id")), back(r))
}

type wsRow struct {
	policy.Workspace
	Zone   string
	Grants []store.RuleRow
}

func (s *Server) workspaces(w http.ResponseWriter, r *http.Request, u auth.User) {
	ctx := r.Context()
	in, err := s.Store.PolicyInput(ctx)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	zones, err := s.Store.Zones(ctx)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	grants, err := s.Store.Grants(ctx)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	zoneNames := map[string]string{}
	for _, z := range zones {
		zoneNames[z.ID] = z.Name
	}
	var rows []wsRow
	for _, ws := range s.Pods.Running() {
		row := wsRow{Workspace: ws, Zone: in.ZoneOf(ws.ID)}
		for _, g := range grants {
			if g.WorkspaceID == ws.ID {
				row.Grants = append(row.Grants, g)
			}
		}
		rows = append(rows, row)
	}
	render(w, "workspaces", map[string]any{"User": u, "Rows": rows, "Zones": zones, "ZoneNames": zoneNames})
}

func (s *Server) assign(w http.ResponseWriter, r *http.Request, u auth.User) {
	s.done(w, r, s.Store.Assign(r.Context(), u.Name, r.PathValue("id"), r.FormValue("zone")), "/workspaces")
}

func (s *Server) grant(w http.ResponseWriter, r *http.Request, u auth.User) {
	ttl, err := ttlFor(r, u)
	if err == nil {
		err = s.Store.Grant(r.Context(), u.Name, r.PathValue("id"), ruleFrom(r), ttl)
	}
	s.done(w, r, err, "/workspaces")
}

func (s *Server) audit(w http.ResponseWriter, r *http.Request, u auth.User) {
	rows, err := s.Store.Audit(r.Context(), 200)
	if err != nil {
		s.done(w, r, err, "")
		return
	}
	render(w, "audit", map[string]any{"User": u, "Rows": rows})
}
```

- [ ] **Step 6: Templates**

`admin/internal/web/templates/layout.html`:
```html
{{define "head"}}<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>sandcastle admin</title>
<style>
body{font:14px system-ui,sans-serif;margin:0 auto;max-width:72rem;padding:0 1rem 2rem;color:#1b1f24;background:#fff}
nav{display:flex;gap:1rem;align-items:center;flex-wrap:wrap;padding:.75rem 0;border-bottom:1px solid #ddd;margin-bottom:1rem}
nav form{margin-left:auto}
.scroll{overflow-x:auto}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}
th,td{text-align:left;padding:.35rem .5rem;border-bottom:1px solid #eee;vertical-align:top}
form.inline{display:inline}
input,select,button,textarea{font:inherit;max-width:100%}
.muted{color:#666}
</style></head><body>
<nav><strong>sandcastle</strong>
{{if .User.Admin}}<a href="/queue">Queue</a><a href="/zones">Zones</a><a href="/workspaces">Workspaces</a><a href="/audit">Audit</a>{{end}}
<a href="/mine">My workspaces</a>
<form method="post" action="/logout">{{template "csrf" .User.CSRF}}<span class="muted">{{.User.Name}}</span> <button>Log out</button></form>
</nav>{{end}}

{{define "foot"}}</body></html>{{end}}

{{define "csrf"}}<input type="hidden" name="csrf" value="{{.}}">{{end}}

{{define "ttl"}}<select name="ttl" aria-label="Grant lifetime"><option value="1h">1 hour</option><option value="24h">1 day</option><option value="168h" selected>7 days</option><option value="720h">30 days</option></select>{{end}}
```

`admin/internal/web/templates/request.html`:
```html
{{define "request"}}{{template "head" .}}
<h1>Request access</h1>
<p>Workspace <strong>{{.WS.Name}}</strong> was denied <code>{{.Host}}:{{.Port}}</code>.</p>
<form method="post" action="/requests">{{template "csrf" .User.CSRF}}
<input type="hidden" name="ws" value="{{.WS.ID}}"><input type="hidden" name="host" value="{{.Host}}"><input type="hidden" name="port" value="{{.Port}}">
<p><label for="j">Why does this workspace need it?</label><br>
<textarea id="j" name="justification" rows="4" cols="60" required maxlength="2000"></textarea></p>
<button>Submit request</button></form>
{{template "foot"}}{{end}}
```

`admin/internal/web/templates/mine.html`:
```html
{{define "mine"}}{{template "head" .}}
{{if .Filed}}<p><strong>Request filed.</strong> An admin will review it.</p>{{end}}
<h1>My workspaces</h1>
<div class="scroll"><table><tr><th>Workspace</th><th>Address</th></tr>
{{range .Workspaces}}<tr><td>{{.Name}}</td><td>{{.IP}}</td></tr>{{else}}<tr><td colspan="2" class="muted">No running workspaces.</td></tr>{{end}}
</table></div>
<h2>Recent denials</h2>
<div class="scroll"><table><tr><th>Workspace</th><th>Destination</th><th>Count</th><th>Last seen</th><th></th></tr>
{{range .Denials}}<tr><td>{{index $.Names .WorkspaceID}}</td><td>{{.Host}}:{{.Port}}</td><td>{{.Count}}</td><td>{{.LastSeen.Format "2006-01-02 15:04:05"}}</td>
<td>{{if or (eq .Port 443) (eq .Port 80)}}<a href="/r?ws={{.WorkspaceID}}&amp;host={{.Host}}:{{.Port}}">Request access</a>{{end}}</td></tr>
{{else}}<tr><td colspan="5" class="muted">None.</td></tr>{{end}}
</table></div>
<h2>My requests</h2>
<div class="scroll"><table><tr><th>Workspace</th><th>Destination</th><th>Status</th><th>Decided by</th><th>Filed</th></tr>
{{range .Requests}}<tr><td>{{index $.Names .WorkspaceID}}</td><td>{{.Host}}:{{.Port}}</td><td>{{.Status}}</td><td>{{.DecidedBy}}</td><td>{{.CreatedAt.Format "2006-01-02 15:04"}}</td></tr>
{{else}}<tr><td colspan="5" class="muted">None.</td></tr>{{end}}
</table></div>
{{template "foot"}}{{end}}
```

`admin/internal/web/templates/queue.html`:
```html
{{define "queue"}}{{template "head" .}}
<h1>Pending requests</h1>
<div class="scroll"><table><tr><th>Workspace</th><th>Destination</th><th>Requester</th><th>Justification</th><th>Decision</th></tr>
{{range .Requests}}<tr><td>{{or (index $.Names .WorkspaceID) .WorkspaceID}}</td><td>{{.Host}}:{{.Port}}</td><td>{{.Requester}}</td><td>{{.Justification}}</td>
<td><form class="inline" method="post" action="/requests/{{.ID}}/approve">{{template "csrf" $.User.CSRF}}{{template "ttl"}} <button>Approve</button></form>
<form class="inline" method="post" action="/requests/{{.ID}}/deny">{{template "csrf" $.User.CSRF}}<button>Deny</button></form></td></tr>
{{else}}<tr><td colspan="5" class="muted">Queue is empty.</td></tr>{{end}}
</table></div>
<h2>Recent denials</h2>
<div class="scroll"><table><tr><th>Workspace</th><th>Destination</th><th>Count</th><th>Last seen</th></tr>
{{range .Denials}}<tr><td>{{or (index $.Names .WorkspaceID) .WorkspaceID}}</td><td>{{.Host}}:{{.Port}}</td><td>{{.Count}}</td><td>{{.LastSeen.Format "2006-01-02 15:04:05"}}</td></tr>
{{else}}<tr><td colspan="4" class="muted">None.</td></tr>{{end}}
</table></div>
{{template "foot"}}{{end}}
```

`admin/internal/web/templates/zones.html`:
```html
{{define "zones"}}{{template "head" .}}
<h1>Zones</h1>
<form method="post" action="/zones">{{template "csrf" .User.CSRF}}<label>New zone <input name="name" required pattern="[a-z0-9][a-z0-9-]{0,40}"></label> <button>Create</button></form>
{{range .Zones}}
<h2>{{.Name}}{{if .Default}} <span class="muted">(default)</span>{{end}}</h2>
<p class="muted">{{if .Default}}Every workspace not moved elsewhere.{{else}}{{len .Members}} workspace(s).{{end}}</p>
<div class="scroll"><table><tr><th>Kind</th><th>Value</th><th>Port</th><th></th></tr>
{{range .Rules}}<tr><td>{{.Kind}}</td><td>{{.Value}}</td><td>{{if eq .Kind "host"}}{{.Port}}{{end}}</td>
<td><form class="inline" method="post" action="/rules/{{.ID}}/delete">{{template "csrf" $.User.CSRF}}<button>Remove</button></form></td></tr>
{{else}}<tr><td colspan="4" class="muted">No rules: nothing allowed.</td></tr>{{end}}
</table></div>
<form method="post" action="/zones/{{.ID}}/rules">{{template "csrf" $.User.CSRF}}
<select name="kind" aria-label="Rule kind"><option value="host">proxy host</option><option value="dns">DNS name</option></select>
<input name="value" required placeholder="example.com or *.example.com" aria-label="Name">
<select name="port" aria-label="Port (host rules)"><option>443</option><option>80</option></select>
<button>Add rule</button></form>
<div>
<form class="inline" method="post" action="/zones/{{.ID}}/clone">{{template "csrf" $.User.CSRF}}<input name="name" required placeholder="clone name" aria-label="Clone name"> <button>Clone</button></form>
<form class="inline" method="post" action="/zones/{{.ID}}/rename">{{template "csrf" $.User.CSRF}}<input name="name" required placeholder="new name" aria-label="New name"> <button>Rename</button></form>
{{if not .Default}}<form class="inline" method="post" action="/zones/{{.ID}}/default">{{template "csrf" $.User.CSRF}}<button>Make default</button></form>
<form class="inline" method="post" action="/zones/{{.ID}}/delete">{{template "csrf" $.User.CSRF}}<button>Delete</button></form>{{end}}
</div>
{{end}}
{{template "foot"}}{{end}}
```

`admin/internal/web/templates/workspaces.html`:
```html
{{define "workspaces"}}{{template "head" .}}
<h1>Running workspaces</h1>
{{range .Rows}}{{$ws := .}}
<h2>{{.Name}} <span class="muted">{{.IP}}</span></h2>
<form method="post" action="/workspaces/{{.ID}}/zone">{{template "csrf" $.User.CSRF}}
<label>Zone <select name="zone">{{range $.Zones}}<option value="{{.ID}}"{{if eq .ID $ws.Zone}} selected{{end}}>{{.Name}}</option>{{end}}</select></label>
<button>Move</button> <span class="muted">now in {{index $.ZoneNames .Zone}}</span></form>
<div class="scroll"><table><tr><th>Grant</th><th>Port</th><th>Expires</th><th>By</th><th></th></tr>
{{range .Grants}}<tr><td>{{.Kind}} {{.Value}}</td><td>{{if eq .Kind "host"}}{{.Port}}{{end}}</td><td>{{if .ExpiresAt}}{{.ExpiresAt.Format "2006-01-02 15:04"}}{{end}}</td><td>{{.CreatedBy}}</td>
<td><form class="inline" method="post" action="/rules/{{.ID}}/delete">{{template "csrf" $.User.CSRF}}<input type="hidden" name="back" value="/workspaces"><button>Revoke</button></form></td></tr>
{{else}}<tr><td colspan="5" class="muted">No grants.</td></tr>{{end}}
</table></div>
<form method="post" action="/workspaces/{{.ID}}/grants">{{template "csrf" $.User.CSRF}}
<select name="kind" aria-label="Grant kind"><option value="host">proxy host</option><option value="dns">DNS name</option></select>
<input name="value" required placeholder="example.com" aria-label="Name">
<select name="port" aria-label="Port"><option>443</option><option>80</option></select>
{{template "ttl"}} <button>Grant</button></form>
{{else}}<p class="muted">No running workspaces.</p>{{end}}
{{template "foot"}}{{end}}
```

`admin/internal/web/templates/audit.html`:
```html
{{define "audit"}}{{template "head" .}}
<h1>Audit log</h1>
<div class="scroll"><table><tr><th>When</th><th>Actor</th><th>Action</th><th>Detail</th></tr>
{{range .Rows}}<tr><td>{{.At.Format "2006-01-02 15:04:05"}}</td><td>{{.Actor}}</td><td>{{.Action}}</td><td><code>{{.Detail}}</code></td></tr>{{end}}
</table></div>
{{template "foot"}}{{end}}
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `make admin-test`
Expected: `ok` for `internal/web` and every earlier package.

- [ ] **Step 8: Commit**

```bash
git add admin/internal/web admin/internal/store/storetest
git commit -m "feat(admin): add request queue, zone and workspace pages"
```
