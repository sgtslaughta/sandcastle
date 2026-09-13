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
	user := func(p string, h func(http.ResponseWriter, *http.Request, auth.User)) {
		mux.HandleFunc(p, s.Auth.Require(false, h))
	}
	admin := func(p string, h func(http.ResponseWriter, *http.Request, auth.User)) {
		mux.HandleFunc(p, s.Auth.Require(true, h))
	}

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
