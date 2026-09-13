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
