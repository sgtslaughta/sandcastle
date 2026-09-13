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
	// ws= must not override src=: the authority in the 403 link is agent-controlled.
	if rec := do(h, "GET", "/r?src=10.42.0.9&ws="+wsBob+"&host=pypi.org:443", nil, cookies, false); rec.Code != 200 ||
		!strings.Contains(rec.Body.String(), wsAlice) || strings.Contains(rec.Body.String(), "bob-ws") {
		t.Fatalf("ws= overrode src= : %d %s", rec.Code, rec.Body)
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
