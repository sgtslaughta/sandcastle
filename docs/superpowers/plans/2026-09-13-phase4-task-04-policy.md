# Phase 4 Build — Task 4: Go module, Docker Go runner, `policy` package

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 4: Go module, Docker Go runner, `policy` package

**Files:**
- Modify: `Makefile` (append targets)
- Create: `admin/go.mod`, `admin/internal/policy/policy.go`, `admin/internal/policy/policy_test.go`

**Interfaces:**
- Produces (used by Tasks 5, 7, 9, 11, 12):
  - `policy.Rule{Kind, Value string; Port int}`
  - `policy.Workspace{ID, Name, OwnerID, IP string}`
  - `policy.Input{DefaultZone string; ZoneRules map[string][]Rule; Assign map[string]string; Grants map[string][]Rule; Pods []Workspace}`
  - `policy.HostKey{Host string; Port int}`
  - `func ValidName(string) bool`, `func ValidRule(Rule) bool`
  - `func (Input) ZoneOf(ws string) string`, `func (Input) Effective(ws, kind string) []Rule`
  - `func HostIPs(Input) map[HostKey][]string`

- [ ] **Step 1: Append Makefile targets**

Append to `Makefile`:
```make
# Go runs in a container: the host and VM have no toolchain. Runs as the
# caller's uid so go.sum and build output stay user-owned.
GOCACHE_DIR := $(HOME)/.cache/sandcastle-go
GO_RUN = mkdir -p $(GOCACHE_DIR) && docker run --rm -u $$(id -u):$$(id -g) \
	-e HOME=/tmp -e GOCACHE=/cache/build -e GOMODCACHE=/cache/mod \
	-v $(GOCACHE_DIR):/cache -v $(CURDIR)/admin:/src -w /src $(GO_DOCKER_ARGS) golang:1.27

admin-go:   ## run a go command for sandcastle-admin, e.g. make admin-go ARGS='mod tidy'
	$(GO_RUN) go $(ARGS)

admin-test: ## sandcastle-admin unit tests (docker)
	$(GO_RUN) go test ./...
```

- [ ] **Step 2: Create the module**

`admin/go.mod`:
```
module github.com/sgtslaughta/sandcastle/admin

go 1.27
```

- [ ] **Step 3: Write the failing test** — `admin/internal/policy/policy_test.go`

```go
package policy

import (
	"reflect"
	"testing"
)

func TestValidName(t *testing.T) {
	for s, want := range map[string]bool{
		"example.com": true, "*.example.com": true, "a-b.c.io": true,
		"": false, "*": false, "*.com.": false, "Example.com": false,
		"10.0.0.1": false, "example": false, "ex ample.com": false,
		"*.*.example.com": false, "-a.com": false, "a.com:443": false,
	} {
		if got := ValidName(s); got != want {
			t.Errorf("ValidName(%q) = %v, want %v", s, got, want)
		}
	}
}

func TestValidRule(t *testing.T) {
	for _, c := range []struct {
		r    Rule
		want bool
	}{
		{Rule{"host", "example.com", 443}, true},
		{Rule{"host", "example.com", 80}, true},
		{Rule{"host", "example.com", 8443}, false},
		{Rule{"dns", "example.com", 0}, true},
		{Rule{"dns", "example.com", 53}, false},
		{Rule{"cidr", "example.com", 0}, false},
	} {
		if got := ValidRule(c.r); got != c.want {
			t.Errorf("ValidRule(%+v) = %v, want %v", c.r, got, c.want)
		}
	}
}

func TestHostIPs(t *testing.T) {
	in := Input{
		DefaultZone: "z-def",
		ZoneRules: map[string][]Rule{
			"z-def":  {{"host", "example.com", 443}, {"dns", "example.com", 0}},
			"z-lock": {},
		},
		Assign: map[string]string{"ws-b": "z-lock"},
		Grants: map[string][]Rule{
			"ws-b": {{"host", "example.org", 443}},
			"ws-c": {{"host", "bad host", 443}}, // invalid rules are ignored
		},
		Pods: []Workspace{
			{ID: "ws-a", IP: "10.42.0.9"},
			{ID: "ws-b", IP: "10.42.0.7"},
			{ID: "ws-c", IP: "10.42.0.8"},
			{ID: "ws-d", IP: ""}, // no IP yet: never granted
		},
	}
	want := map[HostKey][]string{
		{"example.com", 443}: {"10.42.0.8", "10.42.0.9"},
		{"example.org", 443}: {"10.42.0.7"},
	}
	if got := HostIPs(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("HostIPs = %v, want %v", got, want)
	}
	if z := in.ZoneOf("ws-b"); z != "z-lock" {
		t.Errorf("ZoneOf(ws-b) = %q", z)
	}
	if z := in.ZoneOf("ws-a"); z != "z-def" {
		t.Errorf("ZoneOf(ws-a) = %q", z)
	}
	if got := in.Effective("ws-a", "dns"); !reflect.DeepEqual(got, []Rule{{"dns", "example.com", 0}}) {
		t.Errorf("Effective dns = %v", got)
	}
}
```

- [ ] **Step 4: Run it to verify it fails**

Run: `make admin-test`
Expected: FAIL, `undefined: ValidName` (and friends).

- [ ] **Step 5: Implement** — `admin/internal/policy/policy.go`

```go
// Package policy turns zones, grants and running workspace pods into who may
// reach what. Pure functions, no I/O, so every rule is table-tested.
package policy

import (
	"regexp"
	"sort"
)

// Rule is one allowlist entry: a proxy host (Envoy) or a resolvable DNS name
// (Cilium).
type Rule struct {
	Kind  string // "host" or "dns"
	Value string // exact FQDN or "*.suffix", lowercase
	Port  int    // 443 or 80 for host rules, 0 for dns rules
}

// Workspace is a running workspace pod.
type Workspace struct {
	ID, Name, OwnerID, IP string
}

// Input is everything policy needs, loaded from Postgres plus the pod watcher.
type Input struct {
	DefaultZone string
	ZoneRules   map[string][]Rule // zone ID -> rules
	Assign      map[string]string // workspace ID -> zone ID; missing means default
	Grants      map[string][]Rule // workspace ID -> unexpired grants
	Pods        []Workspace
}

// HostKey is one proxy destination.
type HostKey struct {
	Host string
	Port int
}

var nameRE = regexp.MustCompile(`^(\*\.)?([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$`)

// ValidName accepts an exact lowercase FQDN or "*.suffix". The last label
// must be alphabetic, so IP literals never match, and a bare "*" never does.
func ValidName(s string) bool { return len(s) <= 253 && nameRE.MatchString(s) }

// ValidRule checks kind, port and name together.
func ValidRule(r Rule) bool {
	switch r.Kind {
	case "host":
		return (r.Port == 443 || r.Port == 80) && ValidName(r.Value)
	case "dns":
		return r.Port == 0 && ValidName(r.Value)
	}
	return false
}

// ZoneOf returns the workspace's assigned zone, else the default zone.
func (in Input) ZoneOf(ws string) string {
	if z, ok := in.Assign[ws]; ok {
		return z
	}
	return in.DefaultZone
}

// Effective is the workspace's zone rules plus its grants, of one kind.
// Invalid rows are dropped here too, so a bad database row can never reach
// Envoy or Cilium.
func (in Input) Effective(ws, kind string) []Rule {
	var out []Rule
	for _, rules := range [][]Rule{in.ZoneRules[in.ZoneOf(ws)], in.Grants[ws]} {
		for _, r := range rules {
			if r.Kind == kind && ValidRule(r) {
				out = append(out, r)
			}
		}
	}
	return out
}

// HostIPs inverts host rules: each host:port maps to the sorted, unique pod
// IPs allowed to reach it. Hosts nobody may reach are absent.
func HostIPs(in Input) map[HostKey][]string {
	set := map[HostKey]map[string]bool{}
	for _, p := range in.Pods {
		if p.IP == "" {
			continue
		}
		for _, r := range in.Effective(p.ID, "host") {
			k := HostKey{r.Value, r.Port}
			if set[k] == nil {
				set[k] = map[string]bool{}
			}
			set[k][p.IP] = true
		}
	}
	out := make(map[HostKey][]string, len(set))
	for k, ips := range set {
		for ip := range ips {
			out[k] = append(out[k], ip)
		}
		sort.Strings(out[k])
	}
	return out
}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `make admin-test`
Expected: `ok  github.com/sgtslaughta/sandcastle/admin/internal/policy`

- [ ] **Step 7: Commit**

```bash
git add Makefile admin/go.mod admin/internal/policy
git commit -m "feat(admin): add policy package and docker go runner"
```
