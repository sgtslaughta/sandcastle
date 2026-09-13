// Package policy turns zones, grants and running workspace pods into who may
// reach what. Pure functions, no I/O, so every rule is table-tested.
package policy

import (
	"regexp"
	"sort"
	"strings"
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
// IPs allowed to reach it. Hosts nobody may reach are absent. Envoy routes a
// request to the most specific matching domain only, so every "*.suffix"
// key's IPs are also merged into each more specific key on the same port it
// covers (exact hosts and longer wildcards); otherwise a one-workspace grant
// for api.github.com would lock everyone else out of a *.github.com zone.
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
	for wk, wips := range set {
		suffix, ok := strings.CutPrefix(wk.Host, "*")
		if !ok {
			continue
		}
		for k, ips := range set {
			if k != wk && k.Port == wk.Port && strings.HasSuffix(k.Host, suffix) {
				for ip := range wips {
					ips[ip] = true
				}
			}
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
