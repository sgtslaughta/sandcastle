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
