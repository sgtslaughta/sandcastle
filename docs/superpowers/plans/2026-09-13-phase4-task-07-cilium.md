# Phase 4 Build — Task 7: Cilium DNS policy render + apply/prune

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 7: Cilium DNS policy render + apply/prune

**Files:**
- Create: `admin/internal/cilium/cilium.go`, `admin/internal/cilium/cilium_test.go`

**Interfaces:**
- Consumes: `policy.Input`, `policy.Rule`, `policy.ValidRule` (Task 4).
- Produces (used by Task 12):
  - `const Namespace = "sandcastle-workspaces"`
  - `var GVR schema.GroupVersionResource` (cilium.io/v2 ciliumnetworkpolicies)
  - `func Render(in policy.Input) []*unstructured.Unstructured`
  - `func Apply(ctx context.Context, dyn dynamic.Interface, desired []*unstructured.Unstructured) error`

Rendering rules (spec "Cilium (DNS rules)", spike S4):
- Per zone with ≥1 valid DNS rule: `ws-dns-zone-<zoneID>`.
  - Non-default zone: selector `In [assigned workspace IDs]`; skip the zone when nobody is assigned.
  - Default zone: `Exists`, plus `NotIn [IDs assigned to non-default zones]` when that list is non-empty.
- Per workspace with ≥1 valid DNS grant: `ws-dns-grant-<workspaceID>`, `In [that ID]`.
- `*.suffix` renders as `matchPattern`; an exact name as `matchName`.
- Every object carries the label `app.kubernetes.io/managed-by: sandcastle-admin`.
- Output is sorted by name.

- [ ] **Step 1: Write the failing test** — `admin/internal/cilium/cilium_test.go`

```go
package cilium

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

func names(objs []*unstructured.Unstructured) string {
	var n []string
	for _, o := range objs {
		n = append(n, o.GetName())
	}
	return strings.Join(n, ",")
}

func selector(t *testing.T, o *unstructured.Unstructured) string {
	t.Helper()
	b, _ := json.Marshal(o.Object["spec"].(map[string]any)["endpointSelector"])
	return string(b)
}

func TestRender(t *testing.T) {
	in := policy.Input{
		DefaultZone: "zdef",
		ZoneRules: map[string][]policy.Rule{
			"zdef":   {{Kind: "dns", Value: "example.com"}, {Kind: "host", Value: "example.com", Port: 443}},
			"zbuild": {{Kind: "dns", Value: "*.docker.io"}},
			"zempty": {{Kind: "host", Value: "example.org", Port: 443}},
			"znone":  {{Kind: "dns", Value: "example.net"}},
		},
		Assign: map[string]string{"ws2": "zbuild", "ws1": "zbuild", "ws3": "zempty", "ws4": "zdef"},
		Grants: map[string][]policy.Rule{"ws9": {{Kind: "dns", Value: "pypi.org"}}, "ws8": {{Kind: "host", Value: "x.io", Port: 443}}},
	}
	objs := Render(in)
	if got, want := names(objs), "ws-dns-grant-ws9,ws-dns-zone-zbuild,ws-dns-zone-zdef"; got != want {
		t.Fatalf("names = %s, want %s", got, want)
	}
	if s := selector(t, objs[1]); s != `{"matchExpressions":[{"key":"com.coder.workspace.id","operator":"In","values":["ws1","ws2"]}]}` {
		t.Errorf("zbuild selector = %s", s)
	}
	if s := selector(t, objs[2]); s != `{"matchExpressions":[{"key":"com.coder.workspace.id","operator":"Exists"},{"key":"com.coder.workspace.id","operator":"NotIn","values":["ws1","ws2","ws3"]}]}` {
		t.Errorf("default selector = %s", s)
	}
	spec, _ := json.Marshal(objs[1].Object["spec"])
	if !strings.Contains(string(spec), `"matchPattern":"*.docker.io"`) {
		t.Errorf("wildcard not rendered as matchPattern: %s", spec)
	}
	spec, _ = json.Marshal(objs[0].Object["spec"])
	if !strings.Contains(string(spec), `"matchName":"pypi.org"`) || objs[0].GetLabels()["app.kubernetes.io/managed-by"] != "sandcastle-admin" {
		t.Errorf("grant CNP wrong: %s", spec)
	}
}

func TestRenderDefaultWithoutAssignmentsIsExistsOnly(t *testing.T) {
	objs := Render(policy.Input{DefaultZone: "z", ZoneRules: map[string][]policy.Rule{"z": {{Kind: "dns", Value: "example.com"}}}})
	if len(objs) != 1 || selector(t, objs[0]) != `{"matchExpressions":[{"key":"com.coder.workspace.id","operator":"Exists"}]}` {
		t.Fatalf("got %v", names(objs))
	}
}

func TestApplyCreatesUpdatesPrunesOnlyOwned(t *testing.T) {
	ctx := context.Background()
	stale := Render(policy.Input{DefaultZone: "old", ZoneRules: map[string][]policy.Rule{"old": {{Kind: "dns", Value: "a.com"}}}})[0]
	foreign := &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
		"metadata": map[string]any{"name": "workspace-egress", "namespace": Namespace},
		"spec":     map[string]any{"endpointSelector": map[string]any{}},
	}}
	dyn := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(runtime.NewScheme(),
		map[schema.GroupVersionResource]string{GVR: "CiliumNetworkPolicyList"}, stale, foreign)

	desired := Render(policy.Input{DefaultZone: "new", ZoneRules: map[string][]policy.Rule{"new": {{Kind: "dns", Value: "b.com"}}}})
	if err := Apply(ctx, dyn, desired); err != nil {
		t.Fatal(err)
	}
	list, err := dyn.Resource(GVR).Namespace(Namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if got := names(ptrs(list.Items)); got != "workspace-egress,ws-dns-zone-new" {
		t.Fatalf("after apply: %s", got)
	}
	// Second apply with a changed rule updates in place.
	desired = Render(policy.Input{DefaultZone: "new", ZoneRules: map[string][]policy.Rule{"new": {{Kind: "dns", Value: "c.com"}}}})
	if err := Apply(ctx, dyn, desired); err != nil {
		t.Fatal(err)
	}
	cur, _ := dyn.Resource(GVR).Namespace(Namespace).Get(ctx, "ws-dns-zone-new", metav1.GetOptions{})
	if b, _ := json.Marshal(cur.Object["spec"]); !strings.Contains(string(b), "c.com") {
		t.Fatalf("not updated: %s", b)
	}
	// A desired name colliding with an unmanaged object is refused.
	clash := desired[0].DeepCopy()
	clash.SetName("workspace-egress")
	if err := Apply(ctx, dyn, []*unstructured.Unstructured{clash}); err == nil {
		t.Fatal("expected refusal to overwrite unmanaged policy")
	}
}

func ptrs(items []unstructured.Unstructured) []*unstructured.Unstructured {
	out := make([]*unstructured.Unstructured, len(items))
	for i := range items {
		out[i] = &items[i]
	}
	return out
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make admin-go ARGS='get k8s.io/client-go@v0.37.0 k8s.io/apimachinery@v0.37.0' && make admin-test`
Expected: FAIL, `undefined: Render`.

- [ ] **Step 3: Implement** — `admin/internal/cilium/cilium.go`

```go
// Package cilium renders the per-zone and per-grant DNS allow policies and
// reconciles them in the workspace namespace. It owns only objects carrying
// its managed-by label and never touches the static Phase 3 policies.
package cilium

import (
	"context"
	"fmt"
	"reflect"
	"sort"
	"strings"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

const (
	Namespace  = "sandcastle-workspaces"
	wsLabel    = "com.coder.workspace.id"
	ownerLabel = "app.kubernetes.io/managed-by"
	ownerValue = "sandcastle-admin"
)

var GVR = schema.GroupVersionResource{Group: "cilium.io", Version: "v2", Resource: "ciliumnetworkpolicies"}

// Render returns the desired policies, sorted by name. An empty DNS rule list
// would allow every name, so policies without rules are never emitted, and
// neither is an In selector with no values.
func Render(in policy.Input) []*unstructured.Unstructured {
	members := map[string][]string{}
	var elsewhere []string
	for ws, z := range in.Assign {
		if z != in.DefaultZone {
			members[z] = append(members[z], ws)
			elsewhere = append(elsewhere, ws)
		}
	}
	sort.Strings(elsewhere)

	var out []*unstructured.Unstructured
	for z, rules := range in.ZoneRules {
		dns := dnsRules(rules)
		if len(dns) == 0 {
			continue
		}
		var expr []any
		if z == in.DefaultZone {
			// Exists keeps unlabeled pods out: NotIn alone matches them.
			expr = []any{match("Exists", nil)}
			if len(elsewhere) > 0 {
				expr = append(expr, match("NotIn", elsewhere))
			}
		} else {
			ids := members[z]
			if len(ids) == 0 {
				continue
			}
			sort.Strings(ids)
			expr = []any{match("In", ids)}
		}
		out = append(out, cnp("ws-dns-zone-"+z, expr, dns))
	}
	for ws, rules := range in.Grants {
		if dns := dnsRules(rules); len(dns) > 0 {
			out = append(out, cnp("ws-dns-grant-"+ws, []any{match("In", []string{ws})}, dns))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetName() < out[j].GetName() })
	return out
}

func match(op string, values []string) any {
	m := map[string]any{"key": wsLabel, "operator": op}
	if values != nil {
		vs := make([]any, len(values))
		for i, v := range values {
			vs[i] = v
		}
		m["values"] = vs
	}
	return m
}

func dnsRules(rules []policy.Rule) []any {
	var out []any
	for _, r := range rules {
		if r.Kind != "dns" || !policy.ValidRule(r) {
			continue
		}
		if strings.HasPrefix(r.Value, "*.") {
			out = append(out, map[string]any{"matchPattern": r.Value})
		} else {
			out = append(out, map[string]any{"matchName": r.Value})
		}
	}
	return out
}

func cnp(name string, expr, dns []any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "cilium.io/v2",
		"kind":       "CiliumNetworkPolicy",
		"metadata": map[string]any{
			"name": name, "namespace": Namespace,
			"labels": map[string]any{ownerLabel: ownerValue},
		},
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchExpressions": expr},
			"egress": []any{map[string]any{
				"toEndpoints": []any{map[string]any{"matchLabels": map[string]any{
					"k8s:io.kubernetes.pod.namespace": "kube-system", "k8s:k8s-app": "kube-dns",
				}}},
				"toPorts": []any{map[string]any{
					"ports": []any{
						map[string]any{"port": "53", "protocol": "UDP"},
						map[string]any{"port": "53", "protocol": "TCP"},
					},
					"rules": map[string]any{"dns": dns},
				}},
			}},
		},
	}}
}

// Apply creates or updates every desired policy, then deletes managed
// policies that are no longer desired.
func Apply(ctx context.Context, dyn dynamic.Interface, desired []*unstructured.Unstructured) error {
	api := dyn.Resource(GVR).Namespace(Namespace)
	want := map[string]bool{}
	for _, d := range desired {
		want[d.GetName()] = true
		cur, err := api.Get(ctx, d.GetName(), metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			if _, err := api.Create(ctx, d, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("create %s: %w", d.GetName(), err)
			}
		case err != nil:
			return fmt.Errorf("get %s: %w", d.GetName(), err)
		case cur.GetLabels()[ownerLabel] != ownerValue:
			return fmt.Errorf("%s exists and is not managed by %s", d.GetName(), ownerValue)
		case !reflect.DeepEqual(cur.Object["spec"], d.Object["spec"]):
			upd := d.DeepCopy()
			upd.SetResourceVersion(cur.GetResourceVersion())
			if _, err := api.Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("update %s: %w", d.GetName(), err)
			}
		}
	}
	list, err := api.List(ctx, metav1.ListOptions{LabelSelector: ownerLabel + "=" + ownerValue})
	if err != nil {
		return fmt.Errorf("list: %w", err)
	}
	for _, item := range list.Items {
		if want[item.GetName()] {
			continue
		}
		if err := api.Delete(ctx, item.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete %s: %w", item.GetName(), err)
		}
	}
	return nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/cilium`, `internal/policy`, `internal/xds`.

- [ ] **Step 5: Commit**

```bash
git add admin/internal/cilium admin/go.mod admin/go.sum
git commit -m "feat(admin): reconcile per-zone cilium dns policies"
```
