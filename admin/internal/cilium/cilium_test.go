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
	// ...without blocking the other desired objects or the prune.
	other := Render(policy.Input{DefaultZone: "x", ZoneRules: map[string][]policy.Rule{"x": {{Kind: "dns", Value: "d.com"}}}})[0]
	if err := Apply(ctx, dyn, []*unstructured.Unstructured{clash, other}); err == nil || !strings.Contains(err.Error(), "workspace-egress") {
		t.Fatalf("expected refusal to overwrite unmanaged policy, got %v", err)
	}
	list, _ = dyn.Resource(GVR).Namespace(Namespace).List(ctx, metav1.ListOptions{})
	if got := names(ptrs(list.Items)); got != "workspace-egress,ws-dns-zone-x" {
		t.Fatalf("after partial failure: %s", got)
	}
}

func ptrs(items []unstructured.Unstructured) []*unstructured.Unstructured {
	out := make([]*unstructured.Unstructured, len(items))
	for i := range items {
		out[i] = &items[i]
	}
	return out
}
