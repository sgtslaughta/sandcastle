// Package cilium renders the per-zone and per-grant DNS allow policies and
// reconciles them in the workspace namespace. It owns only objects carrying
// its managed-by label and never touches the static Phase 3 policies.
package cilium

import (
	"context"
	"errors"
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
// policies that are no longer desired. One bad object never blocks the rest:
// a revoked DNS grant must still be pruned. All failures are joined.
func Apply(ctx context.Context, dyn dynamic.Interface, desired []*unstructured.Unstructured) error {
	api := dyn.Resource(GVR).Namespace(Namespace)
	want := map[string]bool{}
	var errs []error
	for _, d := range desired {
		want[d.GetName()] = true
		cur, err := api.Get(ctx, d.GetName(), metav1.GetOptions{})
		switch {
		case apierrors.IsNotFound(err):
			if _, err := api.Create(ctx, d, metav1.CreateOptions{}); err != nil {
				errs = append(errs, fmt.Errorf("create %s: %w", d.GetName(), err))
			}
		case err != nil:
			errs = append(errs, fmt.Errorf("get %s: %w", d.GetName(), err))
		case cur.GetLabels()[ownerLabel] != ownerValue:
			errs = append(errs, fmt.Errorf("%s exists and is not managed by %s", d.GetName(), ownerValue))
		case !reflect.DeepEqual(cur.Object["spec"], d.Object["spec"]):
			upd := d.DeepCopy()
			upd.SetResourceVersion(cur.GetResourceVersion())
			if _, err := api.Update(ctx, upd, metav1.UpdateOptions{}); err != nil {
				errs = append(errs, fmt.Errorf("update %s: %w", d.GetName(), err))
			}
		}
	}
	list, err := api.List(ctx, metav1.ListOptions{LabelSelector: ownerLabel + "=" + ownerValue})
	if err != nil {
		return errors.Join(append(errs, fmt.Errorf("list: %w", err))...)
	}
	for _, item := range list.Items {
		if want[item.GetName()] {
			continue
		}
		if err := api.Delete(ctx, item.GetName(), metav1.DeleteOptions{}); err != nil && !apierrors.IsNotFound(err) {
			errs = append(errs, fmt.Errorf("delete %s: %w", item.GetName(), err))
		}
	}
	return errors.Join(errs...)
}
