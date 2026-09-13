// Package watch tracks running workspace pods: the only source of pod IPs,
// which are the workspace identity Envoy sees (DR-3.5).
package watch

import (
	"context"
	"errors"
	"sort"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"

	"github.com/sgtslaughta/sandcastle/admin/internal/policy"
)

const (
	Namespace = "sandcastle-workspaces"
	wsLabel   = "com.coder.workspace.id"
)

type Pods struct {
	lister corelisters.PodLister
}

// Start begins watching and returns once the cache is synced. onChange runs
// on every add, update and delete; callers debounce.
func Start(ctx context.Context, cs kubernetes.Interface, onChange func()) (*Pods, error) {
	f := informers.NewSharedInformerFactoryWithOptions(cs, 10*time.Minute,
		informers.WithNamespace(Namespace),
		informers.WithTweakListOptions(func(o *metav1.ListOptions) { o.LabelSelector = wsLabel }))
	inf := f.Core().V1().Pods()
	if _, err := inf.Informer().AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    func(any) { onChange() },
		UpdateFunc: func(any, any) { onChange() },
		DeleteFunc: func(any) { onChange() },
	}); err != nil {
		return nil, err
	}
	f.Start(ctx.Done())
	if !cache.WaitForCacheSync(ctx.Done(), inf.Informer().HasSynced) {
		return nil, errors.New("workspace pod cache did not sync")
	}
	return &Pods{lister: inf.Lister()}, nil
}

// Running lists workspace pods that are Running, have an IP and are not
// terminating.
func (p *Pods) Running() []policy.Workspace {
	pods, _ := p.lister.List(labels.Everything())
	var out []policy.Workspace
	for _, pod := range pods {
		l := pod.Labels
		if l[wsLabel] == "" || pod.Status.Phase != corev1.PodRunning || pod.Status.PodIP == "" || pod.DeletionTimestamp != nil {
			continue
		}
		out = append(out, policy.Workspace{
			ID: l[wsLabel], Name: l["com.coder.workspace.name"], OwnerID: l["com.coder.user.id"], IP: pod.Status.PodIP,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].IP < out[j].IP
	})
	return out
}

func (p *Pods) ByIP(ip string) (policy.Workspace, bool) {
	for _, w := range p.Running() {
		if w.IP == ip {
			return w, true
		}
	}
	return policy.Workspace{}, false
}

func (p *Pods) ByID(id string) (policy.Workspace, bool) {
	for _, w := range p.Running() {
		if w.ID == id {
			return w, true
		}
	}
	return policy.Workspace{}, false
}
