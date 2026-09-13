# Phase 4 Build — Task 8: Workspace pod watcher

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Plan index, Global Constraints and File Map:** [2026-09-13-phase4-build.md](2026-09-13-phase4-build.md). The Global Constraints apply to this task.

### Task 8: Workspace pod watcher

**Files:**
- Create: `admin/internal/watch/pods.go`, `admin/internal/watch/pods_test.go`

**Interfaces:**
- Consumes: `policy.Workspace` (Task 4).
- Produces (used by Tasks 11, 12):
  - `func Start(ctx context.Context, cs kubernetes.Interface, onChange func()) (*Pods, error)`
  - `func (p *Pods) Running() []policy.Workspace` (sorted by ID, then IP)
  - `func (p *Pods) ByIP(ip string) (policy.Workspace, bool)`
  - `func (p *Pods) ByID(id string) (policy.Workspace, bool)`

A pod counts only when it is Running, has a pod IP, and is not terminating.
A terminating pod loses its grants immediately, before its IP can be reused.

- [ ] **Step 1: Write the failing test** — `admin/internal/watch/pods_test.go`

```go
package watch

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func pod(name, ws, ip string, phase corev1.PodPhase) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: Namespace, Labels: map[string]string{
			"com.coder.workspace.id": ws, "com.coder.workspace.name": name, "com.coder.user.id": "u-" + ws,
		}},
		Status: corev1.PodStatus{Phase: phase, PodIP: ip},
	}
}

func TestPods(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unlabeled := pod("coder-db", "", "10.42.0.99", corev1.PodRunning)
	delete(unlabeled.Labels, "com.coder.workspace.id")
	cs := fake.NewClientset(
		pod("a", "ws-a", "10.42.0.9", corev1.PodRunning),
		pod("b", "ws-b", "", corev1.PodPending),
		unlabeled,
	)
	changed := make(chan struct{}, 10)
	p, err := Start(ctx, cs, func() { changed <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	run := p.Running()
	if len(run) != 1 || run[0].ID != "ws-a" || run[0].OwnerID != "u-ws-a" || run[0].Name != "a" {
		t.Fatalf("Running = %+v", run)
	}
	if w, ok := p.ByIP("10.42.0.9"); !ok || w.ID != "ws-a" {
		t.Fatalf("ByIP = %+v %v", w, ok)
	}
	if _, ok := p.ByIP("10.42.0.99"); ok {
		t.Fatal("unlabeled pod must not resolve")
	}
	if _, ok := p.ByID("ws-b"); ok {
		t.Fatal("pending pod without IP must not resolve")
	}

	if err := cs.CoreV1().Pods(Namespace).Delete(ctx, "a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	deadline := time.After(5 * time.Second)
	for len(p.Running()) != 0 {
		select {
		case <-changed:
		case <-deadline:
			t.Fatal("deleted pod still listed")
		}
	}
}
```

- [ ] **Step 2: Run to verify it fails**

Run: `make admin-go ARGS='get k8s.io/api@v0.37.0' && make admin-test`
Expected: FAIL, `undefined: Start`.

- [ ] **Step 3: Implement** — `admin/internal/watch/pods.go`

```go
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
```
ponytail: linear scans over workspace pods. Add an index when there are thousands of workspaces.

- [ ] **Step 4: Run tests to verify they pass**

Run: `make admin-go ARGS='mod tidy' && make admin-test`
Expected: `ok` for `internal/watch` and all earlier packages.

- [ ] **Step 5: Commit**

```bash
git add admin/internal/watch admin/go.mod admin/go.sum
git commit -m "feat(admin): watch running workspace pods"
```
