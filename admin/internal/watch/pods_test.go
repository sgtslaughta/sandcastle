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
