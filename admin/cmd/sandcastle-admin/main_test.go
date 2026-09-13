package main

import (
	"fmt"
	"testing"
	"time"
)

func TestDenialThrottle(t *testing.T) {
	now := time.Unix(1000, 0)
	th := &throttle{now: func() time.Time { return now }}
	if !th.allow("a|x.com|443") || th.allow("a|x.com|443") {
		t.Fatal("second hit within 1s allowed")
	}
	if !th.allow("b|x.com|443") {
		t.Fatal("other key throttled")
	}
	now = now.Add(time.Second)
	if !th.allow("a|x.com|443") {
		t.Fatal("hit after 1s throttled")
	}
	for i := 0; i < 9998; i++ {
		th.allow(fmt.Sprint(i))
	}
	if len(th.last) != 10000 {
		t.Fatalf("pruned too early: %d", len(th.last))
	}
	now = now.Add(2 * time.Minute)
	th.allow("fresh")
	if len(th.last) != 1 {
		t.Fatalf("stale keys not pruned: %d left", len(th.last))
	}
	for i := 0; i < 10001; i++ { // all fresh: bounded by a reset
		th.allow(fmt.Sprint("f", i))
	}
	if len(th.last) > 10000 {
		t.Fatalf("map grew past cap: %d", len(th.last))
	}
}
