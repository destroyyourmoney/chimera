package healthreport

import (
	"errors"
	"testing"
	"time"
)

func TestRun_PreservesInputOrderRegardlessOfCompletionOrder(t *testing.T) {
	hosts := []string{"slow", "fast", "mid"}
	delays := map[string]time.Duration{
		"slow": 30 * time.Millisecond,
		"fast": 0,
		"mid":  10 * time.Millisecond,
	}
	results := Run(hosts, func(h string) error {
		time.Sleep(delays[h])
		return nil
	})
	if len(results) != 3 {
		t.Fatalf("got %d results, want 3", len(results))
	}
	for i, h := range hosts {
		if results[i].Server != h {
			t.Errorf("results[%d].Server = %q, want %q (order not preserved)", i, results[i].Server, h)
		}
		if !results[i].OK {
			t.Errorf("results[%d] (%s) OK = false, want true", i, h)
		}
	}
}

func TestRun_CapturesError(t *testing.T) {
	results := Run([]string{"bad"}, func(h string) error {
		return errors.New("dial refused")
	})
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1", len(results))
	}
	r := results[0]
	if r.OK {
		t.Error("OK = true, want false for a failing ping")
	}
	if r.Error != "dial refused" {
		t.Errorf("Error = %q, want %q", r.Error, "dial refused")
	}
	if r.RTTMs != 0 {
		t.Errorf("RTTMs = %d, want 0 on failure", r.RTTMs)
	}
}

func TestRun_MeasuresElapsedTimeOnSuccess(t *testing.T) {
	results := Run([]string{"h"}, func(h string) error {
		time.Sleep(15 * time.Millisecond)
		return nil
	})
	if !results[0].OK {
		t.Fatal("expected OK result")
	}
	if results[0].RTTMs < 10 {
		t.Errorf("RTTMs = %d, want >= ~15ms (elapsed time not measured)", results[0].RTTMs)
	}
}

func TestRun_EmptyHosts(t *testing.T) {
	results := Run(nil, func(h string) error { return nil })
	if len(results) != 0 {
		t.Fatalf("got %d results, want 0", len(results))
	}
}

func TestFastest_PicksLowestRTTAmongOK(t *testing.T) {
	results := []Result{
		{Server: "a", OK: true, RTTMs: 120},
		{Server: "b", OK: false, Error: "timeout"},
		{Server: "c", OK: true, RTTMs: 45},
		{Server: "d", OK: true, RTTMs: 200},
	}
	best, ok := Fastest(results)
	if !ok {
		t.Fatal("Fastest reported no OK result, want one")
	}
	if best.Server != "c" {
		t.Errorf("Fastest = %q, want %q (lowest RTT)", best.Server, "c")
	}
}

func TestFastest_NoneOK(t *testing.T) {
	results := []Result{
		{Server: "a", OK: false, Error: "e1"},
		{Server: "b", OK: false, Error: "e2"},
	}
	_, ok := Fastest(results)
	if ok {
		t.Error("Fastest reported a result, want false when nothing is OK")
	}
}

func TestFastest_Empty(t *testing.T) {
	_, ok := Fastest(nil)
	if ok {
		t.Error("Fastest on empty input should return false")
	}
}
