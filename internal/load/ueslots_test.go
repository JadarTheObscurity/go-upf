package load

import (
	"testing"
	"time"
)

func TestSlotsAreStableAndReusable(t *testing.T) {
	s := NewUESlots(3)

	a1, isNew, err := s.Assign("10.60.0.1")
	if err != nil || !isNew {
		t.Fatalf("first assign: slot=%d new=%v err=%v", a1, isNew, err)
	}
	// A repeat must return the SAME slot and report not-new, or the caller
	// would reinstall the tc filter on every reconcile.
	again, isNew2, _ := s.Assign("10.60.0.1")
	if again != a1 || isNew2 {
		t.Errorf("repeat assign gave slot=%d new=%v, want %d/false", again, isNew2, a1)
	}

	b, _, _ := s.Assign("10.60.0.2")
	if b == a1 {
		t.Error("two UEs share a slot; their counters would be merged")
	}

	// Filling the pool must fail clearly rather than overwriting a UE.
	s.Assign("10.60.0.3")
	if _, _, err := s.Assign("10.60.0.4"); err == nil {
		t.Error("assigning past maxUEs returned no error")
	}

	// A released slot becomes available again.
	freed, ok := s.Release("10.60.0.2")
	if !ok || freed != b {
		t.Fatalf("release gave %d/%v, want %d/true", freed, ok, b)
	}
	reused, isNew3, err := s.Assign("10.60.0.4")
	if err != nil || !isNew3 {
		t.Fatalf("assign after release: %v", err)
	}
	if reused != b {
		t.Errorf("reused slot %d, expected the freed %d", reused, b)
	}
}

// tc class counters are cumulative and never reset, so a reused slot must be
// re-baselined or the new UE inherits its predecessor's drops.
func TestReleaseClearsTheBaseline(t *testing.T) {
	s := NewUESlots(2)
	slot, _, _ := s.Assign("10.60.0.1")
	s.SetBaseline(slot, QdiscStats{SentPkts: 5000, Drops: 900})
	if b, ok := s.Baseline(slot); !ok || b.SentPkts != 5000 {
		t.Fatalf("baseline not stored: %+v ok=%v", b, ok)
	}

	s.Release("10.60.0.1")
	if _, ok := s.Baseline(slot); ok {
		t.Error("baseline survived release; a new UE would inherit the old " +
			"UE's cumulative counters")
	}

	reused, _, _ := s.Assign("10.60.0.9")
	if reused != slot {
		t.Fatalf("expected slot %d to be reused", slot)
	}
	if _, ok := s.Baseline(reused); ok {
		t.Error("reused slot already has a baseline")
	}
}

func TestSnapshotAndLen(t *testing.T) {
	s := NewUESlots(4)
	s.Assign("10.60.0.1")
	s.Assign("10.60.0.2")
	if s.Len() != 2 {
		t.Errorf("Len = %d, want 2", s.Len())
	}
	snap := s.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("snapshot has %d entries, want 2", len(snap))
	}
	// Snapshot must be a copy: mutating it must not corrupt the registry.
	for k := range snap {
		delete(snap, k)
	}
	if s.Len() != 2 {
		t.Error("Snapshot returned a live map, not a copy")
	}
}

// LossPct must be computed from counters taken at the SAME point, which is
// the whole reason the per-UE class exists.
func TestLossPct(t *testing.T) {
	cases := []struct {
		fwd, drop uint64
		want      float64
	}{
		{0, 0, 0},        // idle: not a division by zero
		{100, 0, 0},      // no loss
		{0, 100, 100},    // total loss
		{629, 830, 56.9}, // the measured 400 kbit/s UE
		{625, 105, 14.4}, // the measured 200 kbit/s UE
	}
	for _, c := range cases {
		got := UELoss{Forwarded: c.fwd, Dropped: c.drop}.LossPct()
		if diff := got - c.want; diff > 0.1 || diff < -0.1 {
			t.Errorf("LossPct(fwd=%d drop=%d) = %.1f, want %.1f",
				c.fwd, c.drop, got, c.want)
		}
	}
}

// The per-UE guarantee splits the ceiling but must never collapse to zero,
// which would make a class barely schedule.
func TestPerUEGuarantee(t *testing.T) {
	cases := []struct {
		shared string
		maxUEs int
		want   string
	}{
		{"500kbit", 4, "125kbit"},
		{"500kbit", 16, "31kbit"},
		{"500kbit", 200, "8kbit"}, // clamped, not 2kbit
		{"10mbit", 4, "2mbit"},
		{"garbage", 4, "8kbit"}, // unparseable falls back, does not panic
	}
	for _, c := range cases {
		if got := perUEGuarantee(c.shared, c.maxUEs); got != c.want {
			t.Errorf("perUEGuarantee(%q,%d) = %q, want %q",
				c.shared, c.maxUEs, got, c.want)
		}
	}
}

// Each UE's queue must be big enough to hold packets even when the total is
// split many ways.
func TestPerUELimitHasAFloor(t *testing.T) {
	if got := perUELimit(65536, 4); got != 16384 {
		t.Errorf("perUELimit(65536,4) = %d, want 16384", got)
	}
	if got := perUELimit(65536, 64); got != 8192 {
		t.Errorf("perUELimit(65536,64) = %d, want the 8192 floor", got)
	}
}

// Class and leaf handles must be distinct per slot and must not collide with
// the default class at minor 99.
func TestClassHandlesAreDistinct(t *testing.T) {
	q := PerUEQueue{Root: "1:", MaxUEs: 16}
	seen := map[string]bool{}
	for n := 1; n <= 16; n++ {
		cid := q.classID(n)
		if seen[cid] {
			t.Fatalf("duplicate class id %s", cid)
		}
		seen[cid] = true
		if cid == q.defaultClassID() {
			t.Fatalf("slot %d collides with the default class %s", n, cid)
		}
	}
	if q.classID(1) != "1:11" || q.leafHandle(1) != "11:" {
		t.Errorf("slot 1 gave %s / %s, want 1:11 / 11:",
			q.classID(1), q.leafHandle(1))
	}
}

func TestClassMinor(t *testing.T) {
	// 0x00010011 is 1:11
	if got := ClassMinor(0x00010011); got != 0x11 {
		t.Errorf("ClassMinor = %#x, want 0x11", got)
	}
}

var _ = time.Second
