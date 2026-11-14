package load

import (
	"errors"
	"math"
	"testing"
	"time"
)

// The metric is floor(backlog/max*100). These cases pin the boundaries, where
// a float-rounding implementation would disagree with a floored one.
func TestInstantaneousIsFloored(t *testing.T) {
	cases := []struct {
		name          string
		backlog, maxB uint32
		want          uint8
	}{
		{"empty buffer is 0", 0, 65536, 0},
		{"full buffer is 100", 65536, 65536, 100},
		{"half is 50", 32768, 65536, 50},
		// 65160/65536 = 99.426% -> 99, not 100. This is the real saturated
		// reading observed from a bfifo limit 65536 under overload.
		{"saturated bfifo floors to 99", 65160, 65536, 99},
		// 0.99% must floor to 0, not round to 1.
		{"sub-one-percent floors to 0", 649, 65536, 0},
		{"exactly one percent is 1", 656, 65536, 1},
		// A qdisc can momentarily exceed its own limit; clamp, never wrap.
		{"over limit clamps to 100", 70000, 65536, 100},
		{"no limit yields 0", 1234, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			tr := NewTracker(time.Second, 0, "test")
			tr.Observe(c.backlog, c.maxB, 0, 0)
			if got := tr.Metric().Instant; got != c.want {
				t.Fatalf("instant = %d, want %d", got, c.want)
			}
		})
	}
}

// Value must stay inside 0..100 for any input, since it will be encoded into a
// single-octet PFCP IE.
func TestValueAlwaysInRange(t *testing.T) {
	tr := NewTracker(100*time.Millisecond, time.Second, "test")
	for _, b := range []uint32{0, 1, 999, 65535, 65536, math.MaxUint32} {
		tr.Observe(b, 65536, 0, 0)
		if v := tr.Metric().Value; v > 100 {
			t.Fatalf("backlog %d gave %d, out of range", b, v)
		}
	}
}

// The first sample must not be diluted toward zero, or a UPF that starts busy
// would under-report for the length of the averaging window.
func TestFirstSampleSeedsTheAverage(t *testing.T) {
	tr := NewTracker(200*time.Millisecond, 2*time.Second, "test")
	tr.Observe(65536, 65536, 0, 0)
	if got := tr.Metric().Value; got != 100 {
		t.Fatalf("first sample seeded to %d, want 100", got)
	}
}

// A step change should be approached smoothly, and ~63% of the way there after
// one time constant -- that is what makes it a time average rather than a
// latest-value passthrough.
func TestAverageSmoothsAndConverges(t *testing.T) {
	const dt = 100 * time.Millisecond
	const window = time.Second
	tr := NewTracker(dt, window, "test")
	tr.Observe(0, 65536, 0, 0) // start idle

	// Drive a full buffer for exactly one time constant.
	for i := 0; i < int(window/dt); i++ {
		tr.Observe(65536, 65536, 0, 0)
	}
	got := tr.Metric().Raw
	if got < 55 || got > 70 {
		t.Fatalf("after one time constant raw = %.1f, want ~63", got)
	}
	// It must not have jumped straight to 100: that would mean no averaging.
	if tr.Metric().Value == 100 {
		t.Fatal("average reached 100 in one window; smoothing is not applied")
	}

	// Keep going: it should converge.
	for i := 0; i < 100; i++ {
		tr.Observe(65536, 65536, 0, 0)
	}
	if v := tr.Metric().Value; v < 99 {
		t.Fatalf("did not converge: %d", v)
	}
}

// A sampling failure must not be reported as a healthy 0%: a caller has to be
// able to distinguish "idle" from "broken".
func TestErrorMarksUnhealthyAndKeepsLastValue(t *testing.T) {
	tr := NewTracker(time.Second, time.Second, "test")
	tr.Observe(32768, 65536, 4, 0)
	before := tr.Metric()
	if !before.Healthy {
		t.Fatal("should be healthy after a good sample")
	}

	tr.ObserveError(errors.New("qdisc vanished"))
	after := tr.Metric()
	if after.Healthy {
		t.Fatal("should be unhealthy after a failed sample")
	}
	if after.Value != before.Value {
		t.Fatalf("value changed on error: %d -> %d", before.Value, after.Value)
	}
	if after.LastError == "" {
		t.Fatal("error text not recorded")
	}
}

// An untouched tracker must report 0 and unhealthy, not a spurious 0% healthy.
func TestZeroValueTrackerIsUnhealthy(t *testing.T) {
	tr := NewTracker(time.Second, time.Second, "test")
	m := tr.Metric()
	if m.Value != 0 || m.Healthy || m.Samples != 0 {
		t.Fatalf("fresh tracker: %+v", m)
	}
}
