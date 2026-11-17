package load

import (
	"errors"
	"testing"
	"time"
)

func busy(t *Tracker, pct int) {
	// Seed straight to the target so the EWMA does not need warming.
	t.Observe(uint32(pct*655), 65500, 0, 0)
}

// LCI must be the max of the two directions, and must say which one drove it.
func TestLCIIsMaxOfBothDirections(t *testing.T) {
	cases := []struct {
		name         string
		ul, dl       int
		wantValue    uint8
		wantDominant Direction
	}{
		{"uplink majority", 90, 10, 90, DirUplink},
		{"downlink majority", 10, 90, 90, DirDownlink},
		{"both idle", 0, 0, 0, DirUplink},
		{"both saturated", 99, 99, 99, DirUplink},
		{"downlink slightly higher", 50, 51, 51, DirDownlink},
		{"uplink slightly higher", 51, 50, 51, DirUplink},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ul := NewTracker(time.Second, 0, "ul")
			dl := NewTracker(time.Second, 0, "dl")
			busy(ul, c.ul)
			busy(dl, c.dl)
			got := NewCombiner(ul, dl).LCI()
			if got.Value != c.wantValue {
				t.Errorf("value = %d, want %d", got.Value, c.wantValue)
			}
			if got.Dominant != c.wantDominant {
				t.Errorf("dominant = %q, want %q", got.Dominant, c.wantDominant)
			}
			if got.Downlink == nil {
				t.Error("downlink detail missing")
			}
		})
	}
}

// A saturated direction must not be diluted by an idle one. This is the whole
// reason the combiner takes a max instead of a mean.
func TestSaturatedDirectionIsNotAveragedAway(t *testing.T) {
	ul := NewTracker(time.Second, 0, "ul")
	dl := NewTracker(time.Second, 0, "dl")
	busy(ul, 100)
	busy(dl, 0)
	got := NewCombiner(ul, dl).LCI()
	if got.Value != 100 {
		t.Fatalf("a saturated uplink reported %d; a mean would have given ~50",
			got.Value)
	}
}

// With downlink disabled the metric is uplink-only and still valid.
func TestUplinkOnlyWhenDownlinkDisabled(t *testing.T) {
	ul := NewTracker(time.Second, 0, "ul")
	busy(ul, 42)
	got := NewCombiner(ul, nil).LCI()
	if got.Value != 42 || got.Dominant != DirUplink {
		t.Errorf("got %d/%q, want 42/UL", got.Value, got.Dominant)
	}
	if got.Downlink != nil {
		t.Error("downlink detail present though downlink is disabled")
	}
	if !got.Healthy {
		t.Error("uplink-only metric should be healthy")
	}
}

// If either enabled direction stops measuring, the combined value is not
// trustworthy: the unknown direction could be the congested one.
func TestUnhealthyWhenEitherDirectionFails(t *testing.T) {
	for _, broken := range []Direction{DirUplink, DirDownlink} {
		t.Run(string(broken), func(t *testing.T) {
			ul := NewTracker(time.Second, 0, "ul")
			dl := NewTracker(time.Second, 0, "dl")
			busy(ul, 20)
			busy(dl, 20)
			if broken == DirUplink {
				ul.ObserveError(errors.New("ul qdisc vanished"))
			} else {
				dl.ObserveError(errors.New("dl qdisc vanished"))
			}
			if NewCombiner(ul, dl).LCI().Healthy {
				t.Fatalf("LCI reported healthy with %s broken", broken)
			}
		})
	}
}

// Never report a fabricated value when nothing is measured.
func TestNoTrackersIsUnhealthyZero(t *testing.T) {
	got := NewCombiner(nil, nil).LCI()
	if got.Value != 0 || got.Healthy {
		t.Fatalf("got %+v, want 0 and unhealthy", got)
	}
}

// The combined value must stay inside the single octet the IE carries.
func TestLCIStaysInRange(t *testing.T) {
	ul := NewTracker(time.Second, 0, "ul")
	dl := NewTracker(time.Second, 0, "dl")
	ul.Observe(1<<31, 65536, 0, 0) // absurd backlog
	dl.Observe(1<<31, 65536, 0, 0)
	if v := NewCombiner(ul, dl).LCI().Value; v > 100 {
		t.Fatalf("value = %d, outside 0..100", v)
	}
}
