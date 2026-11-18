// lci.go: the node-level load metric reported in PFCP Load Control
// Information (TS 29.244 8.2.54).
//
// DEFINITION
//
//	UL metric = floor(uplink buffer bytes   / uplink max bytes   * 100), averaged
//	DL metric = floor(downlink buffer bytes / downlink max bytes * 100), averaged
//	LCI       = max(UL metric, DL metric)
//
// Both directions use the SAME equation on their own buffer; only the
// measurement point differs (see egress.go). The reported value is the maximum
// rather than a sum or mean, because the IE answers "how loaded is this UPF",
// and a node saturated in one direction IS loaded -- averaging would let a
// full uplink hide behind an idle downlink and understate the node by half.
// Taking the max is also what makes the metric safe to act on: an SMF steering
// sessions away from this UPF should do so when EITHER direction is congested.
package load

import (
	"fmt"
	"time"
)

// Direction identifies which user-plane direction a reading belongs to.
type Direction string

const (
	DirUplink   Direction = "UL"
	DirDownlink Direction = "DL"
)

// LCI is the combined node-level load plus both per-direction views, so a
// reader can see which direction is driving the number.
type LCI struct {
	// Value is what PFCP Load Control Information carries: an integer 0..100.
	Value uint8 `json:"loadMetric"`
	// Dominant names the direction that produced Value. With both directions
	// equal it reports UL, arbitrarily but deterministically.
	Dominant Direction `json:"dominantDirection"`
	// Healthy is false unless every ENABLED direction is measuring. A caller
	// must not send Load Control Information when this is false: advertising a
	// fabricated 0% to an SMF that places sessions on it is worse than
	// advertising nothing.
	Healthy bool `json:"healthy"`

	Uplink   Metric  `json:"uplink"`
	Downlink *Metric `json:"downlink,omitempty"` // nil when DL is disabled

	UpdatedAt time.Time `json:"updatedAt"`
}

// Combiner holds one Tracker per direction and reduces them to the reported
// value. The downlink tracker is nil when the downlink buffer is disabled, in
// which case the metric is uplink-only and still valid.
type Combiner struct {
	ul *Tracker
	dl *Tracker
}

func NewCombiner(ul, dl *Tracker) *Combiner {
	return &Combiner{ul: ul, dl: dl}
}

// UL and DL expose the individual trackers for the samplers to write into.
func (c *Combiner) UL() *Tracker { return c.ul }
func (c *Combiner) DL() *Tracker { return c.dl }

// LCI reduces both directions to the single value PFCP reports.
func (c *Combiner) LCI() LCI {
	out := LCI{Dominant: DirUplink}
	if c.ul == nil {
		// No uplink tracker at all: nothing is being measured.
		return out
	}

	um := c.ul.Metric()
	out.Uplink = um
	out.Value = um.Value
	out.Healthy = um.Healthy
	out.UpdatedAt = um.UpdatedAt

	if c.dl == nil {
		return out // uplink-only deployment
	}

	dm := c.dl.Metric()
	out.Downlink = &dm
	// max(): see the package comment on why not a mean.
	if dm.Value > out.Value {
		out.Value = dm.Value
		out.Dominant = DirDownlink
	}
	// Both directions must be measuring for the max to mean anything: if one
	// is broken its true value is unknown, and an unknown direction could be
	// the congested one.
	out.Healthy = um.Healthy && dm.Healthy
	if dm.UpdatedAt.After(out.UpdatedAt) {
		out.UpdatedAt = dm.UpdatedAt
	}
	return out
}

// ---------------------------------------------------------------------------
// Access for a metrics exporter
// ---------------------------------------------------------------------------

// DirectionStats returns the last qdisc reading for one direction, as the
// sampler saw it. The exporter uses this rather than taking its own netlink
// dump: the sampler is already reading these buffers several times a second,
// so a scrape should cost nothing extra and should report exactly the numbers
// the metric was computed from.
func (c *Combiner) DirectionStats(dir Direction) (QdiscStats, error) {
	t := c.ul
	if dir == DirDownlink {
		t = c.dl
	}
	if t == nil {
		return QdiscStats{}, fmt.Errorf("direction %s is not being measured", dir)
	}
	return t.Last(), nil
}
