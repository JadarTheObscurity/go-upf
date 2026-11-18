// metric.go: the load metric itself.
//
// DEFINITION (as specified for this work)
//
//	instantaneous = floor( backlog_bytes / max_buffer_bytes * 100 )
//	metric        = time average of the instantaneous samples
//
// The average is an exponentially weighted moving average rather than a mean
// over a fixed window: it needs no ring buffer, it is O(1) per sample, and it
// cannot be skewed by one burst the way a short arithmetic mean can. The
// floor() is applied to each instantaneous sample, per the definition, and
// again to the reported average so the published value is an integer 0..100.
//
// Why floor() on the sample and not only at the end: the metric is specified as
// a floored ratio, so a buffer that never exceeds 0.99% reports 0, not 1. That
// also keeps an idle UPF reporting exactly 0.
package load

import (
	"math"
	"sync"
	"time"
)

// Metric is the 0..100 load value plus the inputs it was derived from, so a
// caller (or the debug API) can see WHY the number is what it is.
type Metric struct {
	// Value is the time-averaged, floored load metric: an integer 0..100.
	Value uint8 `json:"loadMetric"`
	// Instant is the most recent instantaneous sample, also floored.
	Instant uint8 `json:"instantLoadMetric"`
	// Raw is the un-floored average, for debugging the averaging itself.
	Raw float64 `json:"rawAverage"`
	// The last sample's inputs.
	BacklogBytes uint32 `json:"egressBufferBytes"`
	MaxBytes     uint32 `json:"maxBufferBytes"`
	BacklogPkts  uint32 `json:"egressBufferPackets"`
	Drops        uint32 `json:"drops"`
	// Operational state, so a caller can tell "0% because idle" from
	// "0% because the measurement is not working".
	Samples   uint64    `json:"samples"`
	Healthy   bool      `json:"healthy"`
	LastError string    `json:"lastError,omitempty"`
	UpdatedAt time.Time `json:"updatedAt"`
	Source    string    `json:"source"`
}

// Tracker keeps the running average. Safe for concurrent use: the sampler
// writes, the API reads.
type Tracker struct {
	mu sync.RWMutex

	// alpha is the EWMA weight for each new sample, derived from the sample
	// interval and the averaging window so that the smoothing is expressed in
	// SECONDS rather than in samples -- changing the sample rate then does not
	// silently change how much history the metric reflects.
	alpha float64

	raw       float64
	instant   uint8
	samples   uint64
	backlog   uint32
	maxBytes  uint32
	pkts      uint32
	drops     uint32
	last      QdiscStats // the reading as the sampler saw it, for the exporter
	healthy   bool
	lastErr   string
	updatedAt time.Time
	source    string
}

// NewTracker builds a Tracker whose average has the given time constant.
// window is how long it takes a step change to be ~63% reflected.
func NewTracker(sampleInterval, window time.Duration, source string) *Tracker {
	alpha := 1.0
	if window > 0 && sampleInterval > 0 && window > sampleInterval {
		// Standard EWMA time constant: alpha = 1 - exp(-dt/tau).
		alpha = 1 - math.Exp(-sampleInterval.Seconds()/window.Seconds())
	}
	return &Tracker{alpha: alpha, source: source}
}

// ObserveQdisc folds a whole qdisc reading in, keeping the cumulative
// forwarded counters the exporter needs alongside the derived metric.
func (t *Tracker) ObserveQdisc(q QdiscStats) {
	t.Observe(q.BacklogB, q.LimitB, q.BacklogPkt, q.Drops)
	t.mu.Lock()
	t.last = q
	t.mu.Unlock()
}

// Last returns the most recent qdisc reading.
func (t *Tracker) Last() QdiscStats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.last
}

// Observe folds one reading of the egress buffer into the average.
func (t *Tracker) Observe(backlogBytes, maxBytes, pkts, drops uint32) {
	// floor(backlog/max*100), computed in integer arithmetic so the floor is
	// exact rather than subject to float rounding at the boundary.
	var inst uint8
	if maxBytes > 0 {
		v := uint64(backlogBytes) * 100 / uint64(maxBytes)
		if v > 100 {
			v = 100 // a qdisc can briefly exceed its own limit
		}
		inst = uint8(v)
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	if t.samples == 0 {
		t.raw = float64(inst) // seed, so the metric does not ramp from 0
	} else {
		t.raw += t.alpha * (float64(inst) - t.raw)
	}
	t.instant = inst
	t.samples++
	t.backlog, t.maxBytes, t.pkts, t.drops = backlogBytes, maxBytes, pkts, drops
	t.healthy, t.lastErr = true, ""
	t.updatedAt = time.Now()
}

// ObserveError records that a sample could not be taken. The last value is
// kept but marked unhealthy, so a reader is never silently served a stale 0.
func (t *Tracker) ObserveError(err error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.healthy = false
	if err != nil {
		t.lastErr = err.Error()
	}
	t.updatedAt = time.Now()
}

// Metric returns the current value.
func (t *Tracker) Metric() Metric {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Metric{
		Value:        uint8(math.Floor(t.raw)),
		Instant:      t.instant,
		Raw:          t.raw,
		BacklogBytes: t.backlog,
		MaxBytes:     t.maxBytes,
		BacklogPkts:  t.pkts,
		Drops:        t.drops,
		Samples:      t.samples,
		Healthy:      t.healthy,
		LastError:    t.lastErr,
		UpdatedAt:    t.updatedAt,
		Source:       t.source,
	}
}
