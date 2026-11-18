// uetracker.go: keep the per-UE classes in step with the live sessions, and
// expose each UE's loss.
//
// UEs are discovered from the gtp5g datapath rather than from PFCP: the UE
// address appears in each PDR, and reading it needs no hook into the session
// handling. The discovery function is injected so this package does not depend
// on internal/metrics (which owns the procfs reader) -- that would be a cycle.
package load

import (
	"context"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// UELoss is one UE's shaper counters for one direction, rebased on the slot's
// baseline so a reused slot never reports its predecessor's traffic.
type UELoss struct {
	Addr      string
	Slot      int
	Direction Direction
	Forwarded uint64
	Dropped   uint64
	// ForwardedBytes lets throughput be reported in bit/s. tc counts bytes
	// alongside packets, so this costs nothing extra to collect.
	ForwardedBytes uint64
	BacklogB       uint32
	LimitB         uint32
}

// LossPct is the share of this UE's offered packets that the shaper discarded.
// Both terms are measured at the same point, so this is a true loss rate --
// unlike comparing a pre-shaper forward count against a post-shaper drop
// count, which is what made per-UE drops read zero before.
func (l UELoss) LossPct() float64 {
	t := l.Forwarded + l.Dropped
	if t == 0 {
		return 0
	}
	return 100 * float64(l.Dropped) / float64(t)
}

// UEDiscoverer returns the UE addresses that currently have datapath rules.
type UEDiscoverer func() ([]string, error)

// UETracker attaches a tc filter per UE and reads each UE's own counters.
type UETracker struct {
	queue    PerUEQueue
	slots    *UESlots
	reader   *QdiscReader
	discover UEDiscoverer
	dir      Direction
	log      *logrus.Entry

	mu      sync.Mutex
	ifindex int
	lastErr error
}

func NewUETracker(q PerUEQueue, dir Direction, discover UEDiscoverer,
	log *logrus.Entry,
) (*UETracker, error) {
	r, err := NewQdiscReader()
	if err != nil {
		return nil, err
	}
	return &UETracker{
		queue: q, slots: NewUESlots(q.MaxUEs), reader: r,
		discover: discover, dir: dir, log: log,
	}, nil
}

// Run reconciles filters against the live UEs until ctx is cancelled.
func (t *UETracker) Run(ctx context.Context, wg *sync.WaitGroup, every time.Duration) {
	if every <= 0 {
		every = 5 * time.Second
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer t.reader.Close()
		tick := time.NewTicker(every)
		defer tick.Stop()
		t.reconcile()
		for {
			select {
			case <-ctx.Done():
				t.log.Infof("%s per-UE tracker stopped", t.dir)
				return
			case <-tick.C:
				t.reconcile()
			}
		}
	}()
}

// reconcile installs filters for new UEs and releases slots for gone ones.
func (t *UETracker) reconcile() {
	addrs, err := t.discover()
	if err != nil {
		t.mu.Lock()
		t.lastErr = err
		t.mu.Unlock()
		return
	}
	live := make(map[string]struct{}, len(addrs))
	for _, a := range addrs {
		live[a] = struct{}{}
	}

	for _, a := range addrs {
		slot, isNew, aerr := t.slots.Assign(a)
		if aerr != nil {
			// Out of slots is worth saying once per reconcile, not per UE.
			t.log.Warnf("%s per-UE classes: %v", t.dir, aerr)
			break
		}
		if !isNew {
			continue
		}
		if ferr := t.queue.AttachUE(slot, a, t.dir == DirDownlink, t.log); ferr != nil {
			t.log.Warnf("%s attach UE %s to slot %d: %v", t.dir, a, slot, ferr)
			t.slots.Release(a)
			continue
		}
		// Baseline the slot now: its class counters may carry traffic from a
		// previous occupant, and tc never resets them.
		if st, serr := t.leaf(slot); serr == nil {
			t.slots.SetBaseline(slot, st)
		}
		t.log.Infof("%s per-UE class: %s -> slot %d (%s)",
			t.dir, a, slot, t.queue.classID(slot))
	}

	for slot, addr := range t.slots.Snapshot() {
		if _, still := live[addr]; still {
			continue
		}
		t.queue.DetachUE(slot)
		t.slots.Release(addr)
		t.log.Infof("%s per-UE class: released slot %d (%s)", t.dir, slot, addr)
	}
}

func (t *UETracker) resolveIfindex() (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ifindex != 0 {
		return t.ifindex, nil
	}
	idx, err := ifindexByName(t.queue.Dev)
	if err != nil {
		return 0, err
	}
	t.ifindex = idx
	return idx, nil
}

func (t *UETracker) leaf(slot int) (QdiscStats, error) {
	idx, err := t.resolveIfindex()
	if err != nil {
		return QdiscStats{}, err
	}
	leaves, err := t.reader.LeafStats(idx, "bfifo")
	if err != nil {
		return QdiscStats{}, err
	}
	st, ok := leaves[SlotMinor(slot)]
	if !ok {
		return QdiscStats{}, errNoLeaf
	}
	return st, nil
}

// Losses returns every tracked UE's counters, rebased on its slot baseline.
func (t *UETracker) Losses() ([]UELoss, error) {
	idx, err := t.resolveIfindex()
	if err != nil {
		return nil, err
	}
	leaves, err := t.reader.LeafStats(idx, "bfifo")
	if err != nil {
		return nil, err
	}
	var out []UELoss
	for slot, addr := range t.slots.Snapshot() {
		st, ok := leaves[SlotMinor(slot)]
		if !ok {
			continue
		}
		fwd, drop, fwdB := st.SentPkts, uint64(st.Drops), st.SentBytes
		if b, has := t.slots.Baseline(slot); has {
			// Counters are cumulative; subtract the slot's zero point. Guard
			// against a tc counter that went backwards (a rebuilt tree).
			if fwd >= b.SentPkts {
				fwd -= b.SentPkts
			}
			if drop >= uint64(b.Drops) {
				drop -= uint64(b.Drops)
			}
			if fwdB >= b.SentBytes {
				fwdB -= b.SentBytes
			}
		}
		out = append(out, UELoss{
			Addr: addr, Slot: slot, Direction: t.dir,
			Forwarded: fwd, Dropped: drop, ForwardedBytes: fwdB,
			BacklogB: st.BacklogB, LimitB: st.LimitB,
		})
	}
	return out, nil
}

// TrackedUEs reports how many UEs have their own class right now.
func (t *UETracker) TrackedUEs() int { return t.slots.Len() }
