// ueslots.go: the UE-address <-> class-slot mapping.
//
// A per-UE class is identified in tc by its slot number, but a metric has to
// be labelled with the UE's address. This keeps that mapping, and it is the
// only place that knows a UE is "slot 3".
//
// Slots are assigned on first sight and RETAINED while the UE's filter is
// installed. Reuse matters: tc class counters are cumulative and never reset,
// so handing a slot to a different UE would make the new UE inherit the old
// one's drops. A released slot is therefore only reused after its filter is
// removed and its counters are re-baselined by the caller.
package load

import (
	"fmt"
	"sync"
)

// UESlots assigns per-UE class slots and remembers which UE holds each one.
type UESlots struct {
	mu     sync.RWMutex
	maxUEs int
	byAddr map[string]int
	bySlot map[int]string

	// baseline holds each slot's counters at the moment the slot was
	// assigned, so a reused slot reports only the current UE's traffic
	// instead of its predecessor's cumulative totals.
	baseline map[int]QdiscStats
}

func NewUESlots(maxUEs int) *UESlots {
	if maxUEs <= 0 {
		maxUEs = 16
	}
	return &UESlots{
		maxUEs:   maxUEs,
		byAddr:   make(map[string]int),
		bySlot:   make(map[int]string),
		baseline: make(map[int]QdiscStats),
	}
}

// Assign returns the slot for a UE address, allocating one if needed. The
// bool reports whether this call created the assignment, which is the signal
// to install a tc filter.
func (u *UESlots) Assign(addr string) (int, bool, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if s, ok := u.byAddr[addr]; ok {
		return s, false, nil
	}
	for s := 1; s <= u.maxUEs; s++ {
		if _, taken := u.bySlot[s]; !taken {
			u.byAddr[addr] = s
			u.bySlot[s] = addr
			return s, true, nil
		}
	}
	return 0, false, fmt.Errorf("no free per-UE class slot (max %d); "+
		"raise the per-UE queue's maxUEs to measure more UEs separately",
		u.maxUEs)
}

// Release frees a slot so another UE can use it.
func (u *UESlots) Release(addr string) (int, bool) {
	u.mu.Lock()
	defer u.mu.Unlock()
	s, ok := u.byAddr[addr]
	if !ok {
		return 0, false
	}
	delete(u.byAddr, addr)
	delete(u.bySlot, s)
	delete(u.baseline, s)
	return s, true
}

// SetBaseline records a slot's counters as the zero point for its current UE.
func (u *UESlots) SetBaseline(slot int, st QdiscStats) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.baseline[slot] = st
}

// Baseline returns the recorded zero point for a slot.
func (u *UESlots) Baseline(slot int) (QdiscStats, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	b, ok := u.baseline[slot]
	return b, ok
}

// Addr returns the UE holding a slot.
func (u *UESlots) Addr(slot int) (string, bool) {
	u.mu.RLock()
	defer u.mu.RUnlock()
	a, ok := u.bySlot[slot]
	return a, ok
}

// Snapshot returns the current slot->address map.
func (u *UESlots) Snapshot() map[int]string {
	u.mu.RLock()
	defer u.mu.RUnlock()
	out := make(map[int]string, len(u.bySlot))
	for s, a := range u.bySlot {
		out[s] = a
	}
	return out
}

// Len reports how many UEs currently hold a slot.
func (u *UESlots) Len() int {
	u.mu.RLock()
	defer u.mu.RUnlock()
	return len(u.byAddr)
}
