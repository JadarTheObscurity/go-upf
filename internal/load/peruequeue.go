// peruequeue.go: per-UE classes under the shared egress ceiling, so packet
// loss can be attributed to the UE that suffered it.
//
// WHY THIS EXISTS
// With one shared bfifo per direction, the qdisc reports an aggregate drop
// count and nothing can say WHICH UE lost packets. gtp5g's own per-PDR drop
// counters do not help: they count datapath discards (no matching PDR, a QER
// rate limit), and the congestion here is produced by a tc shaper that the
// kernel module never sees. Measured on a loaded UPF -- 38,786 aggregate
// drops while every per-PDR ul_drops stayed 0x0, because the per-PDR
// "forwarded" count is taken BEFORE the shaper:
//
//	per-UE forwarded summed  66,750
//	qdisc forwarded+dropped  66,706   <- the per-PDR counts match the
//	qdisc forwarded alone    27,920      shaper's INPUT, not its output
//
// So loss has to be measured where it happens: in the shaper. Giving each UE
// its own class and leaf makes each UE's drops its own counter.
//
// THE SHAPE
//
//	        ┌─ 1:11 ─ bfifo 11:   UE 1   (own drops, own backlog)
//	1:1 ────┼─ 1:12 ─ bfifo 12:   UE 2
//	 │      ├─ ...
//	 │      └─ 1:99 ─ bfifo 99:   default, for unclassified traffic
//	 └─ the shared ceiling: the bottleneck, and what the load metric reads
//
// Each UE class gets rate = ceiling/maxUEs as a guarantee but may borrow up to
// the full ceiling, so a single active UE is not throttled to its share --
// only contention produces drops. That is HTB's lending, and it is also what
// makes per-UE forwarding roughly fair under equal load, where the single
// shared FIFO was drop-tail unfair (measured spreads of 5x uplink, 37x
// downlink between UEs offering identical load).
//
// WHAT THE LOAD METRIC READS NOW
// The metric needs one occupancy/capacity ratio per direction. With the queue
// split per UE there is no single leaf to read, so the sampler reads the
// SHARED PARENT's backlog against the sum of the leaves' limits. The parent
// class accumulates the backlog of everything beneath it, so the ratio still
// describes "how full is this direction's egress buffer".
package load

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/sirupsen/logrus"
)

// PerUEQueue describes the per-UE class tree for one direction.
type PerUEQueue struct {
	// Dev is the device carrying the tree: the ifb for uplink, the gtp5g link
	// for downlink.
	Dev string
	// Root is the qdisc handle, e.g. "1:" for uplink and "2:" for downlink.
	Root string
	// SharedRate is the ceiling every UE borrows up to -- the bottleneck.
	SharedRate string
	// PerUELimitBytes is each UE's own queue capacity, the per-UE denominator.
	PerUELimitBytes uint32
	// MaxUEs bounds how many classes are created.
	MaxUEs int
}

// classID returns the class handle for UE slot n (1-based). Slots start at 11
// so they never collide with the root's own minor numbers, and the default
// class sits at 99.
//
// IMPORTANT: tc handles are HEXADECIMAL. "1:11" is minor 0x11 == 17 decimal,
// not 11. Reading a leaf's parent minor as decimal therefore matched nothing
// and per-UE metrics came out empty with no error -- caught by
// TestLeafStatsKeying. SlotMinor is the single place that conversion happens.
func (q PerUEQueue) classID(n int) string {
	return fmt.Sprintf("%s%x", q.Root, 0x10+n)
}

func (q PerUEQueue) leafHandle(n int) string {
	return fmt.Sprintf("%x:", 0x10+n)
}

// SlotMinor is the qdisc-handle minor number for UE slot n, as the kernel
// reports it in a netlink dump.
func SlotMinor(n int) uint16 { return uint16(0x10 + n) }

// DefaultClassMinor is the minor of the class catching non-UE traffic.
const DefaultClassMinor uint16 = 0x99

func (q PerUEQueue) major() string {
	return strings.TrimSuffix(q.Root, ":")
}

// defaultClassID is where traffic that matches no UE filter goes. It must
// exist: without it, unclassified packets (PFCP, SBI, anything not from a UE)
// would land in a UE's class and corrupt that UE's loss figure.
func (q PerUEQueue) defaultClassID() string {
	return fmt.Sprintf("%s99", q.Root) // 0x99 as a handle; see SlotMinor
}

// Build creates the tree. Idempotent: any existing root is removed first.
func (q PerUEQueue) Build(log *logrus.Entry) error {
	if q.Dev == "" || q.SharedRate == "" || q.PerUELimitBytes == 0 {
		return fmt.Errorf("per-UE queue: dev, shared rate and per-UE limit are required")
	}
	maxUEs := q.MaxUEs
	if maxUEs <= 0 {
		maxUEs = 16
	}

	runIgnore("tc", "qdisc", "del", "dev", q.Dev, "root")

	if err := run(log, "tc", "qdisc", "add", "dev", q.Dev, "root",
		"handle", q.Root, "htb", "default", "99"); err != nil {
		return err
	}
	// The shared ceiling: this is the bottleneck, and the class the load
	// metric reads for aggregate occupancy.
	if err := run(log, "tc", "class", "add", "dev", q.Dev,
		"parent", q.Root, "classid", q.Root+"1", "htb",
		"rate", q.SharedRate, "ceil", q.SharedRate, "burst", "8k"); err != nil {
		return err
	}
	// Default class for non-UE traffic.
	if err := run(log, "tc", "class", "add", "dev", q.Dev,
		"parent", q.Root+"1", "classid", q.defaultClassID(), "htb",
		"rate", "8kbit", "ceil", q.SharedRate, "burst", "4k"); err != nil {
		return err
	}
	if err := run(log, "tc", "qdisc", "add", "dev", q.Dev,
		"parent", q.defaultClassID(), "handle", "99:", "bfifo",
		"limit", fmt.Sprintf("%d", q.PerUELimitBytes)); err != nil {
		return err
	}

	// Per-UE classes. A guarantee of ceiling/maxUEs with borrowing up to the
	// full ceiling: one active UE is unthrottled, contention produces drops.
	guarantee := perUEGuarantee(q.SharedRate, maxUEs)
	for n := 1; n <= maxUEs; n++ {
		if err := run(log, "tc", "class", "add", "dev", q.Dev,
			"parent", q.Root+"1", "classid", q.classID(n), "htb",
			"rate", guarantee, "ceil", q.SharedRate,
			"burst", "8k", "quantum", "1500"); err != nil {
			return err
		}
		if err := run(log, "tc", "qdisc", "add", "dev", q.Dev,
			"parent", q.classID(n), "handle", q.leafHandle(n), "bfifo",
			"limit", fmt.Sprintf("%d", q.PerUELimitBytes)); err != nil {
			return err
		}
	}
	log.Infof("per-UE queues ready on %s: %d classes under a %s ceiling, "+
		"bfifo limit %d B each", q.Dev, maxUEs, q.SharedRate, q.PerUELimitBytes)
	return nil
}

// perUEGuarantee splits the ceiling across maxUEs, keeping tc's unit suffix.
// A guarantee below 8kbit is clamped: HTB warns about very small quanta and
// the resulting class barely schedules.
//
// The digits are taken by hand rather than with Sscanf("%d%s"): %d is greedy
// only up to the first non-digit, but %s then takes the REST of the token, so
// "10mbit" parsed as v=1, unit="0mbit" and a 10 mbit ceiling came out as
// 8 mbit. Caught by TestPerUEGuarantee.
func perUEGuarantee(shared string, maxUEs int) string {
	if maxUEs <= 0 {
		maxUEs = 16
	}
	i := 0
	for i < len(shared) && shared[i] >= '0' && shared[i] <= '9' {
		i++
	}
	if i == 0 {
		return "8kbit" // no leading number: unparseable
	}
	v, err := strconv.Atoi(shared[:i])
	if err != nil || v <= 0 {
		return "8kbit"
	}
	unit := shared[i:]
	per := v / maxUEs
	// Clamp only in kbit: the floor exists because HTB schedules a very small
	// class poorly, and 8 is a sane kbit floor. Applying it to mbit/gbit
	// would RAISE the guarantee instead (10mbit/4 = 2 -> clamped to 8mbit,
	// four times the ceiling). Caught by TestPerUEGuarantee.
	if per < 8 && (unit == "kbit" || unit == "kbps" || unit == "") {
		per = 8
	}
	if per < 1 {
		per = 1
	}
	return fmt.Sprintf("%d%s", per, unit)
}

// AttachUE points this UE's source address at its own class, so its packets
// queue and drop in a counter of its own.
//
// Uplink is matched on the SOURCE address and downlink on the DESTINATION,
// because the same UE address appears in opposite header fields in the two
// directions. Matching the wrong field silently classifies nothing and the
// UE's traffic falls into the default class.
func (q PerUEQueue) AttachUE(slot int, ueAddr string, downlink bool,
	log *logrus.Entry,
) error {
	field := "src"
	if downlink {
		field = "dst"
	}
	return run(log, "tc", "filter", "add", "dev", q.Dev,
		"protocol", "ip", "parent", q.Root, "prio", fmt.Sprintf("%d", slot),
		"u32", "match", "ip", field, ueAddr+"/32",
		"flowid", q.classID(slot))
}

// DetachUE removes a UE's filter by its priority, so a released session's
// slot can be reused.
func (q PerUEQueue) DetachUE(slot int) {
	runIgnore("tc", "filter", "del", "dev", q.Dev, "parent", q.Root,
		"prio", fmt.Sprintf("%d", slot))
}

// Teardown removes the whole tree.
func (q PerUEQueue) Teardown() {
	runIgnore("tc", "qdisc", "del", "dev", q.Dev, "root")
}
