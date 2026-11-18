// egress.go: create the egress buffer the load metric measures.
//
// WHY THE UPF DOES THIS ITSELF
// The metric is floor(buffer bytes / max buffer bytes * 100), so it needs a
// byte-bounded queue to read. A pod's veth is "noqueue": no buffer, no
// capacity, no ratio. Something must therefore install one.
//
// It cannot be done by the deployment's wrapper script before the UPF starts,
// because the queue has to sit on the pre-NAT user-plane path, and the only
// interface carrying that traffic -- upfgtp -- is created BY this process when
// the gtp5g link comes up. A wrapper running earlier fails with
// `Cannot find device "upfgtp"`.
//
// Doing it here also satisfies the requirement that the metric be available
// as soon as the pod is up: by the time the UPF logs "started", the buffer
// exists and the first sample has been taken.
//
// THE SHAPE
//
//	upfgtp ingress --mirred--> upfegress (ifb) --> htb 1:10 --> bfifo limit N
//
// upfgtp ingress is pre-NAT and carries decapsulated uplink user traffic.
// Redirecting it onto an ifb device yields a queue that is exactly the UPF's
// user-plane egress buffer. The HTB class is the bottleneck -- without a rate
// limit the queue drains as fast as it fills and the metric reads 0 forever.
// bfifo is required rather than preferred: its limit is in BYTES, so
// backlog/limit is a byte ratio; pfifo's limit is in packets.
//
// tc is invoked rather than hand-rolling TC netlink: this runs once at startup
// (not per sample), the commands are the documented interface to the kernel's
// queueing disciplines, and iproute2 is already in the UPF image because the
// chart's own wrapper uses ip and tc.
package load

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/sirupsen/logrus"
)

// EgressBufferSpec describes the buffers to build.
type EgressBufferSpec struct {
	// IfName is the ifb device to create for the UPLINK buffer, e.g.
	// "upfegress".
	IfName string
	// SourceIf is the gtp5g link ("upfgtp"). Its ingress is redirected into
	// the uplink buffer, and its egress carries the downlink buffer.
	SourceIf string
	// Rate is the uplink bottleneck, in tc syntax ("500kbit"). Required:
	// with no bottleneck the buffer never fills and the metric is always 0.
	Rate string
	// LimitBytes is the uplink buffer capacity -- the UL metric's denominator.
	LimitBytes uint32

	// DLRate is the downlink bottleneck. Empty disables the downlink buffer,
	// in which case the metric is uplink-only.
	DLRate string
	// DLLimitBytes is the downlink buffer capacity -- the DL denominator.
	DLLimitBytes uint32

	// PerUE gives every UE its own class and leaf, so packet loss can be
	// attributed to the UE that suffered it. With a single shared queue the
	// drop counter is an aggregate and nothing can say which UE lost
	// packets. MaxUEs bounds how many classes are created.
	PerUE  bool
	MaxUEs int
}

// ULQueue and DLQueue describe the per-UE trees for each direction.
func (s EgressBufferSpec) ULQueue() PerUEQueue {
	return PerUEQueue{
		Dev: s.IfName, Root: "1:", SharedRate: s.Rate,
		PerUELimitBytes: perUELimit(s.LimitBytes, s.MaxUEs), MaxUEs: s.MaxUEs,
	}
}

func (s EgressBufferSpec) DLQueue() PerUEQueue {
	return PerUEQueue{
		Dev: s.SourceIf, Root: dlRootHandle, SharedRate: s.DLRate,
		PerUELimitBytes: perUELimit(s.DLLimitBytes, s.MaxUEs), MaxUEs: s.MaxUEs,
	}
}

// perUELimit splits the configured buffer across the UE classes. The shared
// total is kept roughly constant so the aggregate load metric still describes
// the same amount of buffering as the single-queue shape did; a floor keeps a
// per-UE queue large enough to hold a few packets.
func perUELimit(total uint32, maxUEs int) uint32 {
	if maxUEs <= 0 {
		maxUEs = 16
	}
	per := total / uint32(maxUEs)
	if per < 8192 {
		per = 8192
	}
	return per
}

// Downlink qdisc handles on SourceIf. Chosen not to collide with the uplink
// tree's 1:/10: on the ifb device, so the two are easy to tell apart in
// `tc qdisc show` output when debugging.
const (
	dlRootHandle = "2:"
	dlClassID    = "2:20"
	dlLeafHandle = "20:"
)

// DLEnabled reports whether this spec asks for a downlink buffer.
func (s EgressBufferSpec) DLEnabled() bool {
	return s.DLRate != "" && s.DLLimitBytes > 0
}

func run(log *logrus.Entry, args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err,
			strings.TrimSpace(string(out)))
	}
	if t := strings.TrimSpace(string(out)); t != "" {
		log.Debugf("%s: %s", strings.Join(args, " "), t)
	}
	return nil
}

// runIgnore executes a teardown command whose failure is expected when the
// object does not exist yet.
func runIgnore(args ...string) {
	_ = exec.Command(args[0], args[1:]...).Run()
}

// SetupEgressBuffer builds the uplink buffer and, when DLRate is set, the
// downlink one. It is idempotent: an existing tree is torn down and rebuilt,
// so a UPF restart does not inherit a half-built one.
func SetupEgressBuffer(spec EgressBufferSpec, log *logrus.Entry) error {
	if spec.IfName == "" || spec.SourceIf == "" {
		return fmt.Errorf("egress buffer: ifname and sourceIf are required")
	}
	if spec.Rate == "" {
		return fmt.Errorf("egress buffer: rate is required (without a " +
			"bottleneck the buffer never fills and the metric reads 0)")
	}
	if spec.LimitBytes == 0 {
		return fmt.Errorf("egress buffer: limitBytes is required (it is the " +
			"metric's denominator)")
	}

	// Clean slate.
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "handle", "ffff:", "ingress")
	runIgnore("tc", "qdisc", "del", "dev", spec.IfName, "root")
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "root")

	// The ifb device may already exist from a previous run in this netns.
	if err := run(log, "ip", "link", "add", spec.IfName, "type", "ifb"); err != nil {
		if err2 := run(log, "ip", "link", "show", spec.IfName); err2 != nil {
			return fmt.Errorf("create %s: %w (is the ifb kernel module "+
				"available on the host?)", spec.IfName, err)
		}
		log.Infof("egress buffer: reusing existing device %s", spec.IfName)
	}
	if err := run(log, "ip", "link", "set", spec.IfName, "up"); err != nil {
		return err
	}

	// Pre-NAT uplink -> the egress buffer.
	if err := run(log, "tc", "qdisc", "add", "dev", spec.SourceIf,
		"handle", "ffff:", "ingress"); err != nil {
		return err
	}
	if err := run(log, "tc", "filter", "add", "dev", spec.SourceIf,
		"parent", "ffff:", "protocol", "ip", "prio", "1", "u32",
		"match", "u32", "0", "0",
		"action", "mirred", "egress", "redirect", "dev", spec.IfName); err != nil {
		return err
	}

	// The bottleneck, then the byte-bounded buffer(s) the metric reads.
	if spec.PerUE {
		if err := spec.ULQueue().Build(log); err != nil {
			return fmt.Errorf("uplink per-UE queues: %w", err)
		}
	} else {
		if err := run(log, "tc", "qdisc", "add", "dev", spec.IfName,
			"root", "handle", "1:", "htb", "default", "10"); err != nil {
			return err
		}
		if err := run(log, "tc", "class", "add", "dev", spec.IfName,
			"parent", "1:", "classid", "1:10", "htb",
			"rate", spec.Rate, "ceil", spec.Rate, "burst", "8k"); err != nil {
			return err
		}
		if err := run(log, "tc", "qdisc", "add", "dev", spec.IfName,
			"parent", "1:10", "handle", "10:", "bfifo",
			"limit", fmt.Sprintf("%d", spec.LimitBytes)); err != nil {
			return err
		}
		log.Infof("uplink buffer ready: %s ingress -> %s, htb %s, bfifo limit %d B",
			spec.SourceIf, spec.IfName, spec.Rate, spec.LimitBytes)
	}

	if spec.DLEnabled() {
		if err := setupDownlinkBuffer(spec, log); err != nil {
			return fmt.Errorf("downlink buffer: %w", err)
		}
	}
	return nil
}

// setupDownlinkBuffer puts a bounded queue on the gtp5g link's EGRESS, which
// is the downlink path toward the gNB. No ifb is needed: unlike ingress, an
// egress root qdisc can queue.
func setupDownlinkBuffer(spec EgressBufferSpec, log *logrus.Entry) error {
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "root")

	if spec.PerUE {
		return spec.DLQueue().Build(log)
	}

	if err := run(log, "tc", "qdisc", "add", "dev", spec.SourceIf,
		"root", "handle", dlRootHandle, "htb", "default", "20"); err != nil {
		return err
	}
	if err := run(log, "tc", "class", "add", "dev", spec.SourceIf,
		"parent", dlRootHandle, "classid", dlClassID, "htb",
		"rate", spec.DLRate, "ceil", spec.DLRate, "burst", "8k"); err != nil {
		return err
	}
	if err := run(log, "tc", "qdisc", "add", "dev", spec.SourceIf,
		"parent", dlClassID, "handle", dlLeafHandle, "bfifo",
		"limit", fmt.Sprintf("%d", spec.DLLimitBytes)); err != nil {
		return err
	}
	log.Infof("downlink buffer ready: %s egress, htb %s, bfifo limit %d B",
		spec.SourceIf, spec.DLRate, spec.DLLimitBytes)
	return nil
}

// TeardownEgressBuffer removes what SetupEgressBuffer built, in both
// directions.
func TeardownEgressBuffer(spec EgressBufferSpec) {
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "handle", "ffff:", "ingress")
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "root")
	runIgnore("tc", "qdisc", "del", "dev", spec.IfName, "root")
	runIgnore("ip", "link", "del", spec.IfName)
}
