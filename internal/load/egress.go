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

// EgressBufferSpec describes the buffer to build.
type EgressBufferSpec struct {
	// IfName is the ifb device to create, e.g. "upfegress".
	IfName string
	// SourceIf is the interface whose ingress is redirected, normally the
	// gtp5g link ("upfgtp"): pre-NAT, decapsulated uplink user traffic.
	SourceIf string
	// Rate is the bottleneck, in tc syntax ("500kbit"). Required: with no
	// bottleneck the buffer never fills and the metric is always 0.
	Rate string
	// LimitBytes is the buffer capacity -- the metric's denominator.
	LimitBytes uint32
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

// SetupEgressBuffer builds the buffer. It is idempotent: an existing buffer is
// torn down and rebuilt, so a UPF restart does not inherit a half-built tree.
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

	// The bottleneck, then the byte-bounded buffer the metric reads.
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

	log.Infof("egress buffer ready: %s ingress -> %s, htb %s, bfifo limit %d B",
		spec.SourceIf, spec.IfName, spec.Rate, spec.LimitBytes)
	return nil
}

// TeardownEgressBuffer removes what SetupEgressBuffer built.
func TeardownEgressBuffer(spec EgressBufferSpec) {
	runIgnore("tc", "qdisc", "del", "dev", spec.SourceIf, "handle", "ffff:", "ingress")
	runIgnore("tc", "qdisc", "del", "dev", spec.IfName, "root")
	runIgnore("ip", "link", "del", spec.IfName)
}
