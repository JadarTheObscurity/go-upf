package load

import (
	"fmt"
	"os/exec"
	"testing"
)

// Reads a REAL bfifo qdisc over netlink and checks the values against what tc
// reports. This is the test that pins the wire format: the parsing is all
// offsets into kernel structs, so a unit test with synthetic bytes would only
// re-assert my own assumptions.
//
// Needs root and iproute2; skips otherwise.
func TestReadsRealBfifoQdisc(t *testing.T) {
	const dev = "ltest0"
	const limit = 65536

	_ = exec.Command("ip", "link", "add", dev, "type", "dummy").Run()
	defer func() { _ = exec.Command("ip", "link", "del", dev).Run() }()
	if err := exec.Command("ip", "link", "set", dev, "up").Run(); err != nil {
		t.Skipf("cannot bring up %s (needs root): %v", dev, err)
	}
	_ = exec.Command("tc", "qdisc", "del", "dev", dev, "root").Run()
	if err := exec.Command("tc", "qdisc", "add", "dev", dev, "root",
		"handle", "1:", "bfifo", "limit", fmt.Sprint(limit)).Run(); err != nil {
		t.Skipf("cannot add bfifo: %v", err)
	}

	out, err := exec.Command("cat", "/sys/class/net/"+dev+"/ifindex").Output()
	if err != nil {
		t.Fatalf("ifindex: %v", err)
	}
	var idx int
	if _, err := fmt.Sscan(string(out), &idx); err != nil {
		t.Fatalf("parse ifindex: %v", err)
	}

	r, err := NewQdiscReader()
	if err != nil {
		t.Fatalf("NewQdiscReader: %v", err)
	}
	defer r.Close()

	q, err := r.FindByKind(idx, "bfifo")
	if err != nil {
		t.Fatalf("FindByKind: %v", err)
	}
	// The byte limit is the metric's denominator; if this is wrong every
	// reported percentage is wrong.
	if q.LimitB != limit {
		t.Errorf("limit = %d bytes, want %d", q.LimitB, limit)
	}
	if q.Ifindex != idx {
		t.Errorf("ifindex = %d, want %d", q.Ifindex, idx)
	}
	if q.Kind != "bfifo" {
		t.Errorf("kind = %q, want bfifo", q.Kind)
	}

	// The per-ifindex filter must actually narrow the dump: the kernel returns
	// every interface on a dump regardless of what the request asks for.
	all, err := r.Dump(0)
	if err != nil {
		t.Fatalf("Dump(0): %v", err)
	}
	one, err := r.Dump(idx)
	if err != nil {
		t.Fatalf("Dump(%d): %v", idx, err)
	}
	if len(one) >= len(all) || len(one) == 0 {
		t.Errorf("per-ifindex filter did not narrow the dump: %d of %d",
			len(one), len(all))
	}
	for _, g := range one {
		if g.Ifindex != idx {
			t.Errorf("filtered dump returned ifindex %d, want %d", g.Ifindex, idx)
		}
	}

	// A kind that is not there must be an error, not a zero value that would
	// read as a healthy 0%% load.
	if _, err := r.FindByKind(idx, "nosuchqdisc"); err == nil {
		t.Error("FindByKind on a missing kind returned no error")
	}
}

// A closed reader must report an error rather than touching a closed fd.
func TestClosedReaderErrors(t *testing.T) {
	r, err := NewQdiscReader()
	if err != nil {
		t.Skipf("cannot open netlink: %v", err)
	}
	r.Close()
	r.Close() // must be idempotent
	if _, err := r.Dump(1); err == nil {
		t.Error("Dump on a closed reader returned no error")
	}
}
