// Package metrics exports UPF network statistics in Prometheus text format.
//
// perue.go reads the gtp5g datapath's own per-PDR counters, which are the only
// per-UE view available: the load metric's qdiscs are a single shared buffer
// per direction, so they can report aggregate throughput and drops but cannot
// attribute either to a UE.
//
// THE PROCFS INTERFACE
// /proc/gtp5g/pdr is write-then-read: write "<netdev> <seid> <pdr_id>" to
// select a rule, then read the file to get that rule's dump. There is no way
// to enumerate rules, so this walks a bounded SEID/PDR space and keeps what
// answers. The write and the read must stay paired under one lock, because the
// selection is global state in the kernel module.
//
// Two things make the bounds non-obvious, both learned by measurement:
//
//   - A write for a (seid, pdr_id) that does not exist fails with EIO, and a
//     READ with nothing selected then returns EPERM -- proc_pdr_read() returns
//     -1 while proc_pdr_id == 0. So EPERM on read means "the write did not
//     select anything", not "insufficient privilege".
//   - PDR IDs are NOT small per-session ordinals. They are allocated across
//     the whole UPF, so a handful of sessions already yields IDs like
//     13, 14, 29, 30, 32, 33, 37. A scan capped at a small PDR id finds
//     NOTHING even with sessions established -- which is exactly how an
//     earlier version of this reader silently exported no per-UE metrics.
//     The default bound is therefore generous, and the scan remembers the
//     highest id that has answered so a quiet UPF is not rescanned in full.
//
// Fields used, from a real dump:
//
//	PDI UE Addr4: 10.60.0.1(0xa3c0001)   <- the per-UE key
//	UL Packet Count: 4078                 <- forwarded, uplink
//	DL Packet Count: 137                  <- forwarded, downlink
//	UL Byte Count: 35250120               <- the same, in bytes
//	DL Byte Count: 0
//	UL Drop Count: 0x0                    <- discarded by the datapath
//	DL Drop Count: 0x0
//
// Counts are cumulative since the rule was installed, which is what a
// Prometheus counter wants. Note each session has SEVERAL PDRs -- typically
// one matching uplink and one matching downlink -- so a UE's totals are the
// SUM over its PDRs, and a single PDR carries traffic in one direction only.
package metrics

import (
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

const defaultPDRPath = "/proc/gtp5g/pdr"

// UEStats is one UE's datapath counters, summed over its PDRs.
type UEStats struct {
	Addr      string
	ULPackets uint64
	DLPackets uint64
	// Bytes as well as packets, so throughput can be reported in bit/s --
	// the conventional unit -- rather than packets/s. Deriving bits from a
	// packet count would need an assumed packet size, which is wrong for
	// any real traffic mix.
	ULBytes uint64
	DLBytes uint64
	ULDrops uint64
	DLDrops uint64
	PDRs    int
}

var (
	reUEAddr = regexp.MustCompile(`PDI UE Addr4:\s*([0-9.]+)`)
	reULPkt  = regexp.MustCompile(`UL Packet Count:\s*(\S+)`)
	reDLPkt  = regexp.MustCompile(`DL Packet Count:\s*(\S+)`)
	reULDrop = regexp.MustCompile(`UL Drop Count:\s*(\S+)`)
	reDLDrop = regexp.MustCompile(`DL Drop Count:\s*(\S+)`)
	reULByte = regexp.MustCompile(`UL Byte Count:\s*(\S+)`)
	reDLByte = regexp.MustCompile(`DL Byte Count:\s*(\S+)`)
)

// PDRReader walks /proc/gtp5g/pdr. Safe for concurrent use: the write-then-read
// pair is a shared global selection in the kernel module, so it is serialised.
type PDRReader struct {
	mu       sync.Mutex
	path     string
	dev      string
	maxSEID  uint64
	maxPDRID uint64

	// Highest SEID and PDR id seen to answer, so a quiet UPF is not rescanned
	// to the full bound every time. Both grow as sessions are added.
	seidHigh uint64
	pdrHigh  uint64
}

func NewPDRReader(dev string, maxSEID, maxPDRID uint64) *PDRReader {
	if dev == "" {
		dev = "upfgtp"
	}
	if maxSEID == 0 {
		maxSEID = 64
	}
	if maxPDRID == 0 {
		// PDR IDs are UPF-wide, not per-session: see the package comment.
		// 512 covers a lab with tens of sessions; the scan stops early at
		// pdrHigh+8 once it knows where the rules actually are.
		maxPDRID = 512
	}
	return &PDRReader{
		path: defaultPDRPath, dev: dev,
		maxSEID: maxSEID, maxPDRID: maxPDRID,
	}
}

// Available reports whether the procfs interface exists and is writable.
//
// It deliberately does NOT try a write: gtp5g answers a selection for a rule
// that does not exist with EIO, so a probe write fails on a UPF with no
// sessions yet. An exporter that gave up on that would disable per-UE metrics
// permanently, since the check runs at startup -- before any UE attaches.
// Presence and permission are all that can be established up front; whether
// any rules exist is answered per scan, by Scan().
func (r *PDRReader) Available() error {
	st, err := os.Stat(r.path)
	if err != nil {
		return fmt.Errorf("%s not present (needs the gtp5g module): %w",
			r.path, err)
	}
	if st.Mode().Perm()&0o200 == 0 {
		return fmt.Errorf("%s is not writable; the per-UE scan needs to "+
			"write a rule selector before reading", r.path)
	}
	return nil
}

// parseUint accepts both the decimal and the 0x forms the dump mixes.
func parseUint(s string) (uint64, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, false
	}
	if strings.HasPrefix(s, "0x") || strings.HasPrefix(s, "0X") {
		v, err := strconv.ParseUint(s[2:], 16, 64)
		return v, err == nil
	}
	v, err := strconv.ParseUint(s, 10, 64)
	return v, err == nil
}

func field(re *regexp.Regexp, body string) (uint64, bool) {
	m := re.FindStringSubmatch(body)
	if m == nil {
		return 0, false
	}
	return parseUint(m[1])
}

// readOne selects a single PDR and returns its dump.
func (r *PDRReader) readOne(seid, pdrID uint64) (string, error) {
	f, err := os.OpenFile(r.path, os.O_WRONLY, 0)
	if err != nil {
		return "", err
	}
	_, err = fmt.Fprintf(f, "%s %d %d", r.dev, seid, pdrID)
	cerr := f.Close()
	if err != nil {
		return "", err
	}
	if cerr != nil {
		return "", cerr
	}
	b, err := os.ReadFile(r.path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Scan returns per-UE counters, keyed by UE IPv4 address.
func (r *PDRReader) Scan() (map[string]*UEStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	out := make(map[string]*UEStats)
	// Scan a little past the highest SEID that has ever answered, so newly
	// established sessions are picked up without walking the whole bound.
	limit := r.seidHigh + 8
	if limit > r.maxSEID {
		limit = r.maxSEID
	}
	if limit < 8 {
		limit = 8
	}
	// Same idea for PDR ids, but the window has to be wide enough to FIND the
	// first rule: ids are UPF-wide and start well above 1, so a narrow initial
	// window would never discover any and pdrHigh would stay 0 forever.
	pdrLimit := r.pdrHigh + 16
	if r.pdrHigh == 0 {
		pdrLimit = r.maxPDRID
	}
	if pdrLimit > r.maxPDRID {
		pdrLimit = r.maxPDRID
	}

	var firstErr error
	for seid := uint64(1); seid <= limit; seid++ {
		for pdr := uint64(1); pdr <= pdrLimit; pdr++ {
			body, err := r.readOne(seid, pdr)
			if err != nil {
				// gtp5g returns EIO for a rule that does not exist, which is
				// the normal case across most of the probed range -- it is
				// "no such rule", not a malfunction. Only remember it in case
				// NOTHING at all answers, so a genuinely broken interface can
				// still be reported.
				if firstErr == nil {
					firstErr = err
				}
				continue
			}
			addr := reUEAddr.FindStringSubmatch(body)
			if addr == nil || addr[1] == "" || addr[1] == "0.0.0.0" {
				continue // no such rule, or one with no UE address
			}
			if seid > r.seidHigh {
				r.seidHigh = seid
			}
			if pdr > r.pdrHigh {
				r.pdrHigh = pdr
			}
			st := out[addr[1]]
			if st == nil {
				st = &UEStats{Addr: addr[1]}
				out[addr[1]] = st
			}
			st.PDRs++
			if v, ok := field(reULPkt, body); ok {
				st.ULPackets += v
			}
			if v, ok := field(reDLPkt, body); ok {
				st.DLPackets += v
			}
			if v, ok := field(reULByte, body); ok {
				st.ULBytes += v
			}
			if v, ok := field(reDLByte, body); ok {
				st.DLBytes += v
			}
			if v, ok := field(reULDrop, body); ok {
				st.ULDrops += v
			}
			if v, ok := field(reDLDrop, body); ok {
				st.DLDrops += v
			}
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	return out, nil
}
