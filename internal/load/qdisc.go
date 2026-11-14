// Package load computes the UPF's egress load metric: an integer 0..100 that
// later feeds the PFCP Load Control Information IE (TS 29.244 8.2.54).
//
// qdisc.go reads the egress buffer's occupancy and capacity straight from the
// kernel over rtnetlink (RTM_GETQDISC), rather than shelling out to `tc` and
// parsing its text. Two reasons: the UPF samples this several times a second,
// so a fork per sample is wasteful; and `tc` output is a human format that has
// changed shape before, while the netlink attribute layout is ABI.
package load

import (
	"encoding/binary"
	"fmt"
	"sync"
	"syscall"
	"unsafe"
)

// Netlink attribute helpers. Decoded locally rather than with go-nl's, so this
// file depends only on the kernel ABI.
//
//	struct nlattr { __u16 nla_len; __u16 nla_type; }
//
// nla_len covers the header plus payload; each attribute is padded to 4 bytes.
const (
	sizeofNlAttr = 4
	nlaTypeMask  = 0x3fff // strip NLA_F_NESTED | NLA_F_NET_BYTEORDER
)

func nlaAlign(l int) int { return (l + 3) &^ 3 }

// nextAttr splits b into the first attribute's type, value and the remainder.
func nextAttr(b []byte) (typ int, val, rest []byte, ok bool) {
	if len(b) < sizeofNlAttr {
		return 0, nil, nil, false
	}
	alen := int(native.Uint16(b[0:2]))
	atyp := int(native.Uint16(b[2:4])) & nlaTypeMask
	if alen < sizeofNlAttr || alen > len(b) {
		return 0, nil, nil, false
	}
	adv := nlaAlign(alen)
	if adv > len(b) {
		adv = len(b)
	}
	return atyp, b[sizeofNlAttr:alen], b[adv:], true
}

// rtnetlink constants. Not exported by go-nl, which is a generic netlink
// primitive library with no traffic-control support, so they are named here
// from include/uapi/linux/rtnetlink.h and pkt_sched.h.
const (
	rtmGetQdisc = 38 // RTM_GETQDISC

	tcaKind    = 1 // TCA_KIND    - qdisc name, e.g. "bfifo"
	tcaOptions = 2 // TCA_OPTIONS - kind-specific; for *fifo it is tc_fifo_qopt
	tcaStats2  = 7 // TCA_STATS2  - nested, holds the queue stats

	tcaStatsQueue = 3 // TCA_STATS_QUEUE inside TCA_STATS2

	sizeofTcmsg = 20 // struct tcmsg
)

// QdiscStats is one egress buffer's occupancy and capacity, both in bytes.
type QdiscStats struct {
	Kind       string
	Ifindex    int
	Handle     uint32
	BacklogB   uint32 // bytes currently queued -- the egress buffer size
	BacklogPkt uint32 // packets currently queued, for diagnostics
	LimitB     uint32 // the queue's capacity -- the max buffer size
	Drops      uint32
}

// tcmsg mirrors struct tcmsg. Only Ifindex is set on a dump request; the
// kernel fills the rest in each reply.
type tcmsg struct {
	Family  uint8
	Pad1    uint8
	Pad2    uint16
	Ifindex int32
	Handle  uint32
	Parent  uint32
	Info    uint32
}

var native = func() binary.ByteOrder {
	var i uint16 = 1
	if (*[2]byte)(unsafe.Pointer(&i))[0] == 1 {
		return binary.LittleEndian
	}
	return binary.BigEndian
}()

// QdiscReader issues RTM_GETQDISC dumps.
//
// This uses raw netlink syscalls rather than the go-nl Client the rest of the
// repo uses for gtp5g. go-nl's request path returned zero messages for a
// qdisc dump in testing while the identical request built by hand returned the
// expected replies, and its Open() panics on an explicit zero multicast group
// (`1 << (group-1)`). A dump is a single request/response with no multiplexing
// needed, so the syscalls are both simpler and verifiable -- see
// TestReadsRealBfifoQdisc, which pins the wire format against a real qdisc.
type QdiscReader struct {
	mu sync.Mutex
	fd int
	// seq distinguishes our replies from anything else on the socket.
	seq uint32
}

// NewQdiscReader opens a route-netlink socket for reading qdisc statistics.
func NewQdiscReader() (*QdiscReader, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_RAW|syscall.SOCK_CLOEXEC,
		syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("open NETLINK_ROUTE: %w", err)
	}
	// Bind with no multicast groups: this socket only does request/response.
	if err := syscall.Bind(fd, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("bind netlink: %w", err)
	}
	// A dump that is never answered must not wedge the sampler goroutine.
	tv := syscall.Timeval{Sec: 2}
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET,
		syscall.SO_RCVTIMEO, &tv); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("set receive timeout: %w", err)
	}
	return &QdiscReader{fd: fd}, nil
}

func (r *QdiscReader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fd >= 0 {
		syscall.Close(r.fd)
		r.fd = -1
	}
}

const sizeofNlMsghdr = 16

// Dump returns every qdisc on the given interface index, or on all interfaces
// when ifindex is 0.
func (r *QdiscReader) Dump(ifindex int) ([]QdiscStats, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.fd < 0 {
		return nil, fmt.Errorf("qdisc reader is closed")
	}

	r.seq++
	seq := r.seq
	req := make([]byte, sizeofNlMsghdr+sizeofTcmsg)
	h := (*syscall.NlMsghdr)(unsafe.Pointer(&req[0]))
	h.Len = uint32(len(req))
	h.Type = rtmGetQdisc
	h.Flags = syscall.NLM_F_REQUEST | syscall.NLM_F_DUMP
	h.Seq = seq
	m := (*tcmsg)(unsafe.Pointer(&req[sizeofNlMsghdr]))
	m.Family = syscall.AF_UNSPEC
	// The kernel ignores ifindex on a dump and returns every interface, so the
	// filtering is done on the replies below rather than relied on here.
	m.Ifindex = int32(ifindex)

	if err := syscall.Sendto(r.fd, req, 0, &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
	}); err != nil {
		return nil, fmt.Errorf("send RTM_GETQDISC: %w", err)
	}

	var out []QdiscStats
	buf := make([]byte, 1<<16)
	for {
		n, _, err := syscall.Recvfrom(r.fd, buf, 0)
		if err != nil {
			return nil, fmt.Errorf("receive qdisc dump: %w", err)
		}
		msgs, err := syscall.ParseNetlinkMessage(buf[:n])
		if err != nil {
			return nil, fmt.Errorf("parse qdisc dump: %w", err)
		}
		done := false
		for i := range msgs {
			msg := &msgs[i]
			if msg.Header.Seq != seq {
				continue // not ours
			}
			switch msg.Header.Type {
			case syscall.NLMSG_DONE:
				done = true
				continue
			case syscall.NLMSG_ERROR:
				return nil, fmt.Errorf("netlink error in qdisc dump")
			}
			if len(msg.Data) < sizeofTcmsg {
				continue
			}
			tm := (*tcmsg)(unsafe.Pointer(&msg.Data[0]))
			if ifindex != 0 && int(tm.Ifindex) != ifindex {
				continue
			}
			st := QdiscStats{Handle: tm.Handle, Ifindex: int(tm.Ifindex)}
			if err := parseQdiscAttrs(msg.Data[sizeofTcmsg:], &st); err != nil {
				continue // one unparseable qdisc must not hide the others
			}
			out = append(out, st)
		}
		if done {
			break
		}
	}
	return out, nil
}

// FindByKind returns the first qdisc of the given kind on the interface. The
// buffer is located by KIND rather than by a remembered handle, so the metric
// keeps working if the qdisc is rebuilt with a different handle.
func (r *QdiscReader) FindByKind(ifindex int, kind string) (QdiscStats, error) {
	all, err := r.Dump(ifindex)
	if err != nil {
		return QdiscStats{}, err
	}
	for _, q := range all {
		if q.Kind == kind {
			return q, nil
		}
	}
	return QdiscStats{}, fmt.Errorf("no %q qdisc on ifindex %d", kind, ifindex)
}

func parseQdiscAttrs(b []byte, st *QdiscStats) error {
	for {
		typ, val, rest, ok := nextAttr(b)
		if !ok {
			return nil
		}
		switch typ {
		case tcaKind:
			// NUL-terminated string.
			if i := indexByte(val, 0); i >= 0 {
				st.Kind = string(val[:i])
			} else {
				st.Kind = string(val)
			}
		case tcaOptions:
			// For bfifo/pfifo, TCA_OPTIONS is struct tc_fifo_qopt{__u32 limit}:
			// bytes for bfifo, packets for pfifo. Only bfifo gives a byte
			// capacity, which is why the egress buffer is built as bfifo.
			if len(val) >= 4 {
				st.LimitB = native.Uint32(val[:4])
			}
		case tcaStats2:
			parseStats2(val, st)
		}
		b = rest
	}
}

func parseStats2(b []byte, st *QdiscStats) {
	for {
		typ, val, rest, ok := nextAttr(b)
		if !ok {
			return
		}
		if typ == tcaStatsQueue && len(val) >= 12 {
			// struct gnet_stats_queue{qlen,backlog,drops,requeues,overlimits}
			st.BacklogPkt = native.Uint32(val[0:4])
			st.BacklogB = native.Uint32(val[4:8])
			st.Drops = native.Uint32(val[8:12])
		}
		b = rest
	}
}

func indexByte(b []byte, c byte) int {
	for i := range b {
		if b[i] == c {
			return i
		}
	}
	return -1
}
