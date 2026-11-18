// exporter.go: the /metrics endpoint.
//
// Written against the Prometheus text exposition format directly rather than
// with the client_golang library: go-upf does not depend on it today, and the
// whole surface here is a handful of counters and gauges. Adding a dependency
// to format ~20 lines of text would be the larger change. The format is
// stable and documented, and the output is checked by a test that parses it
// back.
//
// WHAT IS EXPORTED AND WHERE IT COMES FROM
//
//	upf_load_metric                 LCI = max(UL,DL)        load.Combiner
//	upf_direction_load_metric       per-direction 0..100     load.Tracker
//	upf_buffer_bytes / _max_bytes   egress buffer occupancy  qdisc stats
//	upf_tx_bytes_total / _packets   forwarded per direction  qdisc stats
//	upf_dropped_packets_total       drops per direction      qdisc stats
//	upf_ue_offered_bytes_total      per-UE OFFERED load      gtp5g procfs
//	upf_ue_forwarded_bytes_total    per-UE delivered         per-UE tc class
//	upf_ue_offered_packets_total    per-UE OFFERED load      gtp5g procfs
//	upf_ue_forwarded_packets_total  per-UE delivered         per-UE tc class
//	upf_ue_dropped_packets_total    per-UE shaper loss       per-UE tc class
//	upf_ue_buffer_bytes             per-UE queue occupancy   per-UE tc class
//	upf_ue_sessions                 UEs with datapath rules  gtp5g procfs
//
// TWO SOURCES FOR PER-UE DATA, AND WHY BOTH
// gtp5g's per-PDR counters are taken BEFORE the shaper, so its "forwarded"
// count is really the OFFERED load and its drop counters stay at zero under
// shaper congestion. Measured on a loaded UPF: 38,786 aggregate shaper drops
// while every per-PDR ul_drops read 0x0, and the per-PDR forwarded totals
// matched the shaper's INPUT (66,750) rather than its output (27,920).
// Real per-UE loss therefore comes from each UE's own tc class, where the
// forwarded and dropped counts are measured at the same point.
//
// Throughput is deliberately NOT exported as a rate: a counter plus
// Prometheus' own rate() is correct across scrape gaps and restarts, whereas a
// pre-computed gauge silently depends on the exporter's sampling interval.
//
// BYTES AND PACKETS BOTH, PER UE
// Throughput belongs in bit/s, so every per-UE volume is exported in bytes as
// well as packets: rate(bytes)*8 gives bit/s directly. Deriving bits from a
// packet count would need an assumed packet size, which is wrong for any real
// traffic mix. Packet counts stay because LOSS is a packet ratio -- a byte
// ratio would understate the loss of small packets.
package metrics

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/load"
)

// QdiscSource supplies the per-direction buffer and traffic counters. The
// load package owns the netlink reading, so this is an interface rather than a
// second reader: one qdisc dump per scrape, not two.
type QdiscSource interface {
	// DirectionStats returns the current counters for one direction.
	DirectionStats(dir load.Direction) (load.QdiscStats, error)
}

// Exporter serves /metrics.
// UELossSource supplies per-UE shaper counters, one entry per UE per
// direction. Implemented by load.UETracker.
type UELossSource interface {
	Losses() ([]load.UELoss, error)
	TrackedUEs() int
}

type Exporter struct {
	combiner *load.Combiner
	qdisc    QdiscSource
	perUE    *PDRReader
	ueLoss   []UELossSource
	log      *logrus.Entry
	srv      *http.Server

	// Per-UE scanning walks procfs with a write-then-read per rule, which is
	// far more expensive than a qdisc dump. It is cached so that a tight
	// scrape interval, or several concurrent scrapers, cannot turn monitoring
	// into load on the datapath.
	mu        sync.Mutex
	ueCache   map[string]*UEStats
	ueCacheAt time.Time
	ueTTL     time.Duration
	ueErr     error
	ueEnabled bool
}

// AddUELossSource registers a per-direction per-UE loss source.
func (e *Exporter) AddUELossSource(s UELossSource) {
	e.ueLoss = append(e.ueLoss, s)
}

func NewExporter(combiner *load.Combiner, qdisc QdiscSource, perUE *PDRReader,
	ueTTL time.Duration, log *logrus.Entry,
) *Exporter {
	if ueTTL <= 0 {
		ueTTL = 2 * time.Second
	}
	e := &Exporter{
		combiner: combiner, qdisc: qdisc, perUE: perUE,
		ueTTL: ueTTL, log: log,
	}
	if perUE != nil {
		if err := perUE.Available(); err != nil {
			// Not fatal: the aggregate metrics are still worth exporting, and
			// a UPF without the procfs interface should still be monitorable.
			log.Warnf("per-UE metrics unavailable, exporting aggregates only: %v", err)
		} else {
			e.ueEnabled = true
		}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", e.handle)
	e.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return e
}

func (e *Exporter) ueStats() (map[string]*UEStats, error) {
	if !e.ueEnabled {
		return nil, nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if time.Since(e.ueCacheAt) < e.ueTTL {
		return e.ueCache, e.ueErr
	}
	st, err := e.perUE.Scan()
	e.ueCache, e.ueErr, e.ueCacheAt = st, err, time.Now()
	return st, err
}

type writer struct{ b strings.Builder }

func (w *writer) meta(name, typ, help string) {
	fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, typ)
}

func (w *writer) val(name, labels string, v any) {
	if labels != "" {
		fmt.Fprintf(&w.b, "%s{%s} %v\n", name, labels, v)
	} else {
		fmt.Fprintf(&w.b, "%s %v\n", name, v)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (e *Exporter) handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	out := &writer{}

	// ---- the load metric -------------------------------------------------
	lci := e.combiner.LCI()
	out.meta("upf_load_metric", "gauge",
		"Node load metric 0..100 for PFCP Load Control Information: max(UL,DL)")
	out.val("upf_load_metric", "", lci.Value)

	out.meta("upf_load_metric_healthy", "gauge",
		"1 when every enabled direction is measuring; the load metric is not trustworthy otherwise")
	out.val("upf_load_metric_healthy", "", b2i(lci.Healthy))

	out.meta("upf_load_metric_dominant", "gauge",
		"1 for the direction currently holding the maximum load")
	out.val("upf_load_metric_dominant", `direction="UL"`,
		b2i(lci.Dominant == load.DirUplink))
	out.val("upf_load_metric_dominant", `direction="DL"`,
		b2i(lci.Dominant == load.DirDownlink))

	// ---- per-direction ---------------------------------------------------
	dirs := []struct {
		dir load.Direction
		m   *load.Metric
	}{{load.DirUplink, &lci.Uplink}}
	if lci.Downlink != nil {
		dirs = append(dirs, struct {
			dir load.Direction
			m   *load.Metric
		}{load.DirDownlink, lci.Downlink})
	}

	out.meta("upf_direction_load_metric", "gauge",
		"Per-direction load metric 0..100: floor(buffer bytes / max buffer bytes * 100), time averaged")
	for _, d := range dirs {
		out.val("upf_direction_load_metric",
			fmt.Sprintf("direction=%q", d.dir), d.m.Value)
	}

	out.meta("upf_buffer_bytes", "gauge", "Bytes currently queued in the egress buffer")
	for _, d := range dirs {
		out.val("upf_buffer_bytes", fmt.Sprintf("direction=%q", d.dir), d.m.BacklogBytes)
	}
	out.meta("upf_buffer_max_bytes", "gauge",
		"Egress buffer capacity: the load metric's denominator")
	for _, d := range dirs {
		out.val("upf_buffer_max_bytes", fmt.Sprintf("direction=%q", d.dir), d.m.MaxBytes)
	}
	out.meta("upf_buffer_packets", "gauge", "Packets currently queued in the egress buffer")
	for _, d := range dirs {
		out.val("upf_buffer_packets", fmt.Sprintf("direction=%q", d.dir), d.m.BacklogPkts)
	}

	// ---- throughput and drops, from the qdisc ---------------------------
	// Exported as counters: rate() over a counter survives scrape gaps and
	// exporter restarts, which a pre-computed throughput gauge does not.
	if e.qdisc != nil {
		out.meta("upf_tx_bytes_total", "counter",
			"Bytes forwarded through the egress buffer; use rate() for throughput")
		out.meta("upf_tx_packets_total", "counter",
			"Packets forwarded through the egress buffer")
		out.meta("upf_dropped_packets_total", "counter",
			"Packets dropped by the egress buffer because it was full")
		for _, d := range dirs {
			q, err := e.qdisc.DirectionStats(d.dir)
			if err != nil {
				continue
			}
			lbl := fmt.Sprintf("direction=%q", d.dir)
			out.val("upf_tx_bytes_total", lbl, q.SentBytes)
			out.val("upf_tx_packets_total", lbl, q.SentPkts)
			out.val("upf_dropped_packets_total", lbl, q.Drops)
		}
	}

	// ---- per-UE, from the gtp5g datapath --------------------------------
	ue, ueErr := e.ueStats()
	out.meta("upf_per_ue_metrics_available", "gauge",
		"1 when per-UE datapath counters can be read from /proc/gtp5g/pdr")
	out.val("upf_per_ue_metrics_available", "", b2i(e.ueEnabled && ueErr == nil))

	if len(ue) > 0 {
		out.meta("upf_ue_sessions", "gauge",
			"Number of UEs with datapath rules installed")
		out.val("upf_ue_sessions", "", len(ue))

		// Sorted so the output is stable between scrapes, which makes a diff
		// of two scrapes readable when debugging.
		addrs := make([]string, 0, len(ue))
		for a := range ue {
			addrs = append(addrs, a)
		}
		sort.Strings(addrs)

		// OFFERED, not forwarded: these counts come from gtp5g, upstream of
		// the shaper, so they include packets the shaper later dropped.
		out.meta("upf_ue_offered_bytes_total", "counter",
			"Bytes gtp5g accepted for one UE in one direction, measured "+
				"BEFORE the egress shaper: offered load, not delivered. "+
				"Use rate()*8 for bit/s")
		for _, a := range addrs {
			s := ue[a]
			out.val("upf_ue_offered_bytes_total",
				fmt.Sprintf("ue=%q,direction=\"UL\"", a), s.ULBytes)
			out.val("upf_ue_offered_bytes_total",
				fmt.Sprintf("ue=%q,direction=\"DL\"", a), s.DLBytes)
		}
		out.meta("upf_ue_offered_packets_total", "counter",
			"Packets gtp5g accepted for one UE in one direction, measured "+
				"BEFORE the egress shaper. Kept alongside the byte counter "+
				"because loss is a packet ratio")
		for _, a := range addrs {
			s := ue[a]
			out.val("upf_ue_offered_packets_total",
				fmt.Sprintf("ue=%q,direction=\"UL\"", a), s.ULPackets)
			out.val("upf_ue_offered_packets_total",
				fmt.Sprintf("ue=%q,direction=\"DL\"", a), s.DLPackets)
		}
		out.meta("upf_ue_datapath_dropped_packets_total", "counter",
			"Packets the gtp5g DATAPATH discarded for one UE (no matching "+
				"PDR, QER policing). Shaper loss is reported separately by "+
				"upf_ue_dropped_packets_total")
		for _, a := range addrs {
			s := ue[a]
			out.val("upf_ue_datapath_dropped_packets_total",
				fmt.Sprintf("ue=%q,direction=\"UL\"", a), s.ULDrops)
			out.val("upf_ue_datapath_dropped_packets_total",
				fmt.Sprintf("ue=%q,direction=\"DL\"", a), s.DLDrops)
		}
	}

	// ---- per-UE shaper counters: the REAL per-UE loss ------------------
	// Forwarded and dropped are both measured in the UE's own tc class, at
	// the same point in the path, so their ratio is a true loss rate.
	if len(e.ueLoss) > 0 {
		var all []load.UELoss
		tracked := 0
		for _, src := range e.ueLoss {
			tracked += src.TrackedUEs()
			l, err := src.Losses()
			if err != nil {
				e.log.Warnf("per-UE loss read: %v", err)
				continue
			}
			all = append(all, l...)
		}
		out.meta("upf_per_ue_queues", "gauge",
			"1 when each UE has its own shaper class, so packet loss can be "+
				"attributed to the UE that suffered it")
		out.val("upf_per_ue_queues", "", b2i(len(all) > 0 || tracked > 0))

		if len(all) > 0 {
			sort.Slice(all, func(i, j int) bool {
				if all[i].Addr != all[j].Addr {
					return all[i].Addr < all[j].Addr
				}
				return all[i].Direction < all[j].Direction
			})
			out.meta("upf_ue_forwarded_bytes_total", "counter",
				"Bytes DELIVERED for one UE through its own shaper class; "+
					"use rate()*8 for that UE's throughput in bit/s")
			for _, l := range all {
				out.val("upf_ue_forwarded_bytes_total",
					fmt.Sprintf("ue=%q,direction=%q", l.Addr, l.Direction),
					l.ForwardedBytes)
			}
			out.meta("upf_ue_forwarded_packets_total", "counter",
				"Packets DELIVERED for one UE through its own shaper class. "+
					"Kept alongside the byte counter because loss is a "+
					"packet ratio")
			for _, l := range all {
				out.val("upf_ue_forwarded_packets_total",
					fmt.Sprintf("ue=%q,direction=%q", l.Addr, l.Direction),
					l.Forwarded)
			}
			out.meta("upf_ue_dropped_packets_total", "counter",
				"Packets the egress shaper dropped for one UE because that "+
					"UE's queue was full: real per-UE packet loss")
			for _, l := range all {
				out.val("upf_ue_dropped_packets_total",
					fmt.Sprintf("ue=%q,direction=%q", l.Addr, l.Direction),
					l.Dropped)
			}
			out.meta("upf_ue_buffer_bytes", "gauge",
				"Bytes queued in one UE's own egress queue")
			for _, l := range all {
				out.val("upf_ue_buffer_bytes",
					fmt.Sprintf("ue=%q,direction=%q", l.Addr, l.Direction),
					l.BacklogB)
			}
			out.meta("upf_ue_buffer_max_bytes", "gauge",
				"Capacity of one UE's own egress queue")
			for _, l := range all {
				out.val("upf_ue_buffer_max_bytes",
					fmt.Sprintf("ue=%q,direction=%q", l.Addr, l.Direction),
					l.LimitB)
			}
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if _, err := w.Write([]byte(out.b.String())); err != nil {
		e.log.Warnf("metrics write: %v", err)
	}
}

func (e *Exporter) Serve(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	e.log.Infof("prometheus exporter listening at %s/metrics", addr)
	if err := e.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (e *Exporter) Shutdown(ctx context.Context) error { return e.srv.Shutdown(ctx) }
