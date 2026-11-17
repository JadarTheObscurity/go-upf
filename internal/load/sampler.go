// sampler.go: the goroutine that polls the egress buffer, and the temporary
// internal HTTP endpoint used to verify the metric.
package load

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
)

// Sampler periodically reads the egress buffer and updates the Tracker.
type Sampler struct {
	reader   *QdiscReader
	tracker  *Tracker
	ifname   string
	kind     string
	dir      Direction
	interval time.Duration
	log      *logrus.Entry

	// The interface index is resolved lazily and re-resolved on failure: the
	// egress device may be created slightly after the UPF starts, and the
	// metric must not be permanently dead if it was not there at t=0.
	mu      sync.Mutex
	ifindex int
}

// NewSampler builds a sampler for one direction's buffer. ifname is the device
// carrying that buffer: the ifb device for uplink, the gtp5g link for downlink.
func NewSampler(tracker *Tracker, ifname, kind string, dir Direction,
	interval time.Duration, log *logrus.Entry,
) (*Sampler, error) {
	reader, err := NewQdiscReader()
	if err != nil {
		return nil, err
	}
	return &Sampler{
		reader: reader, tracker: tracker, ifname: ifname,
		kind: kind, dir: dir, interval: interval, log: log,
	}, nil
}

// Run samples until ctx is cancelled.
func (s *Sampler) Run(ctx context.Context, wg *sync.WaitGroup) {
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer s.reader.Close()
		ticker := time.NewTicker(s.interval)
		defer ticker.Stop()
		s.sampleOnce() // take one immediately so the metric is live at startup
		for {
			select {
			case <-ctx.Done():
				s.log.Infof("%s load metric sampler stopped", s.dir)
				return
			case <-ticker.C:
				s.sampleOnce()
			}
		}
	}()
}

func (s *Sampler) sampleOnce() {
	idx, err := s.resolveIfindex()
	if err != nil {
		s.tracker.ObserveError(err)
		return
	}
	q, err := s.reader.FindByKind(idx, s.kind)
	if err != nil {
		// The device may have been recreated with a new index; force a
		// re-resolve on the next tick rather than failing forever.
		s.mu.Lock()
		s.ifindex = 0
		s.mu.Unlock()
		s.tracker.ObserveError(err)
		return
	}
	if q.LimitB == 0 {
		s.tracker.ObserveError(fmt.Errorf(
			"%s qdisc on %s reports no byte limit; the egress buffer must be "+
				"a byte-limited qdisc (bfifo) for a buffer-ratio metric",
			s.kind, s.ifname))
		return
	}
	s.tracker.Observe(q.BacklogB, q.LimitB, q.BacklogPkt, q.Drops)
}

func (s *Sampler) resolveIfindex() (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ifindex != 0 {
		return s.ifindex, nil
	}
	iface, err := net.InterfaceByName(s.ifname)
	if err != nil {
		return 0, fmt.Errorf("egress interface %q not found: %w", s.ifname, err)
	}
	s.ifindex = iface.Index
	s.log.Infof("%s load metric: buffer on %s (ifindex %d), qdisc kind %q",
		s.dir, s.ifname, iface.Index, s.kind)
	return s.ifindex, nil
}

// ---------------------------------------------------------------------------
// Temporary internal API
//
// TEMPORARY AND INTERNAL. This exists to verify the metric before it is
// carried in PFCP Load Control Information (TS 29.244 8.2.54), which is the
// real consumer. It is not a standardised interface, it is unauthenticated,
// and it should bind to a loopback or pod-internal address only. Remove it
// once the PFCP IE is in place.
// ---------------------------------------------------------------------------

// APIServer serves the metric over HTTP for inspection.
type APIServer struct {
	combiner *Combiner
	srv      *http.Server
	log      *logrus.Entry
}

func NewAPIServer(combiner *Combiner, log *logrus.Entry) *APIServer {
	a := &APIServer{combiner: combiner, log: log}
	mux := http.NewServeMux()
	// Versioned under an explicitly internal path so it cannot be mistaken
	// for a 3GPP service-based interface.
	mux.HandleFunc("/internal/v1/load-metric", a.handleGet)
	a.srv = &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	return a
}

func (a *APIServer) handleGet(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "only GET", http.StatusMethodNotAllowed)
		return
	}
	m := a.combiner.LCI()
	w.Header().Set("Content-Type", "application/json")
	// 503 when a sampler cannot read its buffer: a monitoring caller must be
	// able to tell a real 0% from a broken measurement without parsing a body.
	if !m.Healthy {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	if err := json.NewEncoder(w).Encode(m); err != nil {
		a.log.Warnf("load metric encode: %v", err)
	}
}

func (a *APIServer) Serve(addr string) error {
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp", addr)
	if err != nil {
		return err
	}
	a.log.Infof("load metric internal API listening at %s/internal/v1/load-metric", addr)
	if err := a.srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (a *APIServer) Shutdown(ctx context.Context) error {
	return a.srv.Shutdown(ctx)
}
