package metrics

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/load"
)

func testLog() *logrus.Entry {
	l := logrus.New()
	l.SetOutput(nopWriter{})
	return l.WithField("t", "test")
}

type nopWriter struct{}

func (nopWriter) Write(p []byte) (int, error) { return len(p), nil }

type fakeQdisc struct {
	ul, dl load.QdiscStats
	err    error
}

func (f fakeQdisc) DirectionStats(d load.Direction) (load.QdiscStats, error) {
	if f.err != nil {
		return load.QdiscStats{}, f.err
	}
	if d == load.DirDownlink {
		return f.dl, nil
	}
	return f.ul, nil
}

// sample is one parsed exposition line.
type sample struct {
	name   string
	labels string
	value  float64
}

var reLine = regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)(?:\{([^}]*)\})?\s+(\S+)$`)

// parseExposition parses the text format back, and fails on anything that
// would make Prometheus reject a scrape. This is what makes the hand-written
// format safe: a malformed line is a test failure, not a silent scrape error.
func parseExposition(t *testing.T, body string) []sample {
	t.Helper()
	var out []sample
	declaredType := map[string]bool{}
	for i, line := range strings.Split(strings.TrimRight(body, "\n"), "\n") {
		if line == "" {
			t.Fatalf("line %d: blank line in exposition output", i+1)
		}
		if strings.HasPrefix(line, "#") {
			f := strings.Fields(line)
			if len(f) < 3 || (f[1] != "HELP" && f[1] != "TYPE") {
				t.Fatalf("line %d: malformed comment %q", i+1, line)
			}
			if f[1] == "TYPE" {
				declaredType[f[2]] = true
			}
			continue
		}
		m := reLine.FindStringSubmatch(line)
		if m == nil {
			t.Fatalf("line %d: unparseable sample %q", i+1, line)
		}
		v, err := strconv.ParseFloat(m[3], 64)
		if err != nil {
			t.Fatalf("line %d: value %q is not a number", i+1, m[3])
		}
		if !declaredType[m[1]] {
			t.Errorf("metric %q has samples but no # TYPE declaration", m[1])
		}
		out = append(out, sample{m[1], m[2], v})
	}
	return out
}

func find(ss []sample, name, labels string) (float64, bool) {
	for _, s := range ss {
		if s.name == name && s.labels == labels {
			return s.value, true
		}
	}
	return 0, false
}

func scrape(t *testing.T, e *Exporter) []sample {
	t.Helper()
	rec := httptest.NewRecorder()
	e.handle(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("scrape returned %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("content type = %q, want text/plain", ct)
	}
	return parseExposition(t, rec.Body.String())
}

func busyTracker(pct int, q load.QdiscStats) *load.Tracker {
	tr := load.NewTracker(time.Second, 0, "test")
	q.BacklogB = uint32(pct * 655)
	q.LimitB = 65500
	tr.ObserveQdisc(q)
	return tr
}

// The whole output must be valid exposition format, and the load metric must
// be the max of the two directions, as the IE requires.
func TestExportsValidFormatAndMaxMetric(t *testing.T) {
	ul := busyTracker(20, load.QdiscStats{SentBytes: 1000, SentPkts: 10, Drops: 1})
	dl := busyTracker(80, load.QdiscStats{SentBytes: 2000, SentPkts: 20, Drops: 2})
	c := load.NewCombiner(ul, dl)
	e := NewExporter(c, c, nil, time.Second, testLog())

	ss := scrape(t, e)

	if v, ok := find(ss, "upf_load_metric", ""); !ok || v != 80 {
		t.Errorf("upf_load_metric = %v (found=%v), want 80 (the DL value)", v, ok)
	}
	if v, _ := find(ss, "upf_direction_load_metric", `direction="UL"`); v != 20 {
		t.Errorf("UL metric = %v, want 20", v)
	}
	if v, _ := find(ss, "upf_direction_load_metric", `direction="DL"`); v != 80 {
		t.Errorf("DL metric = %v, want 80", v)
	}
	// The dominant direction must be flagged on DL, not UL.
	if v, _ := find(ss, "upf_load_metric_dominant", `direction="DL"`); v != 1 {
		t.Error("DL should be flagged dominant")
	}
	if v, _ := find(ss, "upf_load_metric_dominant", `direction="UL"`); v != 0 {
		t.Error("UL should not be flagged dominant")
	}
	// Counters must carry the cumulative qdisc totals, per direction.
	if v, _ := find(ss, "upf_tx_bytes_total", `direction="UL"`); v != 1000 {
		t.Errorf("UL tx bytes = %v, want 1000", v)
	}
	if v, _ := find(ss, "upf_dropped_packets_total", `direction="DL"`); v != 2 {
		t.Errorf("DL drops = %v, want 2", v)
	}
}

// With downlink disabled, nothing downlink-labelled may be exported -- a DL
// series stuck at 0 would read as an idle downlink rather than an absent one.
func TestNoDownlinkSeriesWhenDisabled(t *testing.T) {
	ul := busyTracker(30, load.QdiscStats{})
	c := load.NewCombiner(ul, nil)
	e := NewExporter(c, c, nil, time.Second, testLog())
	for _, s := range scrape(t, e) {
		if strings.Contains(s.labels, `direction="DL"`) &&
			s.name != "upf_load_metric_dominant" {
			t.Errorf("exported %s{%s} though downlink is disabled", s.name, s.labels)
		}
	}
}

// An unhealthy metric must be visible as such in the scrape: a consumer has to
// be able to tell a real 0 from a broken measurement.
func TestHealthIsExported(t *testing.T) {
	ul := busyTracker(10, load.QdiscStats{})
	dl := busyTracker(10, load.QdiscStats{})
	dl.ObserveError(errors.New("qdisc vanished"))
	c := load.NewCombiner(ul, dl)
	e := NewExporter(c, c, nil, time.Second, testLog())
	if v, _ := find(scrape(t, e), "upf_load_metric_healthy", ""); v != 0 {
		t.Error("upf_load_metric_healthy should be 0 when a direction failed")
	}
}

// A qdisc read failure must not break the scrape: the load gauges are still
// worth serving.
func TestScrapeSurvivesQdiscError(t *testing.T) {
	ul := busyTracker(40, load.QdiscStats{})
	c := load.NewCombiner(ul, nil)
	e := NewExporter(c, fakeQdisc{err: errors.New("netlink down")}, nil,
		time.Second, testLog())
	ss := scrape(t, e)
	if v, _ := find(ss, "upf_direction_load_metric", `direction="UL"`); v != 40 {
		t.Error("load gauges should survive a qdisc read failure")
	}
	if _, ok := find(ss, "upf_tx_bytes_total", `direction="UL"`); ok {
		t.Error("tx counter exported despite the qdisc read failing")
	}
}

// Without the procfs interface the exporter must say so rather than implying
// there are no UEs.
func TestPerUEUnavailableIsFlagged(t *testing.T) {
	ul := busyTracker(5, load.QdiscStats{})
	c := load.NewCombiner(ul, nil)
	e := NewExporter(c, c, nil, time.Second, testLog())
	ss := scrape(t, e)
	if v, ok := find(ss, "upf_per_ue_metrics_available", ""); !ok || v != 0 {
		t.Errorf("per-UE availability = %v (found=%v), want 0", v, ok)
	}
	if _, ok := find(ss, "upf_ue_sessions", ""); ok {
		t.Error("upf_ue_sessions exported with no per-UE source")
	}
}

// Only GET is a scrape.
func TestRejectsNonGet(t *testing.T) {
	ul := busyTracker(0, load.QdiscStats{})
	c := load.NewCombiner(ul, nil)
	e := NewExporter(c, c, nil, time.Second, testLog())
	rec := httptest.NewRecorder()
	e.handle(rec, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST returned %d, want 405", rec.Code)
	}
}
