package pfcp

import (
	"github.com/wmnsk/go-pfcp/ie"
)

// LoadMetricSource returns the UP function's current load metric (0..100) and
// whether it is valid. A false ok means the measurement is not working, and no
// Load Control Information is sent rather than a misleading value.
type LoadMetricSource func() (metric uint8, ok bool)

// SetLoadMetricSource enables PFCP Load Control (TS 29.244 §6.2.3): Load
// Control Information is then attached to the Session Establishment,
// Modification and Deletion Responses and to Session Report Requests sent to
// CP functions that advertised LOAD. Call it before Start; the PFCP goroutine
// reads it without locking.
func (s *PfcpServer) SetLoadMetricSource(src LoadMetricSource) {
	s.loadMetric = src
}

// loadControlIE returns the Load Control Information to attach to a message
// for rnode, or nil when none should be sent: load control is not enabled, the
// peer did not advertise LOAD in its CP Function Features, or the metric is
// not valid.
//
// The Sequence Number is incremented for every LCI sent, not only when the
// metric changes. The SMF ignores an LCI whose sequence number is not higher
// than the stored one, so repeating a number would also stop it from seeing
// that a steady metric is still current. One counter serves all peers, which
// keeps it increasing towards each of them. The SMF drops its stored LCI when
// the association is set up again, so restarting the counter at 1 after a UPF
// restart is safe.
//
// Only the PFCP goroutine calls this, so lciSeq needs no lock.
func (s *PfcpServer) loadControlIE(rnode *RemoteNode) *ie.IE {
	if s.loadMetric == nil || rnode == nil || !rnode.loadControl {
		return nil
	}
	metric, ok := s.loadMetric()
	if !ok {
		return nil
	}
	if metric > 100 {
		metric = 100
	}
	s.lciSeq++
	return ie.NewLoadControlInformation(
		ie.NewSequenceNumber(s.lciSeq),
		ie.NewMetric(metric),
	)
}
