package pfcp

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wmnsk/go-pfcp/ie"
	"github.com/wmnsk/go-pfcp/message"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/pkg/factory"
)

// newLCITestServer returns a PFCP server bound to a loopback socket and a
// socket standing in for the SMF.
func newLCITestServer(t *testing.T) (*PfcpServer, *net.UDPConn) {
	t.Helper()
	cfg := &factory.Config{Pfcp: &factory.Pfcp{
		Addr:           "127.0.0.1",
		NodeID:         "127.0.0.1",
		RetransTimeout: time.Hour, // no retransmission during a test
	}}
	s := NewPfcpServer(cfg, forwarder.Empty{})
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	s.conn = conn
	smf, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	t.Cleanup(func() {
		s.stopTrTimers()
		conn.Close()
		smf.Close()
	})
	return s, smf
}

func recvMsg(t *testing.T, conn *net.UDPConn) message.Message {
	t.Helper()
	buf := make([]byte, MAX_PFCP_MSG_LEN)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(2*time.Second)))
	n, _, err := conn.ReadFrom(buf)
	require.NoError(t, err)
	msg, err := message.Parse(buf[:n])
	require.NoError(t, err)
	return msg
}

// lciValues decodes an LCI the way the SMF does (lci.SequenceNumber(),
// lci.Metric() on the grouped IE).
func lciValues(t *testing.T, lci *ie.IE) (uint32, uint8) {
	t.Helper()
	require.NotNil(t, lci, "Load Control Information missing")
	seq, err := lci.SequenceNumber()
	require.NoError(t, err)
	metric, err := lci.Metric()
	require.NoError(t, err)
	return seq, metric
}

func fixedMetric(v uint8, ok bool) LoadMetricSource {
	return func() (uint8, bool) { return v, ok }
}

func TestAssociationSetupRecordsLOAD(t *testing.T) {
	for _, tc := range []struct {
		name     string
		features *ie.IE
		want     bool
	}{
		{"LOAD advertised", ie.NewCPFunctionFeatures(0x01), true},
		{"other features only", ie.NewCPFunctionFeatures(0x02), false},
		{"no CP Function Features", nil, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, smf := newLCITestServer(t)
			smfAddr := smf.LocalAddr()
			ies := []*ie.IE{
				ie.NewNodeID("10.100.50.244", "", ""),
				ie.NewRecoveryTimeStamp(time.Now()),
			}
			if tc.features != nil {
				ies = append(ies, tc.features)
			}
			req := message.NewAssociationSetupRequest(7, ies...)
			s.rxTrans[smfAddr.String()+"-7"] = NewRxTransaction(s, smfAddr, 7)

			s.handleAssociationSetupRequest(req, smfAddr)

			node, ok := s.rnodes["10.100.50.244"]
			require.True(t, ok)
			assert.Equal(t, tc.want, node.loadControl)
			_, isRsp := recvMsg(t, smf).(*message.AssociationSetupResponse)
			assert.True(t, isRsp)
		})
	}
}

func TestLoadControlIE(t *testing.T) {
	s := &PfcpServer{}
	loadPeer := &RemoteNode{loadControl: true}
	plainPeer := &RemoteNode{}

	assert.Nil(t, s.loadControlIE(loadPeer), "no metric source")

	s.SetLoadMetricSource(fixedMetric(40, true))
	assert.Nil(t, s.loadControlIE(plainPeer), "peer did not advertise LOAD")
	assert.Nil(t, s.loadControlIE(nil))

	// A steady metric still gets a new sequence number every time.
	seq1, m1 := lciValues(t, s.loadControlIE(loadPeer))
	seq2, m2 := lciValues(t, s.loadControlIE(loadPeer))
	assert.Equal(t, uint8(40), m1)
	assert.Equal(t, uint8(40), m2)
	assert.Greater(t, seq2, seq1)

	s.SetLoadMetricSource(fixedMetric(40, false))
	assert.Nil(t, s.loadControlIE(loadPeer), "unhealthy metric")

	s.SetLoadMetricSource(fixedMetric(150, true))
	seq3, m3 := lciValues(t, s.loadControlIE(loadPeer))
	assert.Equal(t, uint8(100), m3, "clamped to 100")
	assert.Greater(t, seq3, seq2, "skipped LCIs do not consume a number")
	assert.Equal(t, seq2+1, seq3)
}

func TestSessionReportRequestCarriesLCI(t *testing.T) {
	s, smf := newLCITestServer(t)
	s.SetLoadMetricSource(fixedMetric(73, true))
	rnode := s.NewNode("10.100.50.244", smf.LocalAddr(), forwarder.Empty{})
	rnode.loadControl = true
	sess := rnode.NewSess(0x10)

	require.NoError(t, s.serveDLDReport(smf.LocalAddr(), sess.LocalID, 1))
	req, ok := recvMsg(t, smf).(*message.SessionReportRequest)
	require.True(t, ok)
	seq1, metric := lciValues(t, req.LoadControlInformation)
	assert.Equal(t, uint8(73), metric)

	require.NoError(t, s.serveUSAReport(smf.LocalAddr(), sess.LocalID, nil))
	req, ok = recvMsg(t, smf).(*message.SessionReportRequest)
	require.True(t, ok)
	seq2, _ := lciValues(t, req.LoadControlInformation)
	assert.Greater(t, seq2, seq1)
}

func TestSessionResponsesCarryLCI(t *testing.T) {
	setup := func(t *testing.T, loadControl bool) (*PfcpServer, *net.UDPConn, *Sess) {
		s, smf := newLCITestServer(t)
		s.SetLoadMetricSource(fixedMetric(55, true))
		rnode := s.NewNode("10.100.50.244", smf.LocalAddr(), forwarder.Empty{})
		rnode.loadControl = loadControl
		s.rnodes[rnode.ID] = rnode
		return s, smf, rnode.NewSess(0x20)
	}

	t.Run("modification", func(t *testing.T) {
		s, smf, sess := setup(t, true)
		req := message.NewSessionModificationRequest(0, 0, sess.LocalID, 11, 0)
		s.rxTrans[smf.LocalAddr().String()+"-11"] = NewRxTransaction(s, smf.LocalAddr(), 11)
		s.handleSessionModificationRequest(req, smf.LocalAddr())
		rsp, ok := recvMsg(t, smf).(*message.SessionModificationResponse)
		require.True(t, ok)
		_, metric := lciValues(t, rsp.LoadControlInformation)
		assert.Equal(t, uint8(55), metric)
	})

	t.Run("deletion", func(t *testing.T) {
		s, smf, sess := setup(t, true)
		req := message.NewSessionDeletionRequest(0, 0, sess.LocalID, 12, 0)
		s.rxTrans[smf.LocalAddr().String()+"-12"] = NewRxTransaction(s, smf.LocalAddr(), 12)
		s.handleSessionDeletionRequest(req, smf.LocalAddr())
		rsp, ok := recvMsg(t, smf).(*message.SessionDeletionResponse)
		require.True(t, ok)
		_, metric := lciValues(t, rsp.LoadControlInformation)
		assert.Equal(t, uint8(55), metric)
	})

	t.Run("establishment", func(t *testing.T) {
		s, smf, _ := setup(t, true)
		req := message.NewSessionEstablishmentRequest(0, 0, 0, 13, 0,
			ie.NewNodeID("10.100.50.244", "", ""),
			ie.NewFSEID(0x30, net.ParseIP("10.100.50.244"), nil),
		)
		s.rxTrans[smf.LocalAddr().String()+"-13"] = NewRxTransaction(s, smf.LocalAddr(), 13)
		s.handleSessionEstablishmentRequest(req, smf.LocalAddr())
		rsp, ok := recvMsg(t, smf).(*message.SessionEstablishmentResponse)
		require.True(t, ok)
		cause, err := rsp.Cause.Cause()
		require.NoError(t, err)
		require.Equal(t, ie.CauseRequestAccepted, cause)
		_, metric := lciValues(t, rsp.LoadControlInformation)
		assert.Equal(t, uint8(55), metric)
	})

	t.Run("peer without LOAD gets none", func(t *testing.T) {
		s, smf, sess := setup(t, false)
		req := message.NewSessionDeletionRequest(0, 0, sess.LocalID, 14, 0)
		s.rxTrans[smf.LocalAddr().String()+"-14"] = NewRxTransaction(s, smf.LocalAddr(), 14)
		s.handleSessionDeletionRequest(req, smf.LocalAddr())
		rsp, ok := recvMsg(t, smf).(*message.SessionDeletionResponse)
		require.True(t, ok)
		assert.Nil(t, rsp.LoadControlInformation)
	})
}
