package factory

import (
	"time"

	"github.com/davecgh/go-spew/spew"

	"github.com/free5gc/go-upf/internal/logger"
)

const (
	UpfDefaultConfigPath = "./config/upfcfg.yaml"
	UpfDefaultIPv4       = "127.0.0.8"
	UpfPfcpDefaultPort   = 8805
	UpfGtpDefaultPort    = 2152
)

type Config struct {
	Version     string      `yaml:"version"     valid:"required,in(1.0.3)"`
	Description string      `yaml:"description" valid:"optional"`
	Pfcp        *Pfcp       `yaml:"pfcp"        valid:"required"`
	Gtpu        *Gtpu       `yaml:"gtpu"        valid:"required"`
	DnnList     []DnnList   `yaml:"dnnList"     valid:"required"`
	Logger      *Logger     `yaml:"logger"      valid:"required"`
	EES         *EESConfig  `yaml:"ees"        valid:"optional"`
	Load        *LoadConfig `yaml:"load"       valid:"optional"`
}

type Pfcp struct {
	Addr           string        `yaml:"addr"           valid:"required,host"`
	NodeID         string        `yaml:"nodeID"         valid:"required,host"`
	RetransTimeout time.Duration `yaml:"retransTimeout" valid:"required"`
	MaxRetrans     uint8         `yaml:"maxRetrans"     valid:"optional"`
	// StrictFTEIDAllocation rejects a new PDR whose Local F-TEID the SMF allocated (TS 29.244 clause 5.5.1).
	// It is off while free5GC's SMF allocates the F-TEIDs itself.
	StrictFTEIDAllocation bool `yaml:"strictFTEIDAllocation" valid:"optional"`
}

type Gtpu struct {
	Forwarder string   `yaml:"forwarder" valid:"required,in(gtp5g)"`
	IfList    []IfInfo `yaml:"ifList"    valid:"optional"`
}

type IfInfo struct {
	Addr   string `yaml:"addr"   valid:"required,host"`
	Type   string `yaml:"type"   valid:"required,in(N3|N9)"`
	Name   string `yaml:"name"   valid:"optional"`
	IfName string `yaml:"ifname" valid:"optional"`
	MTU    uint32 `yaml:"mtu"    valid:"optional"`
}

type DnnList struct {
	Dnn             string `yaml:"dnn"             valid:"required"`
	Cidr            string `yaml:"cidr"            valid:"required,cidr"`
	NatIfName       string `yaml:"natifname"       valid:"optional"`
	NatIfCIDR       string `yaml:"natIfCIDR"       valid:"optional,cidr"`
	IPForwardEnable bool   `yaml:"ipForwardEnable" valid:"optional"`
	TCPMss          uint16 `yaml:"tcpMss"          valid:"optional"`
}

type Logger struct {
	Enable       bool   `yaml:"enable"       valid:"optional"`
	Level        string `yaml:"level"        valid:"required,in(trace|debug|info|warn|error|fatal|panic)"`
	ReportCaller bool   `yaml:"reportCaller" valid:"optional"`
}

// EESConfig enables the embedded Nupf_EventExposure service. It is disabled by
// default and supports only the free5GC single-UPF scenario; keep it disabled
// in ULCL deployments.
type EESConfig struct {
	Enabled bool   `yaml:"enabled" valid:"optional"`
	IP      string `yaml:"ip"      valid:"optional"` // empty listens on all interfaces
	Port    int    `yaml:"port"    valid:"optional"` // 0 uses 8088
}

// LoadConfig controls the egress load metric (0..100) that is carried in PFCP
// Load Control Information (TS 29.244 8.2.54) to CP functions that advertise
// LOAD (internal/pfcp/load_control.go).
//
// Per direction the metric is floor(buffer bytes / max buffer bytes * 100),
// time averaged, and the reported value is max(UL, DL). That requires a
// BYTE-limited queue in each direction: a pod's veth is "noqueue" by default
// and has no buffer at all, so the UPF installs bounded qdiscs and names them
// here.
type LoadConfig struct {
	Enabled bool `yaml:"enabled" valid:"optional"`
	// IfName is the interface carrying the egress buffer.
	IfName string `yaml:"ifname" valid:"optional"`
	// QdiscKind is the queue to measure. It must report a byte limit, so
	// "bfifo"; pfifo's limit is in packets and yields no byte ratio.
	QdiscKind string `yaml:"qdiscKind" valid:"optional"`
	// SampleIntervalMs is how often the buffer is read.
	SampleIntervalMs int `yaml:"sampleIntervalMs" valid:"optional"`
	// AverageWindowMs is the averaging time constant. Expressed in time, not
	// in samples, so changing the sample rate does not change the smoothing.
	AverageWindowMs int `yaml:"averageWindowMs" valid:"optional"`
	// APIAddr is the TEMPORARY internal verification endpoint, "ip:port".
	// Empty disables it. Remove once the PFCP IE carries the metric.
	APIAddr string `yaml:"apiAddr" valid:"optional"`

	// SetupEgress makes the UPF build the egress buffer itself after the
	// gtp5g link exists. This cannot be done by a startup script, because the
	// buffer must sit on the pre-NAT user-plane path and the only interface
	// carrying it (upfgtp) is created by the UPF process.
	SetupEgress bool `yaml:"setupEgress" valid:"optional"`
	// EgressSourceIf is the interface whose ingress is redirected into the
	// buffer; empty means the gtp5g link, which is always "upfgtp" in this
	// version.
	EgressSourceIf string `yaml:"egressSourceIf" valid:"optional"`
	// EgressRate is the bottleneck in tc syntax, e.g. "500kbit". Required
	// when SetupEgress is set: with no bottleneck the buffer never fills.
	EgressRate string `yaml:"egressRate" valid:"optional"`
	// EgressBufferBytes is the uplink buffer capacity, the UL denominator.
	EgressBufferBytes uint32 `yaml:"egressBufferBytes" valid:"optional"`

	// DLEgressRate is the downlink bottleneck, in tc syntax. Empty disables
	// downlink measurement and the metric becomes uplink-only.
	//
	// Downlink is measured on the gtp5g link's EGRESS -- decapsulated user
	// packets on their way to the gNB -- using the same equation as uplink.
	// The reported Load Control Information value is the MAX of the two.
	DLEgressRate string `yaml:"dlEgressRate" valid:"optional"`
	// DLEgressBufferBytes is the downlink buffer capacity, the DL denominator.
	DLEgressBufferBytes uint32 `yaml:"dlEgressBufferBytes" valid:"optional"`

	// MetricsAddr serves Prometheus metrics at <addr>/metrics. Empty disables
	// the exporter. The chart's PodMonitor scrapes a container port named
	// "metrics", so this normally binds 0.0.0.0 on that port.
	MetricsAddr string `yaml:"metricsAddr" valid:"optional"`
	// PerUEMetrics exports per-UE counters read from /proc/gtp5g/pdr. That
	// walk is far more expensive than a qdisc dump, so it is opt-in and
	// cached; see PerUECacheMs.
	PerUEMetrics bool `yaml:"perUeMetrics" valid:"optional"`
	// PerUECacheMs is how long a per-UE scan is reused. 0 uses 2000 ms.
	PerUECacheMs int `yaml:"perUeCacheMs" valid:"optional"`
	// PerUEMaxSessions bounds the SEID space the per-UE scan walks. The
	// procfs interface cannot enumerate rules, so the scan probes a range.
	PerUEMaxSessions int `yaml:"perUeMaxSessions" valid:"optional"`

	// PerUEQueues gives every UE its own shaper class, so PACKET LOSS can be
	// attributed to the UE that suffered it.
	//
	// Without this the egress buffer is one shared queue: its drop counter is
	// an aggregate, and gtp5g's per-PDR drop counters stay at zero because
	// they count datapath discards, not shaper drops -- the per-PDR
	// "forwarded" count is taken BEFORE the shaper. Measured on a loaded UPF:
	// 38,786 aggregate drops with every per-PDR ul_drops still 0x0.
	//
	// It also makes per-UE forwarding roughly fair under equal load, where a
	// single shared FIFO is drop-tail unfair.
	PerUEQueues bool `yaml:"perUeQueues" valid:"optional"`
	// PerUEQueueMax bounds how many per-UE classes are created. A UE beyond
	// this falls into the default class and is not measured separately.
	PerUEQueueMax int `yaml:"perUeQueueMax" valid:"optional"`
}

func (c *Config) GetVersion() string {
	return c.Version
}

func (c *Config) Print() {
	spew.Config.Indent = "\t"
	str := spew.Sdump(c)
	logger.CfgLog.Infof("==================================================")
	logger.CfgLog.Infof("%s", str)
	logger.CfgLog.Infof("==================================================")
}
