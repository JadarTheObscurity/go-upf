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
	Load        *LoadConfig `yaml:"load"       valid:"optional"`
}

type Pfcp struct {
	Addr           string        `yaml:"addr"           valid:"required,host"`
	NodeID         string        `yaml:"nodeID"         valid:"required,host"`
	RetransTimeout time.Duration `yaml:"retransTimeout" valid:"required"`
	MaxRetrans     uint8         `yaml:"maxRetrans"     valid:"optional"`
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
