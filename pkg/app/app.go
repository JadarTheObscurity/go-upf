package app

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/ees"
	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/load"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/metrics"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

type UpfApp struct {
	ctx        context.Context
	wg         sync.WaitGroup
	cfg        *factory.Config
	driver     forwarder.Driver
	pfcpServer *pfcp.PfcpServer
	eesServer  *ees.Server

	loadMetrics *load.Combiner
	loadAPI     *load.APIServer
	promExport  *metrics.Exporter
	loadEgress  *load.EgressBufferSpec
	// ueTrackers keep one shaper class per UE per direction, so each UE's
	// packet loss lands in a counter of its own.
	ueTrackers []*load.UETracker
}

// LoadMetric exposes the node-level load metric (0..100) for PFCP Load
// Control Information: max(uplink, downlink). The boolean is false when the
// metric is disabled or any enabled direction is not measuring -- do NOT send
// Load Control Information in that case.
func (u *UpfApp) LoadMetric() (uint8, bool) {
	if u.loadMetrics == nil {
		return 0, false
	}
	m := u.loadMetrics.LCI()
	return m.Value, m.Healthy
}

// LoadMetricDetail exposes both directions, for diagnostics.
func (u *UpfApp) LoadMetricDetail() (load.LCI, bool) {
	if u.loadMetrics == nil {
		return load.LCI{}, false
	}
	return u.loadMetrics.LCI(), true
}

func NewApp(cfg *factory.Config) (*UpfApp, error) {
	upf := &UpfApp{
		cfg: cfg,
	}
	upf.SetLogLevel(cfg.Logger.Level)
	upf.SetLogReportCaller(cfg.Logger.ReportCaller)
	return upf, nil
}

func (u *UpfApp) Config() *factory.Config {
	return u.cfg
}

func (a *UpfApp) SetLogLevel(level string) {
	lvl, err := logrus.ParseLevel(level)
	if err != nil {
		logger.MainLog.Warnf("Log level [%s] is invalid", level)
		return
	}

	logger.MainLog.Infof("Log level is set to [%s]", level)
	if lvl == logger.Log.GetLevel() {
		return
	}

	logger.Log.SetLevel(lvl)
}

func (a *UpfApp) SetLogReportCaller(reportCaller bool) {
	logger.MainLog.Infof("Report Caller is set to [%v]", reportCaller)
	if reportCaller == logger.Log.ReportCaller {
		return
	}

	logger.Log.SetReportCaller(reportCaller)
}

func (u *UpfApp) Run() error {
	var cancel context.CancelFunc
	u.ctx, cancel = context.WithCancel(context.Background())
	defer cancel()

	u.wg.Add(1)
	/* Go Routine is spawned here for listening for cancellation event on
	 * context */
	go u.listenShutdownEvent()

	var err error
	u.driver, err = forwarder.NewDriver(&u.wg, u.cfg)
	if err != nil {
		return err
	}

	// The load metric must be available as soon as the pod is up, so it is
	// started here, before the UPF reports itself started. A failure to set it
	// up is logged, not fatal: it is telemetry, and the forwarding plane is
	// already serving traffic by this point. It runs after the forwarder,
	// which creates upfgtp, and before the PFCP server starts, so the PFCP
	// goroutine sees the tracker without further synchronization.
	if err := u.initLoadMetric(); err != nil {
		logger.MainLog.Errorf("load metric disabled: %v", err)
	}

	u.pfcpServer = pfcp.NewPfcpServer(u.cfg, u.driver)
	if u.loadMetrics != nil {
		// Carry the metric in PFCP Load Control Information.
		u.pfcpServer.SetLoadMetricSource(u.LoadMetric)
	}
	u.driver.HandleReport(u.pfcpServer)
	u.pfcpServer.Start(&u.wg)

	// EES is optional; when disabled nothing below touches the PFCP path.
	if err := u.initEES(); err != nil {
		return err
	}

	logger.MainLog.Infoln("UPF started")

	// Wait for interrupt signal to gracefully shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	// Receive the interrupt signal
	logger.MainLog.Infof("Shutdown UPF ...")
	// Notify each goroutine and wait them stopped
	cancel()
	u.WaitRoutineStopped()
	logger.MainLog.Infof("UPF exited")
	return nil
}

func (u *UpfApp) listenShutdownEvent() {
	defer func() {
		if p := recover(); p != nil {
			// Print stack for panic to log. Fatalf() will let program exit.
			logger.MainLog.Fatalf("panic: %v\n%s", p, string(debug.Stack()))
		}

		u.wg.Done()
	}()

	<-u.ctx.Done()
	if u.pfcpServer != nil {
		u.pfcpServer.Stop()
	}
	if u.loadEgress != nil {
		load.TeardownEgressBuffer(*u.loadEgress)
	}
	if u.promExport != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := u.promExport.Shutdown(shutdownCtx); err != nil {
			logger.MainLog.Errorf("Prometheus exporter Shutdown Error: %v", err)
		}
	}
	if u.loadAPI != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := u.loadAPI.Shutdown(shutdownCtx); err != nil {
			logger.MainLog.Errorf("Load metric API Shutdown Error: %v", err)
		}
	}
	if u.eesServer != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := u.eesServer.Shutdown(shutdownCtx); err != nil {
			logger.MainLog.Errorf("EES API Server Shutdown Error: %v", err)
		}
	}
	if u.driver != nil {
		u.driver.Close()
	}
}

func (u *UpfApp) WaitRoutineStopped() {
	u.wg.Wait()
	u.Terminate()
}

func (u *UpfApp) Start() {
	if err := u.Run(); err != nil {
		logger.MainLog.Errorf("UPF Run err: %v", err)
	}
}

func (u *UpfApp) Terminate() {
	logger.MainLog.Infof("Terminating UPF...")
	logger.MainLog.Infof("UPF terminated")
}

// initEES starts the embedded Nupf_EventExposure service when enabled. EES only
// receives usage through a buffer-only PFCP hook; it never writes the PFCP queue.
func (u *UpfApp) initEES() error {
	if u.cfg.EES == nil || !u.cfg.EES.Enabled {
		return nil
	}
	logger.MainLog.Infoln("EES supports only the free5GC single-UPF scenario; keep it disabled in ULCL deployments")

	store := ees.NewSubscriptionStore("")
	aggregator := ees.NewAggregator(store, ees.NewNotifier(logger.EesLog), logger.EesLog)
	u.pfcpServer.RegisterEESReportHandler(aggregator.PushReportWithContext)

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		aggregator.Run(u.ctx)
	}()

	port := u.cfg.EES.Port
	if port == 0 {
		port = 8088
	}
	listenAddr := fmt.Sprintf("%s:%d", u.cfg.EES.IP, port)
	u.eesServer = ees.NewServer(store, logger.EesLog)

	u.wg.Add(1)
	go func() {
		defer u.wg.Done()
		if err := u.eesServer.Serve(listenAddr); err != nil {
			logger.MainLog.Errorf("EES API Server Error: %v", err)
		}
	}()

	logger.MainLog.Infof("EES started at %s (per-subscription repPeriod, SMF URR 2)", listenAddr)
	return nil
}

// initLoadMetric starts the egress load sampler and its temporary internal
// verification API.
func (u *UpfApp) initLoadMetric() error {
	cfg := u.cfg.Load
	if cfg == nil || !cfg.Enabled {
		return nil
	}

	ifname := cfg.IfName
	if ifname == "" {
		ifname = "upfegress"
	}
	kind := cfg.QdiscKind
	if kind == "" {
		// bfifo is required, not merely the default: its limit is in BYTES, so
		// backlog/limit is a byte ratio. pfifo's limit is in packets.
		kind = "bfifo"
	}
	// Build the buffer first: the sampler takes its first reading immediately,
	// so the queue must exist before it runs for the metric to be live as soon
	// as the pod is up.
	if cfg.SetupEgress {
		srcIf := cfg.EgressSourceIf
		if srcIf == "" {
			// Fall back to the configured gtp5g link name, guarding the
			// slice: IfList is optional in the config schema, so indexing it
			// unconditionally would panic on a config that omits it. This
			// tree honours ifname -- forwarder/driver.go gtpuInterface()
			// names the device from gtpu.ifList[0].ifname, falling back to
			// DefaultLinkName -- so hardcoding "upfgtp" would attach the
			// egress buffer to the wrong device whenever ifname is set.
			if u.cfg.Gtpu != nil && len(u.cfg.Gtpu.IfList) > 0 {
				srcIf = u.cfg.Gtpu.IfList[0].IfName
			}
			if srcIf == "" {
				srcIf = "upfgtp"
			}
		}
		bufBytes := cfg.EgressBufferBytes
		if bufBytes == 0 {
			bufBytes = 65536
		}
		dlBufBytes := cfg.DLEgressBufferBytes
		if dlBufBytes == 0 {
			dlBufBytes = bufBytes // same capacity as uplink unless overridden
		}
		maxUEs := cfg.PerUEQueueMax
		if maxUEs <= 0 {
			maxUEs = 16
		}
		u.loadEgress = &load.EgressBufferSpec{
			IfName:       ifname,
			SourceIf:     srcIf,
			Rate:         cfg.EgressRate,
			LimitBytes:   bufBytes,
			DLRate:       cfg.DLEgressRate,
			DLLimitBytes: dlBufBytes,
			PerUE:        cfg.PerUEQueues,
			MaxUEs:       maxUEs,
		}
		if err := load.SetupEgressBuffer(*u.loadEgress, logger.LoadLog); err != nil {
			u.loadEgress = nil
			return err
		}
	}

	interval := time.Duration(cfg.SampleIntervalMs) * time.Millisecond
	if interval <= 0 {
		interval = 200 * time.Millisecond
	}
	window := time.Duration(cfg.AverageWindowMs) * time.Millisecond
	if window <= 0 {
		window = 2 * time.Second
	}

	// Uplink: the ifb device fed from the gtp5g link's ingress.
	ulTracker := load.NewTracker(interval, window, ifname)
	ulSampler, err := load.NewSampler(ulTracker, ifname, kind, load.DirUplink,
		interval, logger.LoadLog)
	if err != nil {
		return err
	}
	// Downlink: the gtp5g link's own egress queue, measured only when the
	// deployment asked for a downlink bottleneck. Without one the queue never
	// fills, and a permanent DL 0 would be indistinguishable from an idle
	// downlink while silently capping max(UL, DL) at the UL value.
	var dlTracker *load.Tracker
	var dlSampler *load.Sampler
	if u.loadEgress != nil && u.loadEgress.DLEnabled() {
		dlTracker = load.NewTracker(interval, window, u.loadEgress.SourceIf)
		var dlErr error
		dlSampler, dlErr = load.NewSampler(dlTracker, u.loadEgress.SourceIf,
			kind, load.DirDownlink, interval, logger.LoadLog)
		if dlErr != nil {
			return dlErr
		}
	}

	// With a per-UE tree there is no single leaf to read, so each sampler must
	// sum the per-UE leaves (excluding the default class at minor 99).
	// Reading one leaf would make the load metric track one UE.
	if u.loadEgress != nil && u.loadEgress.PerUE {
		ulSampler.ReadAggregate(load.DefaultClassMinor)
		if dlSampler != nil {
			dlSampler.ReadAggregate(load.DefaultClassMinor)
		}
	}
	ulSampler.Run(u.ctx, &u.wg)
	if dlSampler != nil {
		dlSampler.Run(u.ctx, &u.wg)
	}

	// Per-UE trackers: one filter per UE per direction, so each UE's drops
	// land in a counter of its own. UEs are discovered from the gtp5g
	// datapath, which is also where the exporter's session list comes from.
	if u.loadEgress != nil && u.loadEgress.PerUE {
		pdr := metrics.NewPDRReader(u.loadEgress.SourceIf,
			uint64(cfg.PerUEMaxSessions), 0)
		discover := func() ([]string, error) {
			st, err := pdr.Scan()
			if err != nil {
				return nil, err
			}
			out := make([]string, 0, len(st))
			for addr := range st {
				out = append(out, addr)
			}
			return out, nil
		}
		if t, terr := load.NewUETracker(u.loadEgress.ULQueue(),
			load.DirUplink, discover, logger.LoadLog); terr == nil {
			t.Run(u.ctx, &u.wg, 5*time.Second)
			u.ueTrackers = append(u.ueTrackers, t)
		} else {
			logger.MainLog.Warnf("uplink per-UE tracker: %v", terr)
		}
		if dlTracker != nil {
			if t, terr := load.NewUETracker(u.loadEgress.DLQueue(),
				load.DirDownlink, discover, logger.LoadLog); terr == nil {
				t.Run(u.ctx, &u.wg, 5*time.Second)
				u.ueTrackers = append(u.ueTrackers, t)
			} else {
				logger.MainLog.Warnf("downlink per-UE tracker: %v", terr)
			}
		}
	}

	u.loadMetrics = load.NewCombiner(ulTracker, dlTracker)
	if dlTracker != nil {
		logger.MainLog.Infof(
			"load metric enabled: max(UL %s/%s, DL %s/%s) sampled every %s, "+
				"averaged over %s", ifname, kind, u.loadEgress.SourceIf, kind,
			interval, window)
	} else {
		logger.MainLog.Infof(
			"load metric enabled: UL only on %s/%s sampled every %s, "+
				"averaged over %s (no dlEgressRate configured)",
			ifname, kind, interval, window)
	}

	// Prometheus exporter. Separate from the temporary verification endpoint:
	// that one is to be deleted once PFCP carries the metric, while this is
	// the lasting monitoring surface the chart's PodMonitor scrapes.
	if cfg.MetricsAddr != "" {
		var pdr *metrics.PDRReader
		if cfg.PerUEMetrics {
			srcIf := "upfgtp"
			if u.loadEgress != nil && u.loadEgress.SourceIf != "" {
				srcIf = u.loadEgress.SourceIf
			}
			pdr = metrics.NewPDRReader(srcIf,
				uint64(cfg.PerUEMaxSessions), 0)
		}
		ttl := time.Duration(cfg.PerUECacheMs) * time.Millisecond
		u.promExport = metrics.NewExporter(u.loadMetrics, u.loadMetrics, pdr,
			ttl, logger.LoadLog)
		// Per-UE shaper counters, which is where real per-UE loss lives.
		for _, t := range u.ueTrackers {
			u.promExport.AddUELossSource(t)
		}
		addr := cfg.MetricsAddr
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			if err := u.promExport.Serve(addr); err != nil {
				logger.MainLog.Errorf("Prometheus exporter error: %v", err)
			}
		}()
	}

	if cfg.APIAddr != "" {
		u.loadAPI = load.NewAPIServer(u.loadMetrics, logger.LoadLog)
		addr := cfg.APIAddr
		u.wg.Add(1)
		go func() {
			defer u.wg.Done()
			if err := u.loadAPI.Serve(addr); err != nil {
				logger.MainLog.Errorf("Load metric API Error: %v", err)
			}
		}()
	}
	return nil
}
