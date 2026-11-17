package app

import (
	"context"
	"os"
	"os/signal"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/free5gc/go-upf/internal/forwarder"
	"github.com/free5gc/go-upf/internal/load"
	"github.com/free5gc/go-upf/internal/logger"
	"github.com/free5gc/go-upf/internal/pfcp"
	"github.com/free5gc/go-upf/pkg/factory"
)

type UpfApp struct {
	ctx        context.Context
	wg         sync.WaitGroup
	cfg        *factory.Config
	driver     forwarder.Driver
	pfcpServer *pfcp.PfcpServer

	loadMetrics *load.Combiner
	loadAPI     *load.APIServer
	loadEgress  *load.EgressBufferSpec
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
	if u.loadAPI != nil {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if err := u.loadAPI.Shutdown(shutdownCtx); err != nil {
			logger.MainLog.Errorf("Load metric API Shutdown Error: %v", err)
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
			// go-upf v1.2.13 always names the gtp5g link "upfgtp"
			// (internal/forwarder/gtp5glink.go); gtpu.ifList[].ifname
			// does not rename it in this version.
			srcIf = "upfgtp"
		}
		bufBytes := cfg.EgressBufferBytes
		if bufBytes == 0 {
			bufBytes = 65536
		}
		dlBufBytes := cfg.DLEgressBufferBytes
		if dlBufBytes == 0 {
			dlBufBytes = bufBytes // same capacity as uplink unless overridden
		}
		u.loadEgress = &load.EgressBufferSpec{
			IfName:       ifname,
			SourceIf:     srcIf,
			Rate:         cfg.EgressRate,
			LimitBytes:   bufBytes,
			DLRate:       cfg.DLEgressRate,
			DLLimitBytes: dlBufBytes,
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
	ulSampler.Run(u.ctx, &u.wg)

	// Downlink: the gtp5g link's own egress queue, measured only when the
	// deployment asked for a downlink bottleneck. Without one the queue never
	// fills, and a permanent DL 0 would be indistinguishable from an idle
	// downlink while silently capping max(UL, DL) at the UL value.
	var dlTracker *load.Tracker
	if u.loadEgress != nil && u.loadEgress.DLEnabled() {
		dlTracker = load.NewTracker(interval, window, u.loadEgress.SourceIf)
		dlSampler, dlErr := load.NewSampler(dlTracker, u.loadEgress.SourceIf,
			kind, load.DirDownlink, interval, logger.LoadLog)
		if dlErr != nil {
			return dlErr
		}
		dlSampler.Run(u.ctx, &u.wg)
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
