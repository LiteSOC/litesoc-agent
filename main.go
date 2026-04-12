package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

// agentVersion is overridden at build time via -ldflags "-X main.agentVersion=x.y.z".
var agentVersion = "1.0.0"

// Injectable for testing — never replace these in production code.
var (
	osExit       = os.Exit
	marshalJSON  = json.Marshal
	signalNotify = signal.Notify
	osHostname   = os.Hostname
	netDial      = func() (net.Conn, error) {
		return net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
	}
)

// ============================================
// Adaptive heartbeat
// ============================================

// heartbeatActiveInterval is the ping cadence used when security events have
// been seen recently. Injectable for tests.
var heartbeatActiveInterval = 60 * time.Second

// heartbeatIdleInterval is the ping cadence used when the system is quiet.
// Injectable for tests.
var heartbeatIdleInterval = 5 * time.Minute

// heartbeatIdleThreshold is how long since the last security event before the
// agent is considered idle. Injectable for tests.
var heartbeatIdleThreshold = 5 * time.Minute

// lastEventAt stores the Unix nanoseconds of the most recent parsed security
// event. Updated by markActivity(); read by isActive().
var lastEventAt atomic.Int64

// markActivity records that a security event was just observed. Called by
// LogTailer.Run() whenever a log line produces an IngestPayload.
func markActivity() {
	lastEventAt.Store(time.Now().UnixNano())
}

// isActive returns true when a security event has been seen within the last
// heartbeatIdleThreshold window, causing runHeartbeat to use the faster cadence.
func isActive() bool {
	ts := lastEventAt.Load()
	if ts == 0 {
		return false
	}
	return time.Since(time.Unix(0, ts)) < heartbeatIdleThreshold
}

// Config holds the full agent configuration loaded from config.yaml.
type Config struct {
	APIEndpoint       string       `yaml:"api_endpoint"`
	HeartbeatInterval int          `yaml:"heartbeat_interval"`
	LogWatchers       []WatcherCfg `yaml:"log_watchers"`
}

// WatcherCfg defines a single log file to monitor and its parser type.
type WatcherCfg struct {
	Path string `yaml:"path"`
	Type string `yaml:"type"` // "sshd" | "nginx" (extensible)
}

func loadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading config: %w", err)
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parsing config: %w", err)
	}
	if cfg.APIEndpoint == "" {
		cfg.APIEndpoint = "https://api.litesoc.io"
	}
	if cfg.HeartbeatInterval <= 0 {
		cfg.HeartbeatInterval = 60
	}
	return &cfg, nil
}

// heartbeatPayload is the body sent to /agent/heartbeat.
type heartbeatPayload struct {
	Hostname     string   `json:"hostname"`
	IPAddress    string   `json:"ip_address"`
	AgentVersion string   `json:"agent_version"`
	RecentLogs   []string `json:"recent_logs,omitempty"`
}

// ============================================
// Recent-logs ring buffer (goroutine-safe)
// ============================================

const recentLogsCapacity = 10

var recentLogsMu sync.Mutex
var recentLogsBuf = make([]string, 0, recentLogsCapacity)

// pushRecentLog appends a line to the ring buffer, evicting the oldest
// entry when capacity is reached.
func pushRecentLog(line string) {
	recentLogsMu.Lock()
	defer recentLogsMu.Unlock()
	if len(recentLogsBuf) >= recentLogsCapacity {
		recentLogsBuf = recentLogsBuf[1:]
	}
	recentLogsBuf = append(recentLogsBuf, line)
}

// drainRecentLogs returns a snapshot of the buffer and resets it.
func drainRecentLogs() []string {
	recentLogsMu.Lock()
	defer recentLogsMu.Unlock()
	if len(recentLogsBuf) == 0 {
		return nil
	}
	snap := make([]string, len(recentLogsBuf))
	copy(snap, recentLogsBuf)
	recentLogsBuf = recentLogsBuf[:0]
	return snap
}

// getHostname returns the machine hostname or "unknown" on error.
func getHostname() string {
	h, err := osHostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// getOutboundIP returns the preferred outbound IP address.
func getOutboundIP() string {
	conn, err := netDial()
	if err != nil {
		return "0.0.0.0"
	}
	defer func() { _ = conn.Close() }()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func sendHeartbeat(ctx context.Context, cfg *Config, apiKey string, client *http.Client) {
	payload := heartbeatPayload{
		Hostname:     getHostname(),
		IPAddress:    getOutboundIP(),
		AgentVersion: agentVersion,
		RecentLogs:   drainRecentLogs(),
	}
	body, err := marshalJSON(payload)
	if err != nil {
		slog.Warn("heartbeat: marshal failed", "error", err)
		return
	}

	url := cfg.APIEndpoint + "/agent/heartbeat"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		slog.Warn("heartbeat: build request failed", "error", err)
		return
	}
	req.Header.Set("X-API-Key", apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "litesoc-agent/"+agentVersion)

	resp, err := client.Do(req)
	if err != nil {
		slog.Warn("heartbeat: request failed", "error", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	slog.Debug("heartbeat sent", "status", resp.StatusCode)

	// Parse response for update instructions.
	if resp.StatusCode == http.StatusOK {
		var hbResp heartbeatResponse
		if err := json.NewDecoder(resp.Body).Decode(&hbResp); err != nil {
			slog.Debug("heartbeat: failed to parse response", "error", err)
			return
		}
		if hbResp.Update != nil && hbResp.Update.Available && hbResp.Update.Force {
			slog.Info("heartbeat: dashboard-triggered update received",
				"current", agentVersion,
				"target", hbResp.Update.LatestVersion,
				"url", hbResp.Update.DownloadURL,
			)
			if err := selfUpdate(hbResp.Update); err != nil {
				slog.Error("self-update failed",
					"error", err,
					"current", agentVersion,
					"target", hbResp.Update.LatestVersion,
					"url", hbResp.Update.DownloadURL,
				)
			}
		} else if hbResp.Update != nil && hbResp.Update.Available {
			slog.Info("heartbeat: update available (waiting for dashboard trigger)",
				"current", agentVersion,
				"latest", hbResp.Update.LatestVersion,
			)
		}
	}
}

func runHeartbeat(ctx context.Context, cfg *Config, apiKey string) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Fire immediately on startup so the dashboard shows the agent as Active.
	sendHeartbeat(ctx, cfg, apiKey, client)

	for {
		// Pick the interval based on whether security events have been seen
		// recently. This reduces API calls from once/minute to once/5-minutes
		// when the monitored host is quiet, cutting heartbeat costs by ~80%.
		interval := heartbeatIdleInterval
		if isActive() {
			interval = heartbeatActiveInterval
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			sendHeartbeat(ctx, cfg, apiKey, client)
		}
	}
}

func main() {
	// Handle --version before anything else (no env vars needed).
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Println("litesoc-agent " + agentVersion)
		return
	}

	// Structured JSON logging — no raw console.log equivalents.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	})))

	apiKey := os.Getenv("LITESOC_KEY")
	if apiKey == "" {
		slog.Error("LITESOC_KEY environment variable is not set")
		osExit(1)
		return
	}

	cfgPath := "/etc/litesoc/config.yaml"
	if len(os.Args) > 1 {
		cfgPath = os.Args[1]
	}

	cfg, err := loadConfig(cfgPath)
	if err != nil {
		slog.Error("failed to load config", "path", cfgPath, "error", err)
		osExit(1)
		return
	}

	slog.Info("litesoc-agent starting",
		"version", agentVersion,
		"endpoint", cfg.APIEndpoint,
		"watchers", len(cfg.LogWatchers),
		"heartbeat_active_s", int(heartbeatActiveInterval.Seconds()),
		"heartbeat_idle_s", int(heartbeatIdleInterval.Seconds()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var wg sync.WaitGroup

	// Launch one goroutine per configured log file.
	for _, w := range cfg.LogWatchers {
		wg.Add(1)
		go func(watcher WatcherCfg) {
			defer wg.Done()
			tailer := NewLogTailer(cfg, apiKey, watcher)
			if err := tailer.Run(ctx); err != nil && ctx.Err() == nil {
				slog.Error("tailer exited with error", "path", watcher.Path, "error", err)
			}
		}(w)
	}

	// Heartbeat goroutine.
	wg.Add(1)
	go func() {
		defer wg.Done()
		runHeartbeat(ctx, cfg, apiKey)
	}()

	// Block until SIGINT or SIGTERM.
	sigCh := make(chan os.Signal, 1)
	signalNotify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	sig := <-sigCh

	slog.Info("shutting down", "signal", sig.String())
	cancel()
	wg.Wait()
	slog.Info("litesoc-agent stopped")
}
