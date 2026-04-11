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
)

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
	Hostname     string `json:"hostname"`
	IPAddress    string `json:"ip_address"`
	AgentVersion string `json:"agent_version"`
}

// getHostname returns the machine hostname or "unknown" on error.
func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}

// getOutboundIP returns the preferred outbound IP address.
func getOutboundIP() string {
	conn, err := net.DialTimeout("udp", "8.8.8.8:80", 2*time.Second)
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
}

func runHeartbeat(ctx context.Context, cfg *Config, apiKey string) {
	client := &http.Client{Timeout: 10 * time.Second}

	// Fire immediately on startup so the dashboard shows the agent as Active right away.
	sendHeartbeat(ctx, cfg, apiKey, client)

	ticker := time.NewTicker(time.Duration(cfg.HeartbeatInterval) * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sendHeartbeat(ctx, cfg, apiKey, client)
		}
	}
}

func main() {
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
		"heartbeat_interval_s", cfg.HeartbeatInterval,
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
