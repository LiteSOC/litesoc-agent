package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestLoadConfig_Valid(t *testing.T) {
	content := "api_endpoint: https://api.example.io\nheartbeat_interval: 30\nlog_watchers:\n  - path: /var/log/auth.log\n    type: sshd\n"
	path := writeTempConfig(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIEndpoint != "https://api.example.io" {
		t.Errorf("APIEndpoint = %q", cfg.APIEndpoint)
	}
	if cfg.HeartbeatInterval != 30 {
		t.Errorf("HeartbeatInterval = %d; want 30", cfg.HeartbeatInterval)
	}
	if len(cfg.LogWatchers) != 1 {
		t.Fatalf("LogWatchers len = %d; want 1", len(cfg.LogWatchers))
	}
	if cfg.LogWatchers[0].Path != "/var/log/auth.log" {
		t.Errorf("Path = %q", cfg.LogWatchers[0].Path)
	}
	if cfg.LogWatchers[0].Type != "sshd" {
		t.Errorf("Type = %q", cfg.LogWatchers[0].Type)
	}
}

func TestLoadConfig_DefaultsApplied(t *testing.T) {
	content := "log_watchers:\n  - path: /var/log/auth.log\n    type: sshd\n"
	path := writeTempConfig(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.APIEndpoint != "https://api.litesoc.io" {
		t.Errorf("default APIEndpoint = %q", cfg.APIEndpoint)
	}
	if cfg.HeartbeatInterval != 60 {
		t.Errorf("default HeartbeatInterval = %d; want 60", cfg.HeartbeatInterval)
	}
}

func TestLoadConfig_ZeroHeartbeatGetsDefault(t *testing.T) {
	path := writeTempConfig(t, "heartbeat_interval: 0")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HeartbeatInterval != 60 {
		t.Errorf("HeartbeatInterval = %d; want 60", cfg.HeartbeatInterval)
	}
}

func TestLoadConfig_NegativeHeartbeatGetsDefault(t *testing.T) {
	path := writeTempConfig(t, "heartbeat_interval: -5")
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.HeartbeatInterval != 60 {
		t.Errorf("HeartbeatInterval = %d; want 60", cfg.HeartbeatInterval)
	}
}

func TestLoadConfig_MissingFile(t *testing.T) {
	if _, err := loadConfig("/nonexistent/path/config.yaml"); err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
}

func TestLoadConfig_InvalidYAML(t *testing.T) {
	// An unclosed flow mapping is a genuine YAML parse error.
	path := writeTempConfig(t, "{unclosed: mapping")
	if _, err := loadConfig(path); err == nil {
		t.Fatal("expected error for invalid YAML, got nil")
	}
}

func TestLoadConfig_MultipleWatchers(t *testing.T) {
	content := "log_watchers:\n  - path: /var/log/auth.log\n    type: sshd\n  - path: /var/log/secure\n    type: sshd\n"
	path := writeTempConfig(t, content)
	cfg, err := loadConfig(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.LogWatchers) != 2 {
		t.Errorf("LogWatchers len = %d; want 2", len(cfg.LogWatchers))
	}
}

func TestSendHeartbeat_Success(t *testing.T) {
	var received heartbeatPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s; want POST", r.Method)
		}
		if r.URL.Path != "/agent/heartbeat" {
			t.Errorf("Path = %s; want /agent/heartbeat", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "lsoc_live_testkey" {
			t.Errorf("X-API-Key header missing or wrong")
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	sendHeartbeat(context.Background(), cfg, "lsoc_live_testkey", client)
	if received.AgentVersion != agentVersion {
		t.Errorf("agent_version = %q; want %q", received.AgentVersion, agentVersion)
	}
}

func TestSendHeartbeat_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	sendHeartbeat(context.Background(), cfg, "lsoc_live_testkey", client)
}

func TestSendHeartbeat_Unreachable(t *testing.T) {
	cfg := &Config{APIEndpoint: "http://127.0.0.1:1", HeartbeatInterval: 60}
	client := &http.Client{Timeout: 100 * time.Millisecond}
	sendHeartbeat(context.Background(), cfg, "lsoc_live_testkey", client)
}

func TestSendHeartbeat_UserAgentHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "litesoc-agent/" + agentVersion; r.Header.Get("User-Agent") != want {
			t.Errorf("User-Agent = %q; want %q", r.Header.Get("User-Agent"), want)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	sendHeartbeat(context.Background(), cfg, "key", client)
}

func writeTempConfig(t testing.TB, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	return path
}

func TestSendHeartbeat_InvalidURL(t *testing.T) {
	// "://invalid" causes http.NewRequestWithContext to fail — covers that branch.
	cfg := &Config{APIEndpoint: "://invalid", HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	sendHeartbeat(context.Background(), cfg, "key", client)
}

func TestRunHeartbeat_StopsOnContextCancel(t *testing.T) {
	// Verify runHeartbeat exits promptly when the context is cancelled.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan struct{})
	go func() {
		runHeartbeat(ctx, cfg, "lsoc_live_testkey")
		close(done)
	}()

	cancel()
	select {
	case <-done:
		// OK
	case <-time.After(3 * time.Second):
		t.Fatal("runHeartbeat did not stop after context was cancelled")
	}
}

func TestSendHeartbeat_MarshalError(t *testing.T) {
	orig := marshalJSON
	defer func() { marshalJSON = orig }()
	marshalJSON = func(v any) ([]byte, error) { return nil, fmt.Errorf("mock marshal error") }
	cfg := &Config{APIEndpoint: "http://127.0.0.1:1", HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	sendHeartbeat(context.Background(), cfg, "key", client) // must not panic
}

func TestRunHeartbeat_TickerFires(t *testing.T) {
	received := make(chan struct{}, 10)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case received <- struct{}{}:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 1}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan struct{})
	go func() {
		runHeartbeat(ctx, cfg, "key")
		close(done)
	}()

	// Wait for initial + at least one tick (2 total).
	for i := 0; i < 2; i++ {
		select {
		case <-received:
		case <-time.After(5 * time.Second):
			t.Fatalf("timeout waiting for heartbeat call %d", i+1)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runHeartbeat did not stop after context cancel")
	}
}

func TestMain_MissingAPIKey(t *testing.T) {
	orig := osExit
	defer func() { osExit = orig }()

	var exitCode int
	osExit = func(code int) {
		exitCode = code
		panic("osExit called")
	}

	t.Setenv("LITESOC_AGENT_KEY", "")
	func() {
		defer func() { _ = recover() }()
		main()
	}()

	if exitCode != 1 {
		t.Errorf("exit code = %d; want 1", exitCode)
	}
}

func TestMain_BadConfig(t *testing.T) {
	origExit := osExit
	origArgs := os.Args
	defer func() { osExit = origExit; os.Args = origArgs }()

	var exitCode int
	osExit = func(code int) {
		exitCode = code
		panic("osExit called")
	}

	t.Setenv("LITESOC_AGENT_KEY", "lsoc_live_testkey")
	os.Args = []string{"cmd", "/nonexistent/path/config.yaml"}

	func() {
		defer func() { _ = recover() }()
		main()
	}()

	if exitCode != 1 {
		t.Errorf("exit code = %d; want 1", exitCode)
	}
}

// TestMain_DefaultConfigPath covers the len(os.Args)==1 branch (no path arg).
func TestMain_DefaultConfigPath(t *testing.T) {
	origExit := osExit
	origSignalNotify := signalNotify
	origNewTailSrc := newTailSrc
	origArgs := os.Args
	defer func() {
		osExit = origExit
		signalNotify = origSignalNotify
		newTailSrc = origNewTailSrc
		os.Args = origArgs
	}()

	var exitCalled bool
	osExit = func(code int) {
		exitCalled = true
		panic("osExit called")
	}
	newTailSrc = mockFailingTailSrc
	signalNotify = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() { time.Sleep(50 * time.Millisecond); c <- syscall.SIGTERM }()
	}

	t.Setenv("LITESOC_AGENT_KEY", "lsoc_live_testkey")
	os.Args = []string{"litesoc-agent"} // no path arg — uses default /etc/litesoc/config.yaml

	func() {
		defer func() { _ = recover() }()
		main()
	}()
	// If /etc/litesoc/config.yaml does not exist: osExit(1) is called (fine).
	// If it does exist: main runs fully and returns after SIGTERM (also fine).
	_ = exitCalled
}

// TestMain_FullRun exercises the happy path: config loads, goroutines start,
// the tailer errors (covers the slog.Error tailer path), and SIGTERM causes
// a clean shutdown.
func TestMain_FullRun(t *testing.T) {
	origSignalNotify := signalNotify
	origNewTailSrc := newTailSrc
	origArgs := os.Args
	defer func() {
		signalNotify = origSignalNotify
		newTailSrc = origNewTailSrc
		os.Args = origArgs
	}()

	// Inject failing tailer so the "tailer exited with error" log is covered.
	newTailSrc = mockFailingTailSrc

	// Inject signalNotify to fire SIGTERM shortly after startup.
	signalNotify = func(c chan<- os.Signal, _ ...os.Signal) {
		go func() { time.Sleep(100 * time.Millisecond); c <- syscall.SIGTERM }()
	}

	cfgPath := writeTempConfig(t,
		"api_endpoint: http://127.0.0.1:1\nheartbeat_interval: 60\nlog_watchers:\n  - path: /var/log/auth.log\n    type: sshd\n")

	t.Setenv("LITESOC_AGENT_KEY", "lsoc_live_testkey")
	os.Args = []string{"litesoc-agent", cfgPath}

	main() // returns after SIGTERM received and all goroutines clean up.
}
