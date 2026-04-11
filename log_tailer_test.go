package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/nxadm/tail"
)

func TestParseSSHDLine_FailedPassword(t *testing.T) {
	line := "Apr 11 12:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.10 port 54321 ssh2"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginFailed, got.Event)
	assertEq(t, "user_ip", "192.168.1.10", got.UserIP)
	assertEq(t, "actor.id", "root", got.Actor.ID)
	assertMeta(t, got.Metadata, "reason", "failed_password")
	assertMeta(t, got.Metadata, "port", "54321")
	assertMeta(t, got.Metadata, "source", "sshd")
	assertMeta(t, got.Metadata, "log_file", "/var/log/auth.log")
}

func TestParseSSHDLine_FailedPasswordInvalidUser(t *testing.T) {
	line := "Apr 11 12:00:01 myhost sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginFailed, got.Event)
	assertEq(t, "user_ip", "10.0.0.1", got.UserIP)
	assertEq(t, "actor.id", "admin", got.Actor.ID)
	assertMeta(t, got.Metadata, "reason", "failed_password")
}

func TestParseSSHDLine_InvalidUser(t *testing.T) {
	line := "Apr 11 12:00:01 myhost sshd[1234]: Invalid user deploy from 203.0.113.5 port 9022"
	got := parseSSHDLine(line, "/var/log/secure")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginFailed, got.Event)
	assertEq(t, "user_ip", "203.0.113.5", got.UserIP)
	assertEq(t, "actor.id", "deploy", got.Actor.ID)
	assertMeta(t, got.Metadata, "reason", "invalid_user")
	assertMeta(t, got.Metadata, "port", "9022")
}

func TestParseSSHDLine_AcceptedPassword(t *testing.T) {
	line := "Apr 11 12:01:00 myhost sshd[5678]: Accepted password for alice from 172.16.0.5 port 43210 ssh2"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginSuccess, got.Event)
	assertEq(t, "user_ip", "172.16.0.5", got.UserIP)
	assertEq(t, "actor.id", "alice", got.Actor.ID)
	assertMeta(t, got.Metadata, "port", "43210")
}

func TestParseSSHDLine_AcceptedPublickey(t *testing.T) {
	line := "Apr 11 12:01:00 myhost sshd[5678]: Accepted publickey for bob from 192.0.2.1 port 55000 ssh2"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginSuccess, got.Event)
	assertEq(t, "actor.id", "bob", got.Actor.ID)
}

func TestParseSSHDLine_Disconnected_WithUser(t *testing.T) {
	line := "Apr 11 12:05:00 myhost sshd[5678]: Disconnected from user alice 172.16.0.5 port 43210"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLogout, got.Event)
	assertEq(t, "user_ip", "172.16.0.5", got.UserIP)
	assertEq(t, "actor.id", "alice", got.Actor.ID)
}

func TestParseSSHDLine_Disconnected_AuthenticatingUser(t *testing.T) {
	line := "Apr 11 12:05:01 myhost sshd[5678]: Disconnected from authenticating user root 192.168.1.10 port 54321"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLogout, got.Event)
	assertEq(t, "actor.id", "root", got.Actor.ID)
}

func TestParseSSHDLine_Disconnected_InvalidUser(t *testing.T) {
	line := "Apr 11 12:05:02 myhost sshd[5678]: Disconnected from invalid user hacker 10.0.0.1 port 22"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLogout, got.Event)
	assertEq(t, "actor.id", "hacker", got.Actor.ID)
}

func TestParseSSHDLine_Disconnected_NoUser(t *testing.T) {
	line := "Apr 11 12:05:03 myhost sshd[5678]: Disconnected from 192.168.1.10 port 54321"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLogout, got.Event)
	assertEq(t, "actor.id", "unknown", got.Actor.ID)
}

func TestParseSSHDLine_IPv6(t *testing.T) {
	line := "Apr 11 12:00:01 myhost sshd[1234]: Failed password for root from ::1 port 22 ssh2"
	got := parseSSHDLine(line, "/var/log/auth.log")
	if got == nil {
		t.Fatal("expected event for IPv6, got nil")
	}
	assertEq(t, "user_ip", "::1", got.UserIP)
}

func TestParseSSHDLine_Irrelevant(t *testing.T) {
	lines := []string{
		"Apr 11 12:00:00 myhost sshd[1234]: Server listening on 0.0.0.0 port 22.",
		"Apr 11 12:00:00 myhost sshd[1234]: Received signal 15; terminating.",
		"Apr 11 12:00:00 myhost CRON[9999]: (root) CMD (/usr/lib/notify-motd)",
		"",
	}
	for _, line := range lines {
		if got := parseSSHDLine(line, "/var/log/auth.log"); got != nil {
			t.Errorf("line %q: expected nil, got event %q", line, got.Event)
		}
	}
}

func TestParseLine_SSHDType(t *testing.T) {
	lt := newTestTailer("sshd")
	line := "Apr 11 12:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"
	got := lt.parseLine(line)
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginFailed, got.Event)
}

func TestParseLine_UnknownTypeDefaultsToSSHD(t *testing.T) {
	lt := newTestTailer("nginx")
	line := "Apr 11 12:00:01 host sshd[1]: Accepted publickey for ci from 1.2.3.4 port 22 ssh2"
	got := lt.parseLine(line)
	if got == nil {
		t.Fatal("expected event, got nil")
	}
	assertEq(t, "event", eventAuthLoginSuccess, got.Event)
}

func TestParseLine_EmptyTypeDefaultsToSSHD(t *testing.T) {
	lt := newTestTailer("")
	line := "Apr 11 12:00:01 host sshd[1]: Accepted password for ci from 1.2.3.4 port 22 ssh2"
	if got := lt.parseLine(line); got == nil {
		t.Fatal("expected event for empty type, got nil")
	}
}

func TestParseLine_IrrelevantLine(t *testing.T) {
	lt := newTestTailer("sshd")
	if got := lt.parseLine("just a noise line"); got != nil {
		t.Errorf("expected nil for noise line, got %+v", got)
	}
}

func TestSendEvent_Success(t *testing.T) {
	var received IngestPayload
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("Method = %s; want POST", r.Method)
		}
		if r.URL.Path != "/collect" {
			t.Errorf("Path = %s; want /collect", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "lsoc_live_testkey" {
			t.Errorf("X-API-Key wrong or missing")
		}
		if ct := r.Header.Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q; want application/json", ct)
		}
		_ = json.NewDecoder(r.Body).Decode(&received)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	lt := &LogTailer{cfg: &Config{APIEndpoint: srv.URL}, apiKey: "lsoc_live_testkey", client: &http.Client{Timeout: 5 * time.Second}}
	err := lt.sendEvent(context.Background(), &IngestPayload{
		Event: eventAuthLoginFailed, UserIP: "192.168.1.1",
		Actor: &IngestActor{ID: "root"}, Metadata: map[string]any{"source": "sshd"},
	})
	if err != nil {
		t.Fatalf("sendEvent error: %v", err)
	}
	assertEq(t, "event", eventAuthLoginFailed, received.Event)
	assertEq(t, "user_ip", "192.168.1.1", received.UserIP)
}

func TestSendEvent_Non2xxReturnsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	lt := &LogTailer{cfg: &Config{APIEndpoint: srv.URL}, apiKey: "bad", client: &http.Client{Timeout: 5 * time.Second}}
	if err := lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for 401, got nil")
	}
}

func TestSendEvent_ServerError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	lt := &LogTailer{cfg: &Config{APIEndpoint: srv.URL}, client: &http.Client{Timeout: 5 * time.Second}}
	if err := lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for 500, got nil")
	}
}

func TestSendEvent_Unreachable(t *testing.T) {
	lt := &LogTailer{cfg: &Config{APIEndpoint: "http://127.0.0.1:1"}, client: &http.Client{Timeout: 100 * time.Millisecond}}
	if err := lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for unreachable server, got nil")
	}
}

func TestSendEvent_UserAgentHeader(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if want := "litesoc-agent/" + agentVersion; r.Header.Get("User-Agent") != want {
			t.Errorf("User-Agent = %q; want %q", r.Header.Get("User-Agent"), want)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	lt := &LogTailer{cfg: &Config{APIEndpoint: srv.URL}, apiKey: "key", client: &http.Client{Timeout: 5 * time.Second}}
	_ = lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed})
}

func TestSendEvent_CancelledContext(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(200 * time.Millisecond)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lt := &LogTailer{cfg: &Config{APIEndpoint: srv.URL}, apiKey: "key", client: &http.Client{Timeout: 5 * time.Second}}
	if err := lt.sendEvent(ctx, &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestNewLogTailer_Fields(t *testing.T) {
	cfg := &Config{APIEndpoint: "https://api.litesoc.io", HeartbeatInterval: 60}
	watcher := WatcherCfg{Path: "/var/log/auth.log", Type: "sshd"}
	lt := NewLogTailer(cfg, "lsoc_live_key", watcher)
	if lt.cfg != cfg {
		t.Error("cfg not set correctly")
	}
	if lt.apiKey != "lsoc_live_key" {
		t.Errorf("apiKey = %q; want lsoc_live_key", lt.apiKey)
	}
	if lt.watcher.Path != "/var/log/auth.log" {
		t.Errorf("watcher.Path = %q", lt.watcher.Path)
	}
	if lt.client == nil {
		t.Error("http client must not be nil")
	}
}

func TestIngestPayload_JSON(t *testing.T) {
	p := &IngestPayload{
		Event: eventAuthLoginFailed, UserIP: "1.2.3.4",
		Actor:    &IngestActor{ID: "root"},
		Metadata: map[string]any{"source": "sshd", "log_file": "/var/log/auth.log", "reason": "failed_password", "port": "22"},
	}
	data, err := json.Marshal(p)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out["event"] != eventAuthLoginFailed {
		t.Errorf("event = %v", out["event"])
	}
	if out["user_ip"] != "1.2.3.4" {
		t.Errorf("user_ip = %v", out["user_ip"])
	}
}

func TestIngestPayload_OmitsNilFields(t *testing.T) {
	p := &IngestPayload{Event: eventAuthLoginFailed}
	data, _ := json.Marshal(p)
	var out map[string]any
	_ = json.Unmarshal(data, &out)
	if _, ok := out["actor"]; ok {
		t.Error("actor field should be omitted when nil")
	}
	if _, ok := out["user_ip"]; ok {
		t.Error("user_ip should be omitted when empty")
	}
}

func newTestTailer(watcherType string) *LogTailer {
	return &LogTailer{
		cfg:     &Config{APIEndpoint: "https://api.litesoc.io"},
		apiKey:  "lsoc_live_testkey",
		watcher: WatcherCfg{Path: "/var/log/auth.log", Type: watcherType},
		client:  &http.Client{Timeout: 5 * time.Second},
	}
}

func assertEq(t *testing.T, field, want, got string) {
	t.Helper()
	if got != want {
		t.Errorf("%s: got %q; want %q", field, got, want)
	}
}

func assertMeta(t *testing.T, meta map[string]any, key, want string) {
	t.Helper()
	v, ok := meta[key]
	if !ok {
		t.Errorf("metadata missing key %q", key)
		return
	}
	if s, _ := v.(string); s != want {
		t.Errorf("metadata[%q] = %q; want %q", key, s, want)
	}
}

func TestSendEvent_InvalidURL(t *testing.T) {
	// "://invalid" causes http.NewRequestWithContext to fail — covers the build-request error branch.
	lt := &LogTailer{
		cfg:    &Config{APIEndpoint: "://invalid"},
		apiKey: "key",
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if err := lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for invalid URL, got nil")
	}
}

func TestLogTailerRun_ForwardsEvents(t *testing.T) {
	// Integration test: write sshd lines to a temp file, verify they reach the mock server.
	var (
		mu     sync.Mutex
		events []IngestPayload
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p IngestPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		mu.Lock()
		events = append(events, p)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	dir := t.TempDir()
	logFile := dir + "/auth.log"
	// Create file first so tail does not have to wait.
	if err := os.WriteFile(logFile, []byte{}, 0600); err != nil {
		t.Fatalf("create log file: %v", err)
	}

	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	watcher := WatcherCfg{Path: logFile, Type: "sshd"}
	lt := NewLogTailer(cfg, "lsoc_live_testkey", watcher)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	runErr := make(chan error, 1)
	go func() {
		runErr <- lt.Run(ctx)
	}()

	// Brief pause to let tail initialise.
	time.Sleep(100 * time.Millisecond)

	// Append two actionable lines.
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	_, _ = f.WriteString("Apr 11 12:00:01 host sshd[1]: Failed password for root from 192.168.1.1 port 22 ssh2\n")
	_, _ = f.WriteString("Apr 11 12:01:00 host sshd[1]: Accepted publickey for alice from 10.0.0.1 port 22 ssh2\n")
	_ = f.Close()

	// Wait up to 3 s for both events to arrive.
	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("timed out waiting for events; got %d", n)
		case <-time.After(50 * time.Millisecond):
		}
	}

	cancel()
	<-runErr

	mu.Lock()
	defer mu.Unlock()
	var gotFailed, gotSuccess bool
	for _, e := range events {
		switch e.Event {
		case eventAuthLoginFailed:
			gotFailed = true
		case eventAuthLoginSuccess:
			gotSuccess = true
		}
	}
	if !gotFailed {
		t.Error("expected auth.login_failed event")
	}
	if !gotSuccess {
		t.Error("expected auth.login_success event")
	}
}

func TestLogTailerRun_StopsOnContextCancel(t *testing.T) {
	dir := t.TempDir()
	logFile := dir + "/auth.log"
	if err := os.WriteFile(logFile, []byte{}, 0600); err != nil {
		t.Fatalf("create log file: %v", err)
	}

	cfg := &Config{APIEndpoint: "http://127.0.0.1:1", HeartbeatInterval: 60}
	lt := NewLogTailer(cfg, "key", WatcherCfg{Path: logFile, Type: "sshd"})

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- lt.Run(ctx) }()

	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Run did not stop after context cancellation")
	}
}

// mockFailingTailSrc returns an error immediately; used by both log_tailer and
// main tests to trigger the tail-error path without a real file system.
func mockFailingTailSrc(_ string, _ tail.Config) (*tailSrc, error) {
	return nil, fmt.Errorf("mock tail error")
}

func TestSendEvent_MarshalError(t *testing.T) {
	orig := marshalJSON
	defer func() { marshalJSON = orig }()
	marshalJSON = func(v any) ([]byte, error) { return nil, fmt.Errorf("mock marshal error") }

	lt := &LogTailer{
		cfg:    &Config{APIEndpoint: "http://127.0.0.1:1"},
		apiKey: "key",
		client: &http.Client{Timeout: 5 * time.Second},
	}
	if err := lt.sendEvent(context.Background(), &IngestPayload{Event: eventAuthLoginFailed}); err == nil {
		t.Fatal("expected error for marshal failure, got nil")
	}
}

func TestLogTailerRun_TailError(t *testing.T) {
	orig := newTailSrc
	defer func() { newTailSrc = orig }()
	newTailSrc = mockFailingTailSrc

	lt := newTestTailer("sshd")
	err := lt.Run(context.Background())
	if err == nil {
		t.Fatal("expected error from Run, got nil")
	}
}

func TestLogTailerRun_ChannelClosed(t *testing.T) {
	orig := newTailSrc
	defer func() { newTailSrc = orig }()

	ch := make(chan *tail.Line)
	close(ch)
	newTailSrc = func(_ string, _ tail.Config) (*tailSrc, error) {
		return &tailSrc{lines: ch, stop: func() {}, clean: func() {}}, nil
	}

	lt := newTestTailer("sshd")
	if err := lt.Run(context.Background()); err != nil {
		t.Errorf("Run returned unexpected error: %v", err)
	}
}

func TestLogTailerRun_LineError(t *testing.T) {
	orig := newTailSrc
	defer func() { newTailSrc = orig }()

	ch := make(chan *tail.Line, 2)
	ch <- &tail.Line{Err: errors.New("read error")}
	close(ch) // closed channel triggers !ok on the next iteration

	newTailSrc = func(_ string, _ tail.Config) (*tailSrc, error) {
		return &tailSrc{lines: ch, stop: func() {}, clean: func() {}}, nil
	}

	lt := newTestTailer("sshd")
	if err := lt.Run(context.Background()); err != nil {
		t.Errorf("Run returned unexpected error: %v", err)
	}
}

func TestLogTailerRun_SendEventError(t *testing.T) {
	orig := newTailSrc
	defer func() { newTailSrc = orig }()

	ch := make(chan *tail.Line, 2)
	// A line that parses into an event.
	ch <- &tail.Line{Text: "Apr 11 12:00:01 host sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2"}
	close(ch)

	newTailSrc = func(_ string, _ tail.Config) (*tailSrc, error) {
		return &tailSrc{lines: ch, stop: func() {}, clean: func() {}}, nil
	}

	// Point to a server that refuses connections so sendEvent fails.
	lt := &LogTailer{
		cfg:     &Config{APIEndpoint: "http://127.0.0.1:1"},
		apiKey:  "key",
		watcher: WatcherCfg{Path: "/var/log/auth.log", Type: "sshd"},
		client:  &http.Client{Timeout: 100 * time.Millisecond},
	}
	if err := lt.Run(context.Background()); err != nil {
		t.Errorf("Run must return nil even when sendEvent errors: %v", err)
	}
}

// TestNewTailSrc_ErrorOnMissingFile calls the real (non-mocked) newTailSrc
// with MustExist: true and a non-existent path, which makes tail.TailFile
// return an error — covering the "return nil, err" branch in newTailSrc.
func TestNewTailSrc_ErrorOnMissingFile(t *testing.T) {
	_, err := newTailSrc("/nonexistent/path/to/file.log", tail.Config{
		MustExist: true,
		Logger:    tail.DiscardingLogger,
	})
	if err == nil {
		t.Fatal("expected error for missing file with MustExist:true, got nil")
	}
}
