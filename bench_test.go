package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// parseSSHDLine — hot path: called on every line tailed from disk.
// ---------------------------------------------------------------------------

var benchLines = []struct {
	name string
	line string
}{
	{
		name: "FailedPassword",
		line: "Apr 11 12:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.10 port 54321 ssh2",
	},
	{
		name: "FailedPassword_InvalidUser",
		line: "Apr 11 12:00:01 myhost sshd[1234]: Failed password for invalid user admin from 10.0.0.1 port 22 ssh2",
	},
	{
		name: "InvalidUser",
		line: "Apr 11 12:00:01 myhost sshd[1234]: Invalid user deploy from 203.0.113.5 port 9022",
	},
	{
		name: "Accepted",
		line: "Apr 11 12:01:00 myhost sshd[5678]: Accepted publickey for alice from 172.16.0.5 port 43210 ssh2",
	},
	{
		name: "Disconnected",
		line: "Apr 11 12:05:00 myhost sshd[5678]: Disconnected from user alice 172.16.0.5 port 43210",
	},
	{
		name: "Irrelevant",
		line: "Apr 11 12:00:00 myhost sshd[1234]: Server listening on 0.0.0.0 port 22.",
	},
	{
		name: "IPv6",
		line: "Apr 11 12:00:01 myhost sshd[1234]: Failed password for root from ::1 port 22 ssh2",
	},
}

func BenchmarkParseSSHDLine(b *testing.B) {
	for _, tc := range benchLines {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				parseSSHDLine(tc.line, "/var/log/auth.log")
			}
		})
	}
}

// BenchmarkParseSSHDLine_All measures the aggregate throughput when cycling
// through all pattern types, reflecting realistic mixed-traffic workloads.
func BenchmarkParseSSHDLine_All(b *testing.B) {
	b.ReportAllocs()
	n := len(benchLines)
	for i := 0; i < b.N; i++ {
		parseSSHDLine(benchLines[i%n].line, "/var/log/auth.log")
	}
}

// ---------------------------------------------------------------------------
// parseLine — adds dispatch overhead on top of parseSSHDLine.
// ---------------------------------------------------------------------------

func BenchmarkParseLine(b *testing.B) {
	lt := newTestTailer("sshd")
	line := "Apr 11 12:00:01 myhost sshd[1234]: Failed password for root from 192.168.1.10 port 54321 ssh2"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lt.parseLine(line)
	}
}

func BenchmarkParseLine_UnknownType(b *testing.B) {
	lt := newTestTailer("nginx")
	line := "Apr 11 12:00:01 myhost sshd[1234]: Accepted publickey for bob from 10.0.0.1 port 22 ssh2"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		lt.parseLine(line)
	}
}

// ---------------------------------------------------------------------------
// sendEvent — full HTTP round-trip to a local mock server.
// ---------------------------------------------------------------------------

func BenchmarkSendEvent(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	lt := &LogTailer{
		cfg:    &Config{APIEndpoint: srv.URL},
		apiKey: "lsoc_live_benchkey",
		client: &http.Client{Timeout: 5 * time.Second},
	}
	payload := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "192.168.1.10",
		Actor:  &IngestActor{ID: "root"},
		Metadata: map[string]any{
			"source":   "sshd",
			"log_file": "/var/log/auth.log",
			"reason":   "failed_password",
			"port":     "54321",
		},
	}

	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = lt.sendEvent(ctx, payload)
	}
}

// ---------------------------------------------------------------------------
// sendHeartbeat — heartbeat HTTP round-trip.
// ---------------------------------------------------------------------------

func BenchmarkSendHeartbeat(b *testing.B) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	client := &http.Client{Timeout: 5 * time.Second}
	ctx := context.Background()

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sendHeartbeat(ctx, cfg, "lsoc_live_benchkey", client)
	}
}

// ---------------------------------------------------------------------------
// loadConfig — YAML parsing from disk.
// ---------------------------------------------------------------------------

func BenchmarkLoadConfig(b *testing.B) {
	path := writeTempConfig(b, "api_endpoint: https://api.litesoc.io\nheartbeat_interval: 30\nlog_watchers:\n  - path: /var/log/auth.log\n    type: sshd\n  - path: /var/log/secure\n    type: sshd\n")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = loadConfig(path)
	}
}
