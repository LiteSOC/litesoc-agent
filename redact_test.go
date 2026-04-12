package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// isPasswordLike
// ---------------------------------------------------------------------------

func TestIsPasswordLike_PlainUsernamesAreNotRedacted(t *testing.T) {
	safe := []string{
		"root", "alice", "bob", "deploy", "ci-runner",
		"user_name", "john.doe", "admin", "ubuntu", "ec2-user",
		"user123", "test-deploy", "my.user",
	}
	for _, u := range safe {
		if isPasswordLike(u) {
			t.Errorf("isPasswordLike(%q) = true; want false (safe username)", u)
		}
	}
}

func TestIsPasswordLike_PasswordPatternsAreDetected(t *testing.T) {
	passwords := []string{
		"P@ssw0rd",         // letter+symbol+alphanumeric
		"S3cur!ty",         // letter+symbol+alphanumeric
		"hunter2!",         // ends with symbol
		"!admin",           // starts with symbol
		"P@$$word",         // two consecutive symbols
		"p4$$w0rd",         // two consecutive symbols
		"Tr0ub4dor&3",      // ampersand in middle
		"correct#horse",    // hash in middle
		"abc@def",          // at-sign between words
		"pass!word",        // exclamation in word
		"12345$6789",       // dollar sign
		"admin^1",          // caret
		"$$uperSecret",     // leading double symbol
		"my+passw0rd",      // plus sign mixed
		"secret~pass",      // tilde mixed
	}
	for _, p := range passwords {
		if !isPasswordLike(p) {
			t.Errorf("isPasswordLike(%q) = false; want true (password-like)", p)
		}
	}
}

func TestIsPasswordLike_EmptyString(t *testing.T) {
	if isPasswordLike("") {
		t.Error("isPasswordLike(\"\") = true; want false")
	}
}

// ---------------------------------------------------------------------------
// isPrivateIP
// ---------------------------------------------------------------------------

func TestIsPrivateIP_PrivateAddressesDetected(t *testing.T) {
	private := []string{
		// RFC 1918
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.254", "192.168.0.1", "192.168.1.100",
		// Loopback
		"127.0.0.1", "127.0.0.2", "::1",
		// Link-local
		"169.254.1.1", "fe80::1",
		// CGNAT
		"100.64.0.1", "100.127.255.255",
		// IPv6 unique local
		"fc00::1", "fd00::1",
	}
	for _, ip := range private {
		if !isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = false; want true (private range)", ip)
		}
	}
}

func TestIsPrivateIP_PublicAddressesNotRedacted(t *testing.T) {
	public := []string{
		"8.8.8.8", "1.1.1.1", "203.0.113.5", "198.51.100.0",
		"2001:db8::1", "2606:4700::1",
	}
	for _, ip := range public {
		if isPrivateIP(ip) {
			t.Errorf("isPrivateIP(%q) = true; want false (public address)", ip)
		}
	}
}

func TestIsPrivateIP_InvalidInputReturnsFalse(t *testing.T) {
	invalid := []string{"not-an-ip", "", "localhost", "example.com"}
	for _, s := range invalid {
		if isPrivateIP(s) {
			t.Errorf("isPrivateIP(%q) = true; want false (invalid input)", s)
		}
	}
}

func TestIsPrivateIP_StripsBracketedPort(t *testing.T) {
	// Addresses with ports should still be detected.
	if !isPrivateIP("[::1]:22") {
		t.Error("isPrivateIP(\"[::1]:22\") = false; want true")
	}
	if !isPrivateIP("192.168.1.1:22") {
		t.Error("isPrivateIP(\"192.168.1.1:22\") = false; want true")
	}
}

// ---------------------------------------------------------------------------
// redactPayload
// ---------------------------------------------------------------------------

func TestRedactPayload_NilIsNoop(t *testing.T) {
	redactPayload(nil) // must not panic
}

func TestRedactPayload_SafeActorUnchanged(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "203.0.113.10",
		Actor:  &IngestActor{ID: "root"},
	}
	redactPayload(p)
	if p.Actor.ID != "root" {
		t.Errorf("Actor.ID = %q; want 'root'", p.Actor.ID)
	}
	if p.UserIP != "203.0.113.10" {
		t.Errorf("UserIP = %q; want '203.0.113.10'", p.UserIP)
	}
}

func TestRedactPayload_PasswordActorIsRedacted(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "203.0.113.10",
		Actor:  &IngestActor{ID: "P@ssw0rd"},
	}
	redactPayload(p)
	if p.Actor.ID != redactedValue {
		t.Errorf("Actor.ID = %q; want %q", p.Actor.ID, redactedValue)
	}
	// UserIP must be untouched.
	if p.UserIP != "203.0.113.10" {
		t.Errorf("UserIP = %q; want '203.0.113.10'", p.UserIP)
	}
}

func TestRedactPayload_PrivateIPIsRedacted(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "192.168.1.50",
		Actor:  &IngestActor{ID: "alice"},
	}
	redactPayload(p)
	if p.UserIP != redactedValue {
		t.Errorf("UserIP = %q; want %q", p.UserIP, redactedValue)
	}
	// Actor must be untouched.
	if p.Actor.ID != "alice" {
		t.Errorf("Actor.ID = %q; want 'alice'", p.Actor.ID)
	}
}

func TestRedactPayload_BothPasswordAndPrivateIPRedacted(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "10.0.0.5",
		Actor:  &IngestActor{ID: "Secr3t!"},
	}
	redactPayload(p)
	if p.Actor.ID != redactedValue {
		t.Errorf("Actor.ID = %q; want %q", p.Actor.ID, redactedValue)
	}
	if p.UserIP != redactedValue {
		t.Errorf("UserIP = %q; want %q", p.UserIP, redactedValue)
	}
}

func TestRedactPayload_NilActorNoFieldPanic(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLogout,
		UserIP: "8.8.8.8",
		Actor:  nil,
	}
	redactPayload(p) // must not panic when Actor is nil
	if p.UserIP != "8.8.8.8" {
		t.Errorf("UserIP = %q; want '8.8.8.8'", p.UserIP)
	}
}

func TestRedactPayload_EmptyUserIPNoFieldPanic(t *testing.T) {
	p := &IngestPayload{
		Event: eventAuthLoginFailed,
		Actor: &IngestActor{ID: "alice"},
	}
	redactPayload(p) // UserIP is "" — must not call isPrivateIP with garbage
	if p.Actor.ID != "alice" {
		t.Errorf("Actor.ID = %q; want 'alice'", p.Actor.ID)
	}
}

func TestRedactPayload_Idempotent(t *testing.T) {
	p := &IngestPayload{
		Event:  eventAuthLoginFailed,
		UserIP: "172.16.0.1",
		Actor:  &IngestActor{ID: "P@ssw0rd"},
	}
	redactPayload(p)
	redactPayload(p) // second call must not change anything further
	if p.Actor.ID != redactedValue {
		t.Errorf("Actor.ID = %q after idempotent call", p.Actor.ID)
	}
	if p.UserIP != redactedValue {
		t.Errorf("UserIP = %q after idempotent call", p.UserIP)
	}
}

// ---------------------------------------------------------------------------
// Integration: redaction applied before events leave the host
// ---------------------------------------------------------------------------

// TestLogTailerRun_RedactsBeforeSend verifies that redactPayload is called
// before events are batched and sent to the API. It injects a "Failed
// password" sshd line where the "username" is P@ssword (password-like) and
// the source IP is 192.168.1.1 (private RFC-1918). Neither should appear in
// the payload received by the mock server.
func TestLogTailerRun_RedactsBeforeSend(t *testing.T) {
	origInterval := batchFlushInterval
	batchFlushInterval = 150 * time.Millisecond
	defer func() { batchFlushInterval = origInterval }()

	var (
		mu     sync.Mutex
		events []IngestPayload
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var batch BatchPayload
		_ = json.NewDecoder(r.Body).Decode(&batch)
		mu.Lock()
		events = append(events, batch.Events...)
		mu.Unlock()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()

	dir := t.TempDir()
	logFile := dir + "/auth.log"
	if err := os.WriteFile(logFile, []byte{}, 0600); err != nil {
		t.Fatalf("create log file: %v", err)
	}

	cfg := &Config{APIEndpoint: srv.URL, HeartbeatInterval: 60}
	lt := NewLogTailer(cfg, "lsoc_live_testkey", WatcherCfg{Path: logFile, Type: "sshd"})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = lt.Run(ctx) }()
	time.Sleep(80 * time.Millisecond)

	// Line with a password-as-username and a private source IP.
	f, err := os.OpenFile(logFile, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatalf("open log file: %v", err)
	}
	_, _ = f.WriteString("Apr 11 12:00:01 host sshd[1]: Failed password for P@ssword from 192.168.1.1 port 22 ssh2\n")
	_ = f.Close()

	deadline := time.After(3 * time.Second)
	for {
		mu.Lock()
		n := len(events)
		mu.Unlock()
		if n >= 1 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("timed out waiting for redacted event")
		case <-time.After(50 * time.Millisecond):
		}
	}

	mu.Lock()
	got := events[0]
	mu.Unlock()

	if got.Actor != nil && got.Actor.ID != redactedValue {
		t.Errorf("Actor.ID = %q; want %q (password-like username not redacted)", got.Actor.ID, redactedValue)
	}
	if got.UserIP != redactedValue {
		t.Errorf("UserIP = %q; want %q (private IP not redacted)", got.UserIP, redactedValue)
	}
}
