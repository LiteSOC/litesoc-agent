package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/nxadm/tail"
)

// LiteSOC standard event names covered by this agent.
const (
	eventAuthLoginFailed  = "auth.login_failed"
	eventAuthLoginSuccess = "auth.login_success"
	eventAuthLogout       = "auth.logout"
)

// batchSize is the number of buffered events that triggers an immediate flush.
const batchSize = 50

// batchFlushInterval is the maximum time events are held in the buffer before
// being sent. Overridable in tests.
var batchFlushInterval = 20 * time.Second

// Compiled regexes for /var/log/auth.log (syslog sshd format).
//
// Patterns match the most common OpenSSH log lines across Debian, Ubuntu,
// RHEL, Fedora, and Alpine. IPv6 addresses (colons) are included in the IP
// character class so dual-stack hosts are captured correctly.
var (
	// "Failed password for [invalid user] <user> from <ip> port <port>"
	reFailedPassword = regexp.MustCompile(
		`Failed password for (?:invalid user )?(\S+) from ([\d.:a-f]+) port (\d+)`,
	)

	// "Invalid user <user> from <ip> port <port>"
	reInvalidUser = regexp.MustCompile(
		`Invalid user (\S+) from ([\d.:a-f]+) port (\d+)`,
	)

	// "Accepted (password|publickey|gssapi-with-mic|...) for <user> from <ip> port <port>"
	reAccepted = regexp.MustCompile(
		`Accepted \S+ for (\S+) from ([\d.:a-f]+) port (\d+)`,
	)

	// "Disconnected from [authenticating user|invalid user|user] <user> <ip> port <port>"
	reDisconnected = regexp.MustCompile(
		`Disconnected from (?:(?:authenticating user|invalid user|user) (\S+) )?([\d.:a-f]+) port (\d+)`,
	)
)

// IngestPayload is the JSON body sent to api.litesoc.io/collect.
// Field names follow the LiteSOC snake_case API contract.
type IngestPayload struct {
	Event    string         `json:"event"`
	UserIP   string         `json:"user_ip,omitempty"`
	Actor    *IngestActor   `json:"actor,omitempty"`
	Metadata map[string]any `json:"metadata,omitempty"`
}

// IngestActor carries the subject identity of the security event.
type IngestActor struct {
	ID string `json:"id,omitempty"`
}

// BatchPayload is the JSON body sent to api.litesoc.io/collect/batch.
type BatchPayload struct {
	Events []IngestPayload `json:"events"`
}

// LogTailer follows a single log file and forwards parsed events to LiteSOC.
type LogTailer struct {
	cfg     *Config
	apiKey  string
	watcher WatcherCfg
	client  *http.Client
}

// NewLogTailer creates a LogTailer for the given watcher configuration.
func NewLogTailer(cfg *Config, apiKey string, watcher WatcherCfg) *LogTailer {
	return &LogTailer{
		cfg:     cfg,
		apiKey:  apiKey,
		watcher: watcher,
		// Shared HTTP client: keep-alive enabled, hard timeout per request.
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// tailSrc wraps the nxadm/tail library so Run can be unit-tested with mock
// log lines without a real file system.
type tailSrc struct {
	lines chan *tail.Line
	stop  func()
	clean func()
}

// newTailSrc is a package-level variable so tests can inject a mock tailer.
var newTailSrc = func(path string, cfg tail.Config) (*tailSrc, error) {
	t, err := tail.TailFile(path, cfg)
	if err != nil {
		return nil, err
	}
	return &tailSrc{
		lines: t.Lines,
		stop:  func() { _ = t.Stop() },
		clean: t.Cleanup,
	}, nil
}

// Run tails the log file and blocks until ctx is cancelled or a fatal error
// occurs. It handles log rotation via ReOpen and uses inotify (not polling)
// to keep CPU usage negligible.
//
// Parsed events are buffered in memory and sent as a batch to /collect/batch
// whenever the buffer reaches batchSize (50) OR batchFlushInterval (20 s)
// elapses — whichever comes first. This reduces per-event HTTP overhead and
// API costs significantly under normal load.
func (lt *LogTailer) Run(ctx context.Context) error {
	src, err := newTailSrc(lt.watcher.Path, tail.Config{
		Follow:    true,
		ReOpen:    true,  // survive logrotate
		MustExist: false, // wait for the file if it doesn't exist yet
		Logger:    tail.DiscardingLogger,
	})
	if err != nil {
		return fmt.Errorf("tail %s: %w", lt.watcher.Path, err)
	}
	defer src.stop()
	defer src.clean()

	slog.Info("watching log file", "path", lt.watcher.Path, "type", lt.watcher.Type)

	var buffer []IngestPayload
	ticker := time.NewTicker(batchFlushInterval)
	defer ticker.Stop()

	// flush sends all buffered events as a single batch request and resets
	// the buffer. fctx allows callers to use a different context for the
	// final shutdown flush after the main ctx has been cancelled.
	flush := func(fctx context.Context) {
		if len(buffer) == 0 {
			return
		}
		batch := BatchPayload{Events: buffer}
		buffer = nil
		if err := lt.sendBatch(fctx, batch); err != nil {
			slog.Warn("failed to send batch",
				"count", len(batch.Events),
				"error", err,
			)
		}
	}

	for {
		select {
		case <-ctx.Done():
			// Best-effort: deliver any buffered events before exiting.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			flush(shutdownCtx)
			return nil

		case <-ticker.C:
			flush(ctx)

		case line, ok := <-src.lines:
			if !ok {
				flush(ctx)
				return nil
			}
			if line.Err != nil {
				slog.Warn("tail read error", "path", lt.watcher.Path, "error", line.Err)
				continue
			}
			if event := lt.parseLine(line.Text); event != nil {
				// Stamp source hostname once here so every event in the
				// batch already carries it (sendBatch does not re-stamp).
				if event.Metadata == nil {
					event.Metadata = make(map[string]any)
				}
				event.Metadata["source_hostname"] = getHostname()
				pushRecentLog(line.Text)
				markActivity() // signal runHeartbeat to use the active interval
				buffer = append(buffer, *event)
				if len(buffer) >= batchSize {
					flush(ctx)
				}
			}
		}
	}
}

// parseLine dispatches to the correct parser based on watcher type.
// Defaults to sshd for unknown types so that a bare auth.log path still works.
func (lt *LogTailer) parseLine(line string) *IngestPayload {
	switch lt.watcher.Type {
	case "sshd", "":
		return parseSSHDLine(line, lt.watcher.Path)
	default:
		slog.Debug("unknown watcher type, defaulting to sshd", "type", lt.watcher.Type)
		return parseSSHDLine(line, lt.watcher.Path)
	}
}

// parseSSHDLine extracts a structured IngestPayload from a single syslog line
// produced by OpenSSH. Returns nil if the line is not actionable.
func parseSSHDLine(line, logPath string) *IngestPayload {
	meta := func(reason, port string) map[string]any {
		m := map[string]any{
			"source":   "sshd",
			"log_file": logPath,
		}
		if reason != "" {
			m["reason"] = reason
		}
		if port != "" {
			m["port"] = port
		}
		return m
	}

	// Priority: failed password > invalid user > accepted > disconnected.
	// "Invalid user" lines often precede a "Failed password" for the same
	// attempt — we prefer "Failed password" because it carries the reason.
	if m := reFailedPassword.FindStringSubmatch(line); m != nil {
		return &IngestPayload{
			Event:    eventAuthLoginFailed,
			UserIP:   m[2],
			Actor:    &IngestActor{ID: m[1]},
			Metadata: meta("failed_password", m[3]),
		}
	}

	if m := reInvalidUser.FindStringSubmatch(line); m != nil {
		return &IngestPayload{
			Event:    eventAuthLoginFailed,
			UserIP:   m[2],
			Actor:    &IngestActor{ID: m[1]},
			Metadata: meta("invalid_user", m[3]),
		}
	}

	if m := reAccepted.FindStringSubmatch(line); m != nil {
		return &IngestPayload{
			Event:    eventAuthLoginSuccess,
			UserIP:   m[2],
			Actor:    &IngestActor{ID: m[1]},
			Metadata: meta("", m[3]),
		}
	}

	if m := reDisconnected.FindStringSubmatch(line); m != nil {
		user := m[1]
		if user == "" {
			user = "unknown"
		}
		return &IngestPayload{
			Event:    eventAuthLogout,
			UserIP:   m[2],
			Actor:    &IngestActor{ID: user},
			Metadata: meta("", m[3]),
		}
	}

	return nil
}

// sendBatch POSTs a slice of events to the LiteSOC Batch Ingestion endpoint.
// Events must already have source_hostname stamped before calling this.
func (lt *LogTailer) sendBatch(ctx context.Context, batch BatchPayload) error {
	body, err := marshalJSON(batch)
	if err != nil {
		return fmt.Errorf("marshal batch: %w", err)
	}

	url := lt.cfg.APIEndpoint + "/collect/batch"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build batch request: %w", err)
	}
	req.Header.Set("X-API-Key", lt.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "litesoc-agent/"+agentVersion)

	resp, err := lt.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from batch ingestion API", resp.StatusCode)
	}

	slog.Debug("batch forwarded", "count", len(batch.Events))
	return nil
}

// sendEvent POSTs a single event to the LiteSOC Ingestion API.
// The API key is transmitted only in the request header — never logged.
func (lt *LogTailer) sendEvent(ctx context.Context, payload *IngestPayload) error {
	// Stamp source hostname so the dashboard can show which server sent the event.
	if payload.Metadata == nil {
		payload.Metadata = make(map[string]any)
	}
	payload.Metadata["source_hostname"] = getHostname()

	body, err := marshalJSON(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	url := lt.cfg.APIEndpoint + "/collect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build request: %w", err)
	}
	req.Header.Set("X-API-Key", lt.apiKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "litesoc-agent/"+agentVersion)

	resp, err := lt.client.Do(req)
	if err != nil {
		return fmt.Errorf("http: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// 202 Accepted is the canonical success response from the ingestion API.
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("unexpected status %d from ingestion API", resp.StatusCode)
	}

	slog.Debug("event forwarded",
		"event", payload.Event,
		"user_ip", payload.UserIP,
	)
	return nil
}
