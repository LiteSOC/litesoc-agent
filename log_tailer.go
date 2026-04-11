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

	for {
		select {
		case <-ctx.Done():
			return nil
		case line, ok := <-src.lines:
			if !ok {
				return nil
			}
			if line.Err != nil {
				slog.Warn("tail read error", "path", lt.watcher.Path, "error", line.Err)
				continue
			}
			if event := lt.parseLine(line.Text); event != nil {
				if err := lt.sendEvent(ctx, event); err != nil {
					slog.Warn("failed to send event",
						"event", event.Event,
						"user_ip", event.UserIP,
						"error", err,
					)
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

// sendEvent POSTs a single event to the LiteSOC Ingestion API.
// The API key is transmitted only in the request header — never logged.
func (lt *LogTailer) sendEvent(ctx context.Context, payload *IngestPayload) error {
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
