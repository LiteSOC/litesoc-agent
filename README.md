<div align="center">
  <img src="assets/LiteSoc.svg" alt="LiteSOC Logo" width="96" />
  <h1>litesoc-agent</h1>
  <p>Lightweight open-source server agent for LiteSOC — streams SSH security events in real-time.</p>

  ![Go Version](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)
  ![License](https://img.shields.io/badge/license-MIT-indigo)
  ![Coverage](https://img.shields.io/badge/coverage-100%25-brightgreen)
  ![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macOS-lightgrey)
</div>

---

## Overview

`litesoc-agent` runs as a background service on your servers. It tails system authentication logs (e.g. `/var/log/auth.log`, `/var/log/secure`), parses OpenSSH events, and forwards structured security events to the [LiteSOC](https://litesoc.io) ingestion API — **with zero polling overhead** using inotify / kqueue.

A periodic heartbeat keeps your dashboard server status accurate and alerts you if an agent goes silent.

---

## Features

| | |
|---|---|
| 🔍 **SSH brute-force detection** | Parses `sshd` lines and emits `auth.login_failed` / `auth.login_success` / `auth.logout` events |
| ⚡ **Real-time streaming** | Events reach `api.litesoc.io/collect` within milliseconds of the log line appearing |
| 💓 **Heartbeat** | Pings LiteSOC every 60 s to keep your server marked as "Active" |
| 🔄 **Log-rotation aware** | Handles `logrotate` via `ReOpen` — no missed events after rotation |
| 🛡️ **Systemd integration** | Ships with a service unit; auto-restarts on failure |
| 📦 **Zero runtime deps** | Single static binary — no runtime, interpreter, or sidecar required |
| 🏗️ **Multi-arch** | Pre-built for `linux/amd64`, `linux/arm64`, `linux/arm`, `darwin/amd64`, `darwin/arm64` |

---

## Quick Start

### One-Line Install (Linux)

```bash
curl -sSL https://litesoc.io/install.sh | LITESOC_KEY=lsoc_live_xxx bash
```

The installer will:
1. Detect your OS and architecture
2. Download the pre-built binary from GitHub Releases
3. Write `/etc/litesoc/config.yaml` (skipped if already present)
4. Store your agent key securely in `/etc/litesoc/agent.env` (mode `0600`)
5. Install and enable a `systemd` service

### Requirements

- Linux (or macOS for local testing)
- `curl` and `tar`
- `systemd` (optional — for service management)
- A LiteSOC Agent API key (`lsoc_live_...`) from your [dashboard](https://app.litesoc.io)

---

## Configuration

The agent reads `/etc/litesoc/config.yaml` at startup.

> **Security note:** Your API key is **never** stored in the config file. It is read exclusively from the `LITESOC_KEY` environment variable.

```yaml
# /etc/litesoc/config.yaml

api_endpoint: https://api.litesoc.io
heartbeat_interval: 60   # seconds

log_watchers:
  # Debian / Ubuntu
  - path: /var/log/auth.log
    type: sshd

  # Fedora / RHEL / CentOS / Amazon Linux
  # - path: /var/log/secure
  #   type: sshd
```

| Field | Default | Description |
|---|---|---|
| `api_endpoint` | `https://api.litesoc.io` | LiteSOC ingestion base URL |
| `heartbeat_interval` | `60` | Heartbeat frequency in seconds |
| `log_watchers[].path` | — | Absolute path to the log file to tail |
| `log_watchers[].type` | — | Parser type. Currently: `sshd` |

---

## Building from Source

**Prerequisites:** Go 1.22+

```bash
# Clone
git clone https://github.com/litesoc/litesoc-agent.git
cd litesoc-agent

# Build for the current platform
make build
# → bin/litesoc-agent

# Cross-compile all release targets
make build-all

# Package .tar.gz archives (mirrors install.sh expectations)
make release-archives
```

---

## Running

### Manually

```bash
export LITESOC_KEY=lsoc_live_your_key
./bin/litesoc-agent /etc/litesoc/config.yaml
```

### systemd

```bash
# Check status
sudo systemctl status litesoc-agent

# Restart
sudo systemctl restart litesoc-agent

# Tail live logs
sudo journalctl -u litesoc-agent -f
```

---

## Development

**Prerequisites:** Go 1.22+, [golangci-lint v2](https://golangci-lint.run/welcome/install/)

### 1 — Tests

Run the full test suite:

```bash
go test ./... -count=1
```

Expected output:

```
ok  github.com/litesoc/litesoc-agent  1.5s
```

### 2 — Coverage

Generate a statement-level coverage report (100% required for all PRs):

```bash
go test ./... -coverprofile=coverage.out -count=1
go tool cover -func=coverage.out
```

Open an interactive HTML report in your browser:

```bash
go tool cover -html=coverage.out
```

Expected total:

```
total: (statements) 100.0%
```

### 3 — Race Detector

Verify there are no data races under concurrent execution:

```bash
go test ./... -race -count=1
```

All tests must pass with no `WARNING: DATA RACE` output.

### 4 — Linter

Run the full golangci-lint suite (mirrors CI):

```bash
golangci-lint run ./...
```

Expected output:

```
0 issues.
```

Key linters enabled: `errcheck`, `staticcheck`, `govet`, `unused`.

### 5 — Benchmarks

Measure the performance of hot-path functions (regex parsing, HTTP round-trips, YAML loading):

```bash
go test ./... -run='^$' -bench=. -benchmem -benchtime=3s
```

Sample output on Apple M4:

```
BenchmarkParseSSHDLine/FailedPassword-10    7722412    455 ns/op    562 B/op    8 allocs/op
BenchmarkParseSSHDLine/Irrelevant-10       21969438    169 ns/op      0 B/op    0 allocs/op
BenchmarkSendEvent-10                        109568  31463 ns/op   8152 B/op  101 allocs/op
BenchmarkLoadConfig-10                       207363  17271 ns/op  11672 B/op  129 allocs/op
```

> Irrelevant log lines exit with zero allocations — the fast-exit path is fully optimised.

---

## Contributing

Contributions are welcome! Please follow these steps:

1. **Fork** the repository and create a feature branch:
   ```bash
   git checkout -b feat/my-feature
   ```

2. **Make your changes** — keep commits small and focused.

3. **Run the full quality gate** before opening a PR:
   ```bash
   go test ./... -race -count=1                        # all tests + race detector
   go test ./... -coverprofile=coverage.out && \
     go tool cover -func=coverage.out | grep total     # must show 100.0%
   golangci-lint run ./...                             # must show 0 issues
   ```

4. **Open a Pull Request** against `main` with a clear description of what changed and why.

### Guidelines

- **Coverage:** Every new function or branch must be covered by a test. PRs that drop coverage below 100% will not be merged.
- **No `console.log`:** Use the structured `slog` logger — never `fmt.Println` or `log.Print`.
- **Naming:** Database/API payload keys use `snake_case`; Go variables use `camelCase`.
- **New log parsers:** Add a new `type` value to `WatcherCfg` and implement a `parse<Type>Line` function alongside `parseSSHDLine`. Register it in `parseLine`.
- **Security:** Never log or store the API key. It must only appear in request headers.

---

## Uninstall

```bash
sudo systemctl stop litesoc-agent
sudo systemctl disable litesoc-agent
sudo rm -f /usr/local/bin/litesoc-agent
sudo rm -rf /etc/litesoc
sudo rm -f /etc/systemd/system/litesoc-agent.service
sudo systemctl daemon-reload
```

---

## License

Open Source. See [LICENSE](../litesoc-node/LICENSE) for details.
