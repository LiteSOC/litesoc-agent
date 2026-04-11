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
curl -sSL https://get.litesoc.io/agent | LITESOC_AGENT_KEY=lsoc_live_xxx bash
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

> **Security note:** Your API key is **never** stored in the config file. It is read exclusively from the `LITESOC_AGENT_KEY` environment variable.

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
export LITESOC_AGENT_KEY=lsoc_live_your_key
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

```bash
# Run tests (100% coverage)
go test ./... -race

# Run with coverage report
go test ./... -coverprofile=coverage.out && go tool cover -html=coverage.out

# Lint (golangci-lint v2)
golangci-lint run ./...

# Benchmarks
go test ./... -run='^$' -bench=. -benchmem
```

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
