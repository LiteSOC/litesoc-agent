# CLAUDE.md — litesoc-agent

> Repo-specific guide. Read the workspace root [`../CLAUDE.md`](../CLAUDE.md) first for mission,
> Golden Rules, and the shared agents in `../.claude/agents/` (integration-reviewer, backend,
> security, test-runner, bug-investigator, …) and rules in `../.claude/rules/`. **Do not redefine
> root agents or root rules here** — this file only complements them.

## Purpose
**Go host agent** that tails system auth logs (sshd), parses OpenSSH events, and streams SSH
security events in real time to the LiteSOC ingestion API. Event-driven (inotify/kqueue, **zero
polling**). Ships as a single static binary + systemd unit with an adaptive heartbeat.

## Technology stack
- **Go 1.22**, module `github.com/litesoc/litesoc-agent`.
- Deps: `github.com/nxadm/tail v1.4.11`, `gopkg.in/yaml.v3`.
- Logging: `slog` (JSON). Lint: `golangci-lint`.

## Key files
- `main.go` — entrypoint, config load, adaptive heartbeat, goroutine orchestration.
- `log_tailer.go` — tail + sshd regex parsing + batch send.
- `redact.go` — redaction (see security paths).
- `updater.go` — self-update.
- `config.yaml` — runtime config.
- Tests: `main_test.go`, `log_tailer_test.go`, `redact_test.go`, `updater_test.go`, `bench_test.go`
  (`coverage.out` present). `install.sh` provisions the host.

## Commands
Makefile (verbatim): `make build` (go build, `LDFLAGS -X main.agentVersion`),
`make build-all` / `build-linux` / `build-darwin` (cross-compile amd64/arm64/arm),
`make release-archives`, `make tidy` (`go mod tidy`), `make test` (`go test -v -race ./...`),
`make install` (`sudo install -m 0755 bin/litesoc-agent /usr/local/bin/`), `make clean`.

Also: `go test ./... -count=1`; coverage `go test ./... -coverprofile=coverage.out` then
`go tool cover -func`; race `-race`; lint `golangci-lint run ./...`; bench `go test ./... -bench=.`.

## Architecture & boundaries
- Endpoints (base from config `api_endpoint`, default `https://api.litesoc.io`):
  - `POST /collect/batch` — primary; batches of 50 or every 20s.
  - `POST /collect` — single event.
  - `POST /agent/heartbeat`.
- Headers: `X-API-Key` + `User-Agent: litesoc-agent/<version>`.
- Parsed events: `auth.login_failed`, `auth.login_success`, `auth.logout`.
- Heartbeat is **adaptive**: 60s active / 5min idle; carries hostname, outbound IP,
  `agent_version`, and a ring buffer of `recent_logs`. The heartbeat response may include an
  `update` object (drives self-update).
- The **server** assigns `severity`/`timestamp`; emit only supported event names. Keep the
  ingestion payload aligned with the `api.litesoc.io` **snake_case** contract.

## External dependencies
- `https://api.litesoc.io` (`/collect`, `/collect/batch`, `/agent/heartbeat`).
- Self-update download host + `checksum_url` (both surfaced via the heartbeat `update` object).

## Environment variables / config
- API key **only** from env `LITESOC_KEY` (format `lsoc_(live|test)_...`). `install.sh` writes it to
  `/etc/litesoc/agent.env` (chmod `600`).
- `config.yaml` keys (names only): `api_endpoint`, `heartbeat_interval`,
  `log_watchers[]` (`path`, `type=sshd`).

## Security-sensitive code paths
- `redact.go` — masks password-like `Actor.ID` → `[REDACTED]` and nullifies private/internal source
  IPs → `[REDACTED]`, applied **before** any payload leaves the host.
- API key is **never logged** (slog JSON) and lives only in `LITESOC_KEY` / the `0600` `agent.env`.
- `updater.go` self-update verifies the **SHA-256** of the downloaded archive against `checksum_url`.
- `install.sh` — creates a low-priv `litesoc` user and a hardened systemd unit
  (`NoNewPrivileges`, `ProtectSystem=strict`, `PrivateTmp`, `MemoryMax=32M`, `CPUQuota=5%`).
- **KNOWN soft spots — flag on sight:**
  - (a) If `checksum_url` is empty/unavailable the update currently proceeds **without** verification,
    and there is **no cryptographic signature** (only a checksum whose URL comes from the same
    heartbeat response). Prefer fail-closed + a real signature.
  - (b) A stale comment in `updater.go` references a sudoers/cp mechanism **no longer used** — fix it.

## Database / migration responsibility
None. No schema or migrations.

## Deployment / distribution target
Single static Go binary distributed via `make release-archives` and installed by `install.sh`
(systemd service + `/usr/local/bin/litesoc-agent`). CI lives under `.github/`.

## Cross-repository consumers & dependencies
- Producer of ingestion events consumed by `api.litesoc.io` (`/collect`, `/collect/batch`) and
  `/agent/heartbeat` (the `lsoc_app` contract).
- Keep event names and payload shape in sync with the `lsoc_app` contract and `litesoc-docs`.

## Repo-specific rules & skills pointer
- Local rule: [`.claude/rules/redaction-and-update.md`](.claude/rules/redaction-and-update.md).
- Root rules/skills apply — see `../.claude/rules/` and `../.claude/skills/`.
