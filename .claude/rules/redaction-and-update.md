---
title: Redaction & Self-Update Integrity
scope: litesoc-agent
applies_to:
  - "redact.go"
  - "log_tailer.go"
  - "updater.go"
  - "main.go"
  - "install.sh"
---

# Redaction & Self-Update Integrity

- **Redaction runs first.** `redact.go` MUST execute before any payload leaves the host — never send
  raw passwords or private/internal source IPs. Any change touching parsing or redaction must run
  the redaction tests: `go test ./... -race`.
- **API key handling.** The key comes **only** from `LITESOC_KEY` and must never be logged or written
  anywhere except the `0600` `/etc/litesoc/agent.env`.
- **Self-update integrity — fail closed.** Require SHA-256 verification of the downloaded archive; a
  missing or undownloadable `checksum_url` must be treated as a **failure**, not a pass. Prefer
  adding a real cryptographic **signature** (the checksum URL arrives via the same heartbeat
  response and is not sufficient on its own).
- **Least privilege.** Keep the hardened systemd unit intact (`NoNewPrivileges`,
  `ProtectSystem=strict`, `PrivateTmp`, `MemoryMax=32M`, `CPUQuota=5%`) and the low-priv `litesoc`
  user.
- **Housekeeping.** Update the stale `updater.go` comment referencing the retired sudoers/cp
  mechanism.
- **Contract.** Keep the ingestion payload aligned with the `api.litesoc.io` **snake_case** contract;
  emit only supported event names; the server assigns `severity`/`timestamp`.
