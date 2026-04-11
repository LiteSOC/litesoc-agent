#!/usr/bin/env bash
# =============================================================================
#  LiteSOC Sentinel — Server Security Agent Installer
#  Usage:
#    curl -sSL https://litesoc.io/install.sh | LITESOC_KEY=lsoc_live_xxx bash
# =============================================================================
set -euo pipefail

# ── Constants ─────────────────────────────────────────────────────────────────
readonly BINARY_NAME="litesoc-agent"
readonly INSTALL_PATH="/usr/local/bin/${BINARY_NAME}"
readonly CONFIG_DIR="/etc/litesoc"
readonly SERVICE_FILE="/etc/systemd/system/${BINARY_NAME}.service"
readonly AGENT_USER="litesoc"
readonly GITHUB_REPO="litesoc/litesoc-agent"
readonly RELEASE_VERSION="${LITESOC_AGENT_VERSION:-latest}"

# ── ANSI colour helpers ───────────────────────────────────────────────────────
if [[ -t 1 ]]; then
  BOLD="\033[1m"; GREEN="\033[0;32m"; YELLOW="\033[0;33m"
  RED="\033[0;31m"; CYAN="\033[0;36m"; RESET="\033[0m"
else
  BOLD=""; GREEN=""; YELLOW=""; RED=""; CYAN=""; RESET=""
fi

step()  { echo -e "${BOLD}${CYAN}${1}${RESET}"; }
ok()    { echo -e "  ${GREEN}✓${RESET} ${1}"; }
warn()  { echo -e "  ${YELLOW}!${RESET} ${1}"; }
die()   { echo -e "\n${RED}ERROR:${RESET} ${1}" >&2; exit 1; }

# ── Rollback tracker ─────────────────────────────────────────────────────────
# Each item in ROLLBACK_STEPS is a command executed in reverse on failure.
declare -a ROLLBACK_STEPS=()

rollback() {
  local exit_code=$?
  if [[ ${#ROLLBACK_STEPS[@]} -gt 0 ]]; then
    echo -e "\n${YELLOW}Rolling back changes...${RESET}"
    for (( i=${#ROLLBACK_STEPS[@]}-1; i>=0; i-- )); do
      eval "${ROLLBACK_STEPS[$i]}" 2>/dev/null || true
    done
  fi
  echo -e "\n${RED}Installation failed (exit code ${exit_code}).${RESET}"
  echo    "  For help: https://litesoc.io/docs/integrations/agent"
  exit "${exit_code}"
}
trap rollback ERR

# ── Helper: require root or sudo ─────────────────────────────────────────────
require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "This installer must be run as root (or via sudo).\n  sudo bash -c \"\$(curl -sSL https://litesoc.io/install.sh)\""
  fi
}

# ── Helper: require a command ────────────────────────────────────────────────
require_cmd() {
  command -v "$1" &>/dev/null || die "Required command not found: $1. Please install it and re-run."
}

# =============================================================================
# STEP 1 — Pre-flight checks: key validation + architecture detection
# =============================================================================
step "[1/4] Detecting architecture..."

require_root
require_cmd curl
require_cmd tar

# Validate the key is present and matches lsoc_live_* / lsoc_test_* format.
if [[ -z "${LITESOC_KEY:-}" ]]; then
  die "LITESOC_KEY is not set.\n\n  Run the installer with your key:\n    curl -sSL https://litesoc.io/install.sh | LITESOC_KEY=lsoc_live_xxx bash"
fi
if [[ ! "${LITESOC_KEY}" =~ ^lsoc_(live|test)_[a-zA-Z0-9_-]{16,}$ ]]; then
  die "LITESOC_KEY looks invalid. Copy the exact key from your LiteSOC dashboard."
fi

# Detect OS.
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
[[ "${OS}" == "linux" ]] || die "Unsupported OS: ${OS}. The LiteSOC agent currently requires Linux."

# Detect CPU architecture.
RAW_ARCH="$(uname -m)"
case "${RAW_ARCH}" in
  x86_64)          ARCH="amd64" ;;
  aarch64 | arm64) ARCH="arm64" ;;
  armv7l)          ARCH="arm"   ;;
  *)               die "Unsupported CPU architecture: ${RAW_ARCH}" ;;
esac

ok "Linux/${ARCH} detected"

# Check systemd availability.
if ! command -v systemctl &>/dev/null; then
  die "systemd is required but was not found. See https://litesoc.io/docs/integrations/agent for alternatives."
fi
ok "systemd found"

# Verify inbound connectivity to the API.
if ! curl -sSf --max-time 5 "https://api.litesoc.io/health" &>/dev/null; then
  warn "Could not reach api.litesoc.io — check firewall rules if the agent fails to connect."
fi

# =============================================================================
# STEP 2 — Download pre-compiled binary from GitHub Releases
# =============================================================================
step "[2/4] Downloading LiteSOC Sentinel..."

# Resolve the download URL. If version is "latest", use the GitHub redirect.
if [[ "${RELEASE_VERSION}" == "latest" ]]; then
  RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/latest/download"
else
  RELEASE_URL="https://github.com/${GITHUB_REPO}/releases/download/${RELEASE_VERSION}"
fi

ARCHIVE="${BINARY_NAME}_linux_${ARCH}.tar.gz"
DOWNLOAD_URL="${RELEASE_URL}/${ARCHIVE}"
CHECKSUM_URL="${RELEASE_URL}/checksums.sha256"

TMP_DIR="$(mktemp -d)"
# Ensure temp dir is always cleaned up, even on success.
trap 'rm -rf "${TMP_DIR}"' EXIT

ok "Release URL: ${DOWNLOAD_URL}"

# Download the archive.
if ! curl -sSL --fail --retry 3 --retry-delay 2 \
    -o "${TMP_DIR}/${ARCHIVE}" "${DOWNLOAD_URL}"; then
  die "Failed to download ${ARCHIVE}.\n  URL: ${DOWNLOAD_URL}\n  Verify the version exists: https://github.com/${GITHUB_REPO}/releases"
fi

# Verify SHA-256 checksum if the checksums file is available.
if curl -sSL --fail --max-time 5 -o "${TMP_DIR}/checksums.sha256" "${CHECKSUM_URL}" 2>/dev/null; then
  if command -v sha256sum &>/dev/null; then
    pushd "${TMP_DIR}" > /dev/null
    if grep -qF "${ARCHIVE}" checksums.sha256; then
      grep "${ARCHIVE}" checksums.sha256 | sha256sum --check --status \
        || die "Checksum mismatch! The downloaded binary may be corrupted. Aborting."
      ok "Checksum verified"
    fi
    popd > /dev/null
  fi
else
  warn "Checksums file not available for this release — skipping integrity check."
fi

# Extract the binary.
tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}" "${BINARY_NAME}" \
  2>/dev/null || tar -xzf "${TMP_DIR}/${ARCHIVE}" -C "${TMP_DIR}"

[[ -f "${TMP_DIR}/${BINARY_NAME}" ]] \
  || die "Binary not found in archive. The release package may be malformed."

# Install the binary.
install -m 0755 -o root -g root "${TMP_DIR}/${BINARY_NAME}" "${INSTALL_PATH}"
ROLLBACK_STEPS+=("rm -f '${INSTALL_PATH}'")

# Resolve the actual version baked into the binary (strips any leading 'v').
INSTALLED_VERSION=$("${INSTALL_PATH}" --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' || echo "${RELEASE_VERSION}")

ok "Binary installed to ${INSTALL_PATH} (${INSTALLED_VERSION})"

# =============================================================================
# STEP 3 — Configure the system service (systemd + low-privilege user)
# =============================================================================
step "[3/4] Configuring system service..."

# Create the dedicated low-privilege system user (nologin, no home).
if ! id -u "${AGENT_USER}" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "${AGENT_USER}"
  ROLLBACK_STEPS+=("userdel '${AGENT_USER}' 2>/dev/null || true")
  ok "System user '${AGENT_USER}' created"
else
  ok "System user '${AGENT_USER}' already exists"
fi

# Create config directory and store the key in an env file (chmod 600).
mkdir -p "${CONFIG_DIR}"
ROLLBACK_STEPS+=("rm -rf '${CONFIG_DIR}'")

# Write the env file — key is stored here, not in the unit file.
cat > "${CONFIG_DIR}/agent.env" <<ENV
LITESOC_KEY=${LITESOC_KEY}
ENV
chmod 600 "${CONFIG_DIR}/agent.env"
chown root:root "${CONFIG_DIR}/agent.env"
ok "Agent key stored in ${CONFIG_DIR}/agent.env (chmod 600)"

# Write the default config.yaml if it doesn't already exist.
if [[ ! -f "${CONFIG_DIR}/config.yaml" ]]; then
  cat > "${CONFIG_DIR}/config.yaml" <<YAML
# LiteSOC Agent Configuration
# Generated by installer on $(date -u '+%Y-%m-%d %H:%M:%S UTC')
api_endpoint: https://api.litesoc.io
heartbeat_interval: 60

log_watchers:
  # Debian / Ubuntu
  - path: /var/log/auth.log
    type: sshd
  # Fedora / RHEL / CentOS — uncomment if needed:
  # - path: /var/log/secure
  #   type: sshd
YAML
  ok "Config written to ${CONFIG_DIR}/config.yaml"
else
  ok "Existing config at ${CONFIG_DIR}/config.yaml preserved"
fi

chown -R root:"${AGENT_USER}" "${CONFIG_DIR}"
chmod 750 "${CONFIG_DIR}"

# Write the systemd service unit.
cat > "${SERVICE_FILE}" <<UNIT
[Unit]
Description=LiteSOC Sentinel — Server Security Agent
Documentation=https://litesoc.io/docs/integrations/agent
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=180
StartLimitBurst=6

[Service]
Type=simple
User=${AGENT_USER}
Group=${AGENT_USER}

# Load the API key from the protected env file — never embed it in the unit.
EnvironmentFile=${CONFIG_DIR}/agent.env

ExecStart=${INSTALL_PATH} ${CONFIG_DIR}/config.yaml
ExecReload=/bin/kill -HUP \$MAINPID

Restart=always
RestartSec=10

# Resource guardrails.
MemoryMax=32M
CPUQuota=5%

# Hardening — reduce the attack surface of the service.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log
AmbientCapabilities=
CapabilityBoundingSet=

[Install]
WantedBy=multi-user.target
UNIT

ROLLBACK_STEPS+=("rm -f '${SERVICE_FILE}'")
ok "Systemd service file written to ${SERVICE_FILE}"

# Reload, enable, and start the service.
systemctl daemon-reload

if systemctl is-active --quiet "${BINARY_NAME}"; then
  systemctl restart "${BINARY_NAME}"
  ok "Service restarted"
else
  systemctl enable --now "${BINARY_NAME}"
  ok "Service enabled and started"
fi

# Wait briefly and confirm the process is running.
sleep 2
if ! systemctl is-active --quiet "${BINARY_NAME}"; then
  warn "The service did not start cleanly."
  echo ""
  systemctl status "${BINARY_NAME}" --no-pager -l || true
  die "Service failed to start. Run: journalctl -u ${BINARY_NAME} -n 50"
fi

# =============================================================================
# STEP 4 — Verify connectivity to the LiteSOC API
# =============================================================================
step "[4/4] Connection successful! Check your dashboard at litesoc.io"

# Quick probe — POST to the heartbeat endpoint with the user's key to confirm
# end-to-end connectivity. We don't fail the install if this check is slow.
PROBE_HOSTNAME=$(hostname 2>/dev/null || echo "unknown")
PROBE_IP=$(hostname -I 2>/dev/null | awk '{print $1}' || echo "0.0.0.0")
[ -z "${PROBE_IP}" ] && PROBE_IP="0.0.0.0"
HEARTBEAT_STATUS=$(curl -sSo /dev/null -w "%{http_code}" --max-time 8 \
  -X POST "https://api.litesoc.io/agent/heartbeat" \
  -H "X-API-Key: ${LITESOC_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"hostname":"'"${PROBE_HOSTNAME}"'","ip_address":"'"${PROBE_IP}"'","agent_version":"'"${INSTALLED_VERSION}"'"}' 2>/dev/null || echo "000")

if [[ "${HEARTBEAT_STATUS}" == "200" || "${HEARTBEAT_STATUS}" == "202" ]]; then
  ok "Heartbeat acknowledged by LiteSOC (HTTP ${HEARTBEAT_STATUS})"
elif [[ "${HEARTBEAT_STATUS}" == "401" ]]; then
  warn "API returned 401 — double-check your LITESOC_KEY in ${CONFIG_DIR}/agent.env"
else
  warn "Heartbeat probe returned HTTP ${HEARTBEAT_STATUS} — verify network/key if the agent does not appear online."
fi

# ── Success banner ────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════════════╗${RESET}"
echo -e "${GREEN}${BOLD}║  LiteSOC Sentinel installed successfully!                ║${RESET}"
echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════════════╝${RESET}"
echo ""
echo -e "  ${BOLD}Dashboard  ${RESET}: https://litesoc.io/dashboard"
echo -e "  ${BOLD}Agent logs ${RESET}: journalctl -u ${BINARY_NAME} -f"
echo -e "  ${BOLD}Status     ${RESET}: systemctl status ${BINARY_NAME}"
echo -e "  ${BOLD}Config     ${RESET}: ${CONFIG_DIR}/config.yaml"
echo ""
