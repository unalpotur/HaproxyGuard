#!/usr/bin/env bash
# HAProxy Guard — Remote node bootstrap script
#
# Deployed via SSH or run manually.  Installs the Guard agent + Docker HAProxy
# on the target machine.
#
# Usage:
#   curl -s .../bootstrap.sh | sudo bash -s -- <GUARD_URL> <NODE_TOKEN> <NODE_ID>
#
set -euo pipefail

GUARD_URL="${1:-http://localhost:7000}"
NODE_TOKEN="${2:-}"
NODE_ID="${3:-}"

echo "=== HAProxy Guard Bootstrap ==="
echo "  Guard URL : $GUARD_URL"
echo "  Node ID   : $NODE_ID"

# ── Prerequisites ───────────────────────────────────────────────────────
echo "[1/5] Checking prerequisites..."

command -v docker >/dev/null 2>&1 || {
    echo "Docker not found. Install: https://docs.docker.com/engine/install/"
    exit 1
}
docker compose version >/dev/null 2>&1 || {
    echo "Docker Compose v2 required."
    exit 1
}
ok() { echo "  ✓ $*"; }

ok "docker: $(docker --version 2>/dev/null)"
ok "docker compose: $(docker compose version 2>/dev/null | head -1)"

# ── Stop system haproxy ─────────────────────────────────────────────────
echo "[2/5] Handling existing HAProxy..."

if systemctl is-active --quiet haproxy 2>/dev/null; then
    echo "  Stopping systemctl haproxy..."
    systemctl stop haproxy
    systemctl disable haproxy 2>/dev/null || true
    ok "systemctl haproxy stopped & disabled"
else
    ok "no systemctl haproxy running"
fi

# ── Create directories ──────────────────────────────────────────────────
echo "[3/5] Creating /opt/haproxy-guard..."

mkdir -p /opt/haproxy-guard/certs
mkdir -p /etc/haproxy

# ── Create default haproxy config if missing ─────────────────────────────
if [[ ! -f /etc/haproxy/haproxy.cfg ]]; then
    cat > /etc/haproxy/haproxy.cfg << 'EOF'
global
    log stdout format raw local0
    stats socket ipv4@0.0.0.0:9999 level admin
    stats timeout 30s
    nbthread 2
    maxconn 4096

defaults
    mode http
    log global
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend web
    bind *:80
    default_backend app

backend app
    # Add servers via Guard UI
EOF
    ok "default haproxy.cfg created"
else
    ok "haproxy.cfg exists ($(wc -l < /etc/haproxy/haproxy.cfg) lines)"
fi

# ── Start Docker HAProxy ────────────────────────────────────────────────
echo "[4/5] Starting Docker HAProxy..."

docker rm -f haproxy-prod 2>/dev/null || true

docker run -d \
    --name haproxy-prod \
    --network host \
    --restart unless-stopped \
    -v /etc/haproxy:/usr/local/etc/haproxy:ro \
    -v /opt/haproxy-guard/certs:/opt/haproxy-guard/certs:ro \
    --user root haproxy:2.9-alpine

ok "haproxy-prod container running"

# ── Agent env ───────────────────────────────────────────────────────────
echo "[5/5] Installing agent..."

cat > /opt/haproxy-guard/agent.env << AGENTENV
GUARD_URL=$GUARD_URL
NODE_ID=$NODE_ID
NODE_TOKEN=$NODE_TOKEN
MANAGE_MODE=docker
CONTAINER_NAME=haproxy-prod
HAPROXY_CFG=/etc/haproxy/haproxy.cfg
CERT_DIR=/opt/haproxy-guard/certs
AGENTENV

# Copy agent script (assumed already present in same dir as this bootstrap)
if [[ -f ./haproxy_guard_agent.py ]]; then
    cp ./haproxy_guard_agent.py /opt/haproxy-guard/
    ok "agent copied"
fi

# ── systemd service ─────────────────────────────────────────────────────
cat > /etc/systemd/system/haproxy-guard-agent.service << 'UNIT'
[Unit]
Description=HAProxy Guard host agent
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=/opt/haproxy-guard/agent.env
ExecStart=/usr/bin/python3 /opt/haproxy-guard/haproxy_guard_agent.py
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now haproxy-guard-agent
ok "agent service installed and running"

echo ""
echo "=== Bootstrap complete ==="
echo "  HAProxy  : docker (network_mode: host, ports 80/443/9999)"
echo "  Agent    : systemctl haproxy-guard-agent"
echo "  Logs     : journalctl -u haproxy-guard-agent -f"
