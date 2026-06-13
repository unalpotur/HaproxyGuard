#!/usr/bin/env bash
# HAProxy Guard — Interactive install script
#
# Guides the user through installation, asking whether HAProxy should be
# managed via systemctl (native) or Docker (container with host networking).
#
# Usage:
#   chmod +x scripts/install.sh
#   ./scripts/install.sh

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

banner() {
    echo
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}         HAProxy Guard — Kurulum Asistanı${NC}"
    echo -e "${CYAN}══════════════════════════════════════════════════════${NC}"
    echo
}

ok()   { echo -e "  ${GREEN}✓${NC} $*"; }
warn() { echo -e "  ${YELLOW}⚠${NC} $*"; }
fail() { echo -e "  ${RED}✗${NC} $*"; }
info() { echo -e "  ${CYAN}→${NC} $*"; }

die() {
    echo
    echo -e "${RED}HATA: $*${NC}"
    echo "Kurulum iptal edildi."
    exit 1
}

# ── Prerequisites ────────────────────────────────────────────────────────

banner

info "Ön gereksinimler kontrol ediliyor..."

command -v docker >/dev/null 2>&1 \
    || die "Docker kurulu değil. Kurun: https://docs.docker.com/engine/install/"

docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2+ gerekli. Kurun: https://docs.docker.com/compose/install/"

command -v python3 >/dev/null 2>&1 \
    || die "Python 3.11+ gerekli. 'sudo apt install python3' ile kurun."

command -v node >/dev/null 2>&1 \
    || warn "Node.js bulunamadı — frontend dev modu için gerekli (Docker kurulumda şart değil)"

ok "Docker       : $(docker --version 2>/dev/null)"
ok "Docker Compose: $(docker compose version 2>/dev/null | head -1)"
ok "Python       : $(python3 --version 2>/dev/null)"

# ── Env file ─────────────────────────────────────────────────────────────

ENV_FILE="$(cd "$(dirname "$0")/.." && pwd)/.env"

if [[ ! -f "$ENV_FILE" ]] || [[ ! -s "$ENV_FILE" ]]; then
    echo
    info ".env dosyası oluşturuluyor..."
    cat > "$ENV_FILE" << 'EOF'
# ── Database ──────────────────────────────────────────────────────────
# PostgreSQL Docker container kullanılır, bu satırı değiştirmeyin.

# ── Optional: AI Assistant ────────────────────────────────────────────
# ANTHROPIC_API_KEY=sk-ant-...

# ── Optional: RBAC Admin ──────────────────────────────────────────────
# HG_ADMIN_KEY=your-secure-admin-key

# ── Web UI / API port overrides ───────────────────────────────────────
# HG_WEB_PORT=8080
# HG_API_PORT=8000
EOF
    ok ".env dosyası oluşturuldu: $ENV_FILE"
else
    ok ".env zaten mevcut: $ENV_FILE"
fi

# Load .env so HG_API_PORT / HG_WEB_PORT are available.
set -a
# shellcheck disable=SC1090
source "$ENV_FILE" 2>/dev/null || true
set +a

# ── HAProxy mode selection ──────────────────────────────────────────────

echo
echo -e "${CYAN}── HAProxy Yönetim Modu ────────────────────────────────────${NC}"
echo
echo "  HAProxy iki şekilde yönetilebilir:"
echo
echo "  [1] systemctl  — Bu bilgisayarda kurulu HAProxy'yi sistem servisi"
echo "                   olarak kullanır. HAProxy zaten systemctl üzerinden"
echo "                   çalışıyor olmalı."
echo
echo "  [2] Docker     — HAProxy bir Docker konteynerinde çalışır."
echo "                   network_mode: host kullanır (port 80/443/9999)."
echo "                   Sistemdeki HAProxy varsa durdurulur."
echo

while true; do
    read -r -p "  Seçiminiz [1/systemctl | 2/docker]: " mode_choice
    case "${mode_choice,,}" in
        1|systemctl)
            MANAGE_MODE="systemd"
            break
            ;;
        2|docker)
            MANAGE_MODE="docker"
            break
            ;;
        *)
            warn "Lütfen 1/systemctl veya 2/docker girin"
            ;;
    esac
done

echo
info "Seçilen mod: ${GREEN}${MANAGE_MODE}${NC}"

# ── Docker modu: system HAProxy'yi durdur ───────────────────────────────

if [[ "$MANAGE_MODE" == "docker" ]]; then
    echo
    echo -e "${CYAN}── System HAProxy kontrolü ─────────────────────────────────${NC}"

    SYSTEM_HAPROXY_ACTIVE=false
    if systemctl is-active --quiet haproxy 2>/dev/null; then
        SYSTEM_HAPROXY_ACTIVE=true
        warn "Systemctl üzerinde HAProxy AKTİF durumda."

        echo
        echo "  Docker modu seçtiniz. System HAProxy DURDURULMALI yoksa"
        echo "  port çakışması olur (her ikisi de 80/443'e bağlanmaya çalışır)."
        echo
        read -r -p "  System HAProxy durdurulsun mu? [E/h]: " stop_choice

        if [[ "${stop_choice,,}" != "h" ]] && [[ "${stop_choice,,}" != "n" ]]; then
            info "HAProxy durduruluyor..."
            sudo systemctl stop haproxy
            ok "HAProxy durduruldu (systemctl stop haproxy)"

            read -r -p "  HAProxy boot'ta tekrar başlamasın mı (disable)? [E/h]: " disable_choice
            if [[ "${disable_choice,,}" != "h" ]] && [[ "${disable_choice,,}" != "n" ]]; then
                sudo systemctl disable haproxy 2>/dev/null || true
                ok "HAProxy disable edildi"
            else
                info "HAProxy enabled kaldı — Docker başlatmadan önce durdurmanız gerekir"
            fi
        else
            warn "System HAProxy durdurulmadı. Docker HAProxy başlatıldığında port çakışması olabilir!"
        fi
    else
        ok "Systemctl HAProxy zaten çalışmıyor — sorun yok"
    fi

    # ── HAProxy config yoksa oluştur ──────────────────────────────────────

    HAPROXY_CFG="${HAPROXY_CFG:-/etc/haproxy/haproxy.cfg}"
    if [[ ! -f "$HAPROXY_CFG" ]]; then
        echo
        info "HAProxy config dosyası bulunamadı. Varsayılan config oluşturuluyor..."
        sudo mkdir -p "$(dirname "$HAPROXY_CFG")"
        sudo tee "$HAPROXY_CFG" > /dev/null << 'EOF'
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
    # Sunucuları Guard UI üzerinden ekleyin.
EOF
        ok "Varsayılan HAProxy config oluşturuldu: $HAPROXY_CFG"
    else
        ok "HAProxy config mevcut: $HAPROXY_CFG"
    fi
fi

# ── Yardımcı fonksiyonlar ─────────────────────────────────────────────────

# Returns 0 if the port is in LISTEN state, 1 otherwise.
port_in_use() {
    local port="$1"
    ss -tln 2>/dev/null | awk '{print $4}' | grep -q ":${port}$"
}

# Write a key=value to .env, replacing if it already exists.
set_env() {
    local key="$1"
    local val="$2"
    if grep -q "^${key}=" "$ENV_FILE" 2>/dev/null; then
        sed -i "s/^${key}=.*/${key}=${val}/" "$ENV_FILE"
    else
        echo "${key}=${val}" >> "$ENV_FILE"
    fi
    export "${key}=${val}"
}

# ── Port yapılandırması ──────────────────────────────────────────────────

echo
echo -e "${CYAN}── Port Yapılandırması ─────────────────────────────────────${NC}"
echo
echo "  HAProxy Guard API ve Web UI için kullanılacak portlar."
echo "  Enter'a basarak varsayılan değerlerle devam edebilirsiniz."
echo

API_PORT="${HG_API_PORT:-8000}"
WEB_PORT="${HG_WEB_PORT:-8080}"

while true; do
    read -r -p "  API port [${API_PORT}]: " ans
    ans="${ans:-$API_PORT}"
    if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans > 0 && ans <= 65535 )); then
        if port_in_use "$ans"; then
            warn "Port $ans zaten kullanımda, başka bir port girin"
        else
            API_PORT="$ans"
            break
        fi
    else
        warn "Geçerli bir port numarası girin (1-65535)"
    fi
done
set_env "HG_API_PORT" "$API_PORT"
ok "API portu : ${API_PORT}"

while true; do
    read -r -p "  Web UI port [${WEB_PORT}]: " ans
    ans="${ans:-$WEB_PORT}"
    if [[ "$ans" =~ ^[0-9]+$ ]] && (( ans > 0 && ans <= 65535 )); then
        if [[ "$ans" == "$API_PORT" ]]; then
            warn "Web UI portu API portuyla aynı olamaz"
        elif port_in_use "$ans"; then
            warn "Port $ans zaten kullanımda, başka bir port girin"
        else
            WEB_PORT="$ans"
            break
        fi
    else
        warn "Geçerli bir port numarası girin (1-65535)"
    fi
done
set_env "HG_WEB_PORT" "$WEB_PORT"
ok "Web UI portu : ${WEB_PORT}"

# ── Docker modu: HAProxy host portları ───────────────────────────────────

if [[ "$MANAGE_MODE" == "docker" ]]; then
    echo
    echo -e "${CYAN}── HAProxy host port kontrolü ───────────────────────────────${NC}"
    for p in 80 443 9999; do
        if port_in_use "$p"; then
            warn "Port $p zaten kullanımda — system HAProxy olabilir"
        else
            ok "Port $p boş"
        fi
    done
fi

# ── Docker Compose servislerini başlat ──────────────────────────────────

echo
echo -e "${CYAN}── Servisler başlatılıyor ───────────────────────────────────${NC}"

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$PROJECT_DIR"

info "Docker imajları build ediliyor..."
docker compose build --quiet 2>&1 | tail -3

info "Temel servisler başlatılıyor (db + api + web)..."
if ! docker compose up -d --wait 2>&1; then
    echo
    die "Docker Compose başlatılamadı. Yukarıdaki hatayı kontrol edin."
fi

echo
ok "db   : PostgreSQL 16"
ok "api  : FastAPI → http://localhost:${HG_API_PORT:-8000}"
ok "web  : React UI → http://localhost:${HG_WEB_PORT:-8080}"

if [[ "$MANAGE_MODE" == "docker" ]]; then
    echo
    info "Docker HAProxy (production profili) başlatılıyor..."
    if docker compose --profile prod up -d haproxy-prod 2>&1; then
        ok "haproxy-prod : network_mode=host → port 80/443/9999"
    else
        warn "haproxy-prod başlatılamadı. Port çakışması olabilir, logları kontrol edin:"
        echo "       docker compose --profile prod logs haproxy-prod"
    fi
fi

# ── Sonraki adımlar ─────────────────────────────────────────────────────

echo
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  Kurulum tamamlandı! ✓${NC}"
echo -e "${CYAN}══════════════════════════════════════════════════════════════${NC}"
echo
echo "  Web UI  : http://localhost:${HG_WEB_PORT:-8080}"
echo "  API     : http://localhost:${HG_API_PORT:-8000}"
echo "  API Doc : http://localhost:${HG_API_PORT:-8000}/docs"
echo

if [[ "$MANAGE_MODE" == "docker" ]]; then
    echo "  HAProxy modu : Docker (network_mode: host)"
    echo
    echo "  HAProxy konteynerini yönetmek için:"
    echo "    docker compose --profile prod logs -f haproxy-prod"
    echo "    docker compose --profile prod restart haproxy-prod"
    echo
    echo "  Agent kurulumu için:"
    echo "    cp scripts/haproxy-guard-agent.env.example /etc/haproxy-guard-agent.env"
    echo "    # MANAGE_MODE=docker olarak düzenleyin"
    echo "    # CONTAINER_NAME=haproxy-prod olarak ayarlayın"
    echo "    sudo cp scripts/haproxy-guard-agent.service /etc/systemd/system/"
    echo "    sudo systemctl daemon-reload && sudo systemctl enable --now haproxy-guard-agent"
else
    echo "  HAProxy modu : systemctl"
    echo
    echo "  Agent kurulumu için:"
    echo "    cp scripts/haproxy-guard-agent.env.example /etc/haproxy-guard-agent.env"
    echo "    # MANAGE_MODE=systemd (varsayılan)"
    echo "    sudo cp scripts/haproxy-guard-agent.service /etc/systemd/system/"
    echo "    sudo systemctl daemon-reload && sudo systemctl enable --now haproxy-guard-agent"
fi

echo
echo "  Tüm servisleri durdurmak için:"
echo "    docker compose down"
if [[ "$MANAGE_MODE" == "docker" ]]; then
    echo "    docker compose --profile prod down"
fi
echo
