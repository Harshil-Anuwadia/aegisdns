#!/usr/bin/env bash
set -e

# ==============================================================================
# AegisDNS Automated Docker Installer
# ==============================================================================

if [ -t 1 ]; then
    BOLD="\033[1m"; RESET="\033[0m"; GREEN="\033[32m"; YELLOW="\033[33m"; RED="\033[31m"; BLUE="\033[34m"
else
    BOLD=""; RESET=""; GREEN=""; YELLOW=""; RED=""; BLUE=""
fi

log_info() { echo -e "${BOLD}${BLUE}[INFO]${RESET} $1"; }
log_ok()   { echo -e "${BOLD}${GREEN}[ OK ]${RESET} $1"; }
log_warn() { echo -e "${BOLD}${YELLOW}[WARN]${RESET} $1"; }
log_err()  { echo -e "${BOLD}${RED}[ERR ]${RESET} $1" >&2; exit 1; }

echo ""
echo -e "${BOLD}AegisDNS Automated Setup${RESET}"
echo "================================================================================"

log_info "Verifying privileges..."
if [ "$EUID" -ne 0 ]; then
    log_err "Please run this script with sudo: sudo ./install.sh"
fi
log_ok "Administrator privileges confirmed."

log_info "Checking for Docker..."
if ! command -v docker &> /dev/null; then
    log_info "Docker is missing. Installing Docker automatically..."
    curl -fsSL https://get.docker.com -o get-docker.sh
    sh get-docker.sh >/dev/null 2>&1
    rm get-docker.sh
    log_ok "Docker installed successfully."
else
    log_ok "Docker is already installed."
fi

log_info "Checking Docker Compose plugin..."
if ! docker compose version &> /dev/null && ! docker-compose --version &> /dev/null; then
    log_warn "Docker Compose is missing. Attempting to install via apt/dnf..."
    if command -v apt-get &> /dev/null; then
        apt-get update -qq && apt-get install -yqq docker-compose-plugin >/dev/null 2>&1 || true
    elif command -v dnf &> /dev/null; then
        dnf install -yq docker-compose-plugin >/dev/null 2>&1 || true
    fi
fi

log_info "Resolving system port conflicts (Port 53)..."
if systemctl is-active --quiet systemd-resolved; then
    mkdir -p /etc/systemd/resolved.conf.d
    echo -e "[Resolve]\nDNSStubListener=no" > /etc/systemd/resolved.conf.d/aegisdns-override.conf
    systemctl restart systemd-resolved || true
    log_ok "systemd-resolved stub listener disabled."
fi

log_info "Building and starting AegisDNS container..."
if docker compose version &> /dev/null; then
    docker compose up -d --build
elif command -v docker-compose &> /dev/null; then
    docker-compose up -d --build
else
    log_err "Docker Compose is not available. Please install it manually."
fi
log_ok "AegisDNS container is running!"

echo "================================================================================"
echo -e "${BOLD}${GREEN}AegisDNS successfully installed.${RESET}"
echo ""
echo -e "${BOLD}Required Next Steps for Tailscale Users:${RESET}"
echo "  1. Log into your Tailscale Admin Console (https://login.tailscale.com/admin/dns)"
echo "  2. Go to the 'DNS' tab."
echo "  3. Click 'Add Nameserver' -> 'Custom' and enter the Tailscale IP of this machine."
echo "  4. Turn ON 'Override local DNS'."
echo "  5. Ensure 'Secure DNS' / DoH is disabled in Chrome/Brave/Firefox settings."
echo ""
echo -e "${BOLD}Access the Web Dashboard:${RESET}"
echo "  Open http://<YOUR_TAILSCALE_IP>:5380 in your browser."
echo "================================================================================"
