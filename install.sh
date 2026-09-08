#!/bin/bash
# AegisDNS installer

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NEEDS_RELOGIN=false
USE_TAILSCALE=true
FORCE_REBUILD=false
TEMP_FILES=()

for arg in "$@"; do
    case "$arg" in
        --no-tailscale) USE_TAILSCALE=false ;;
        --rebuild) FORCE_REBUILD=true ;;
        -h|--help)
            echo "Usage: ./install.sh [--no-tailscale] [--rebuild]"
            exit 0
            ;;
        *) echo "Unknown option: $arg" >&2; exit 2 ;;
    esac
done

cleanup() {
    local file
    for file in "${TEMP_FILES[@]}"; do rm -f "$file"; done
}
trap cleanup EXIT

# ── colors ─────────────────────────────────────────────────────────────────────
R='\033[0;31m'
G='\033[0;32m'
Y='\033[1;33m'
C='\033[0;36m'
B='\033[1m'
D='\033[2m'
N='\033[0m'

ok()   { echo -e "  ${G}✓${N} $*"; }
bad()  { echo -e "  ${R}✗${N} $*"; }
info() { echo -e "  ${C}→${N} $*"; }
warn() { echo -e "  ${Y}!${N} $*"; }
die()  { echo -e "\n${R}${B}Error:${N} $*\n"; exit 1; }

header() {
    echo ""
    echo -e "${B}$*${N}"
    printf '%*s\n' "${#1}" '' | tr ' ' '-'
}

# ── banner ─────────────────────────────────────────────────────────────────────
if [ -t 1 ] && command -v clear >/dev/null 2>&1; then clear || true; fi
echo -e "${C}${B}"
cat << 'EOF'
  ╔═╗┌─┐┌─┐┬┌─┐╔╦╗╔╗╔╔═╗
  ╠═╣├┤ │ ┬│└─┐ ║║║║║╚═╗
  ╩ ╩└─┘└─┘┴└─┘═╩╝╝╚╝╚═╝
EOF
echo -e "${N}"
if $USE_TAILSCALE; then
    echo -e "  ${D}Self-hosted DNS for your Tailscale network${N}"
else
    echo -e "  ${D}Self-hosted DNS for your local network${N}"
fi
echo ""

# ── root check ─────────────────────────────────────────────────────────────────
header "Checking environment"

if [ "$EUID" -eq 0 ]; then
    die "Don't run this as root. Run as your normal user — sudo will be used when needed."
fi

if ! command -v sudo >/dev/null 2>&1; then
    die "'sudo' is not installed. Install it first, then re-run."
fi

if ! sudo -n true 2>/dev/null; then
    info "This script needs sudo access for a few things. Enter your password:"
    sudo -v || die "Sudo authentication failed."
fi

# keep sudo alive in background
( while true; do sudo -n true; sleep 50; kill -0 "$$" 2>/dev/null || exit; done & )

ok "Environment looks good"

# ── curl check ─────────────────────────────────────────────────────────────────
if ! command -v curl >/dev/null 2>&1; then
    die "'curl' is not installed. Install it and re-run.\n  Debian/Ubuntu: sudo apt install curl\n  Fedora:        sudo dnf install curl"
fi

# ── docker ─────────────────────────────────────────────────────────────────────
header "Docker"

install_docker() {
    info "Downloading and running the official Docker installer..."
    local installer
    installer=$(mktemp) || die "Could not create a temporary file."
    TEMP_FILES+=("$installer")
    curl -fL --proto '=https' --tlsv1.2 https://get.docker.com -o "$installer" || die "Docker installer download failed."
    sh "$installer" || die "Docker installation failed. Check the output above."

    # Enable and start the service
    if command -v systemctl >/dev/null 2>&1; then
        sudo systemctl enable --now docker >/dev/null 2>&1 || true
    fi

    # Add user to docker group so they don't need sudo
    if ! groups "$USER" | grep -qw docker; then
        sudo usermod -aG docker "$USER"
        NEEDS_RELOGIN=true
    fi

    # Give the daemon a moment to spin up
    local tries=0
    while ! sudo docker info >/dev/null 2>&1; do
        tries=$((tries + 1))
        [ $tries -ge 10 ] && die "Docker installed but the daemon won't start. Try: sudo systemctl start docker"
        sleep 2
    done
}

if ! command -v docker >/dev/null 2>&1; then
    warn "Docker not found — installing it now."
    install_docker
    ok "Docker installed."
else
    ok "Docker is already installed."
fi

# Try to connect to the daemon, start it if needed
DOCKER_CMD=(docker)
if ! docker info >/dev/null 2>&1; then
    if sudo docker info >/dev/null 2>&1; then
        # User isn't in the docker group yet, use sudo for this session
        DOCKER_CMD=(sudo docker)
        warn "Using sudo for Docker this session (user not in docker group yet)."
    else
        info "Starting Docker daemon..."
        if command -v systemctl >/dev/null 2>&1; then
            sudo systemctl enable --now docker >/dev/null 2>&1 || true
            sleep 3
        fi
        if ! sudo docker info >/dev/null 2>&1; then
            die "Can't connect to Docker. Try: sudo systemctl start docker"
        fi
        DOCKER_CMD=(sudo docker)
    fi
fi

# Check for Docker Desktop (it breaks per-device IP tracking)
if "${DOCKER_CMD[@]}" info 2>/dev/null | grep -q "Docker Desktop"; then
    echo ""
    warn "${B}Docker Desktop is running — this will cause problems.${N}"
    echo ""
    echo -e "  Docker Desktop uses a VM that hides the real IP of your devices."
    echo -e "  Every DNS query will look like it comes from the same gateway IP,"
    echo -e "  so per-device tracking and filtering won't work."
    echo ""
    echo -e "  To fix this: uninstall Docker Desktop and re-run this script."
    echo -e "  The script will install native Docker Engine automatically."
    echo ""
    read -rp "  Continue anyway? [y/N] " _resp
    [[ "$_resp" =~ ^[Yy]$ ]] || die "Cancelled."
fi

# Docker Compose
if ! "${DOCKER_CMD[@]}" compose version >/dev/null 2>&1; then
    die "Docker Compose plugin is missing.\n  Try: sudo apt install docker-compose-plugin  (or dnf/yum equivalent)"
fi

# Add user to docker group if they aren't already
if ! groups "$USER" | grep -qw docker; then
    info "Adding $USER to the docker group..."
    sudo usermod -aG docker "$USER"
    NEEDS_RELOGIN=true
fi

ok "Docker is ready."

# ── tailscale ──────────────────────────────────────────────────────────────────
header "Tailscale"

install_tailscale() {
    info "Installing Tailscale..."
    local installer
    installer=$(mktemp) || die "Could not create a temporary file."
    TEMP_FILES+=("$installer")
    curl -fL --proto '=https' --tlsv1.2 https://tailscale.com/install.sh -o "$installer" || die "Tailscale installer download failed."
    sh "$installer" || die "Tailscale installation failed."
    sudo systemctl enable --now tailscaled >/dev/null 2>&1 || true
    ok "Tailscale installed."
}

TS_IP=""
if $USE_TAILSCALE; then
    if ! command -v tailscale >/dev/null 2>&1; then
        warn "Tailscale not found — installing it now."
        install_tailscale
    fi

    if ! sudo tailscale status >/dev/null 2>&1; then
        info "Starting tailscaled..."
        sudo systemctl enable --now tailscaled >/dev/null 2>&1 || true
        sleep 2
    fi

    if sudo tailscale status 2>&1 | grep -qi "stopped\|not logged\|needslogin"; then
        echo ""
        warn "Tailscale is installed but not connected."
        echo -e "  Run ${C}sudo tailscale up${N}, then re-run this installer."
        echo -e "  For a LAN-only install, use ${C}./install.sh --no-tailscale${N}."
        die "Tailscale setup is incomplete."
    fi
    TS_IP=$(tailscale ip -4 2>/dev/null || sudo tailscale ip -4 2>/dev/null || true)
    if [ -n "$TS_IP" ]; then
        ok "Connected to Tailscale.  Your IP: ${C}$TS_IP${N}"
    else
        die "Tailscale is connected but did not report an IPv4 address."
    fi
else
    info "Skipping Tailscale; configuring AegisDNS for the local network."
fi

# ── network config ─────────────────────────────────────────────────────────────
header "Network"

AEGIS_IP=""

# Prefer Tailscale IP
if [ -n "$TS_IP" ]; then
    AEGIS_IP="$TS_IP"
fi

# Local network fallback
if [ -z "$AEGIS_IP" ]; then
    AEGIS_IP=$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
fi

# hostname fallback
if [ -z "$AEGIS_IP" ]; then
    AEGIS_IP=$(hostname -I 2>/dev/null | awk '{print $1}')
fi

# last resort
if ! [[ "$AEGIS_IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    AEGIS_IP="127.0.0.1"
    warn "Couldn't detect your IP. Using 127.0.0.1 (local only)."
else
    IFS=. read -r -a IP_OCTETS <<< "$AEGIS_IP"
    for octet in "${IP_OCTETS[@]}"; do
        if [ "$octet" -gt 255 ]; then
            AEGIS_IP="127.0.0.1"
            warn "Detected an invalid IPv4 address. Using 127.0.0.1 (local only)."
            break
        fi
    done
    ok "Using IP: ${C}$AEGIS_IP${N}"
fi

upsert_env_value() {
    local key="$1" value="$2" file="$SCRIPT_DIR/.env" tmp
    tmp=$(mktemp "$SCRIPT_DIR/.env.XXXXXX") || return 1
    TEMP_FILES+=("$tmp")
    if [ -f "$file" ]; then
        awk -v k="$key" -v v="$value" 'BEGIN{done=0} index($0,k "=")==1 {if(!done){print k "=" v;done=1};next} {print} END{if(!done)print k "=" v}' "$file" > "$tmp"
    else
        printf '%s=%s\n' "$key" "$value" > "$tmp"
    fi
    chmod 600 "$tmp"
    mv "$tmp" "$file"
}

upsert_env_value "AEGIS_HOST_IP" "$AEGIS_IP" || die "Could not update .env."

# Write config if it doesn't exist
if [ ! -f "$SCRIPT_DIR/config.json" ]; then
    info "Creating config.json..."
    cat > "$SCRIPT_DIR/config.json" <<JSONEOF
{
  "host_ips": [
    "127.0.0.1",
    "$AEGIS_IP"
  ]
}
JSONEOF
    ok "config.json created."
else
    # Add the IP while retaining future or user-defined configuration keys.
    command -v python3 >/dev/null 2>&1 || die "Python 3 is required to validate and safely update the existing config.json."
    AEGIS_CONFIG_FILE="$SCRIPT_DIR/config.json" python3 -c '
import json, os
config=json.load(open(os.environ["AEGIS_CONFIG_FILE"],encoding="utf-8"))
if not isinstance(config,dict) or not isinstance(config.get("host_ips",[]),list):
    raise ValueError("host_ips must be an array")
' || die "config.json is invalid. Repair it or replace it with config.example.json."
    AEGIS_CONFIG_FILE="$SCRIPT_DIR/config.json" AEGIS_NEW_IP="$AEGIS_IP" python3 -c '
import json, os
path, ip = os.environ["AEGIS_CONFIG_FILE"], os.environ["AEGIS_NEW_IP"]
with open(path, encoding="utf-8") as f: config=json.load(f)
ips=config.get("host_ips", ["127.0.0.1"])
if not isinstance(ips,list): raise ValueError("host_ips must be an array")
if ip not in ips: ips.append(ip)
config["host_ips"]=ips
tmp=path+".tmp"
with open(tmp,"w",encoding="utf-8") as f: json.dump(config,f,indent=2); f.write("\n")
os.replace(tmp,path)
' || die "config.json is invalid and could not be updated."
    ok "config.json is up to date."
fi

# ── build ──────────────────────────────────────────────────────────────────────
header "Building"

cd "$SCRIPT_DIR"

mkdir -p "$SCRIPT_DIR/blocklists" || die "Could not create the local blocklists directory."

for required in docker-compose.yml Dockerfile Dockerfile.openroot Cargo.lock config.json openroot.json; do
    [ -e "$SCRIPT_DIR/$required" ] || die "Required project file is missing: $required"
done

if ! "${DOCKER_CMD[@]}" compose config --quiet; then
    die "Docker Compose configuration is invalid."
fi

if $FORCE_REBUILD; then
    info "Rebuilding Docker images without cache."
    BUILD_ARGS=(--no-cache)
else
    info "Building Docker images (the Docker cache keeps reruns fast)."
    BUILD_ARGS=()
fi
echo ""
if ! "${DOCKER_CMD[@]}" compose build "${BUILD_ARGS[@]}"; then
    die "Build failed. Check the errors above."
fi
ok "Build complete."

# ── cli ────────────────────────────────────────────────────────────────────────
if [ -f "$SCRIPT_DIR/aegis" ]; then
    chmod +x "$SCRIPT_DIR/aegis"
    if sudo ln -sf "$SCRIPT_DIR/aegis" /usr/local/bin/aegis 2>/dev/null; then
        ok "'aegis' command installed to /usr/local/bin/aegis"
    else
        warn "Couldn't install 'aegis' globally. Run it with: $SCRIPT_DIR/aegis"
    fi
fi

# ── done ───────────────────────────────────────────────────────────────────────
echo ""
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo -e "${G}${B}  Done! AegisDNS is installed.${N}"
echo -e "${G}${B}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${N}"
echo ""

if [ "$NEEDS_RELOGIN" = true ]; then
    warn "Open a new terminal before running 'aegis' — your user was just"
    warn "added to the docker group and that only takes effect in new sessions."
    echo ""
fi

if $USE_TAILSCALE && [ -z "$TS_IP" ]; then
    echo -e "  ${Y}!${N} Connect to Tailscale first:"
    echo -e "    ${C}sudo tailscale up${N}"
    echo -e "    Then re-run ${C}./install.sh${N} to pick up your Tailscale IP."
    echo ""
fi

echo -e "  Start AegisDNS:"
echo -e "    ${C}aegis start${N}"
echo ""
echo -e "  Then open the dashboard:"
echo -e "    ${C}http://localhost:5380${N}"
echo -e "    Username: ${B}admin${N}"
echo -e "    Password: run ${C}aegis credentials${N} after starting"
echo ""
echo -e "  Register a device (use its Tailscale IP):"
echo -e "    ${C}aegis device add 100.x.x.x \"My Phone\"${N}"
echo ""

exit 0
