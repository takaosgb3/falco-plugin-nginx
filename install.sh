#!/bin/bash
#
# Falco nginx Plugin Installer
# One-liner installation script for easy deployment
#

set -euo pipefail

# Configuration
PLUGIN_REPO="takaosgb3/falco-nginx-plugin"
PLUGIN_VERSION="${PLUGIN_VERSION:-latest}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Helper functions
log() { echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"; }
success() { echo -e "${GREEN}✅ $1${NC}"; }
error() { echo -e "${RED}❌ $1${NC}"; exit 1; }
warning() { echo -e "${YELLOW}⚠️  $1${NC}"; }

# ASCII Art
cat << 'EOF'
 _____     _                   _             _      
|  ___|_ _| | ___ ___    _ __ | | _   _  __ _(_)_ __  
| |_ / _` | |/ __/ _ \  | '_ \| | | | |/ _` | | '_ \ 
|  _| (_| | | (_| (_) | | |_) | | |_| | (_| | | | | |
|_|  \__,_|_|\___\___/  | .__/|_|\__,_|\__, |_|_| |_|
                        |_|            |___/         
nginx security plugin installer
EOF

echo ""
log "Starting Falco nginx plugin installation"
log "Version: ${PLUGIN_VERSION}"
log "Repository: ${PLUGIN_REPO}"
echo ""

# Check system requirements
if [ "$EUID" -ne 0 ]; then 
    error "Please run as root (use sudo)"
fi

if [ ! -f /etc/os-release ]; then
    error "Cannot detect OS. This installer supports Ubuntu/Debian only"
fi

if ! grep -E "(Ubuntu|Debian)" /etc/os-release > /dev/null 2>&1; then
    warning "This installer is designed for Ubuntu/Debian. Attempting to continue..."
fi

ARCH=$(uname -m)
if [ "$ARCH" != "x86_64" ]; then
    error "Currently only x86_64 architecture is supported"
fi

# Install nginx if needed
if ! command -v nginx &> /dev/null; then
    log "Installing nginx..."
    if ! apt-get update -qq; then
        error "Failed to update package list. Please check your internet connection."
    fi
    if ! apt-get install -y nginx; then
        error "Failed to install nginx. Please check your system configuration."
    fi
    success "nginx installed"
else
    success "nginx is already installed"
fi

# Configure nginx
log "Configuring nginx..."
if [ ! -f /var/log/nginx/access.log ]; then
    # Ensure nginx is configured with access logging
    cat > /etc/nginx/sites-available/default << 'NGINX_CONF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    server_name _;
    
    access_log /var/log/nginx/access.log combined;
    error_log /var/log/nginx/error.log;
    
    location / {
        try_files $uri $uri/ =404;
    }
}
NGINX_CONF
    systemctl restart nginx
fi
success "nginx configured"

# Install Falco if needed
if ! command -v falco &> /dev/null; then
    log "Installing Falco..."
    # Create keyring directory if it doesn't exist
    mkdir -p /usr/share/keyrings
    curl -fsSL https://falco.org/repo/falcosecurity-packages.asc | \
        gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
    # Create sources directory if it doesn't exist
    mkdir -p /etc/apt/sources.list.d
    echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] \
        https://download.falco.org/packages/deb stable main" | \
        tee /etc/apt/sources.list.d/falcosecurity.list > /dev/null
    apt-get update -qq
    DEBIAN_FRONTEND=noninteractive apt-get install -y falco > /dev/null 2>&1
    success "Falco installed"
else
    success "Falco is already installed"
fi

# Download plugin
log "Downloading nginx plugin..."
TMP_DIR=$(mktemp -d) || error "Failed to create temporary directory"
cd "$TMP_DIR" || error "Failed to change to temporary directory"
log "Working in temporary directory: $TMP_DIR"

if [ "$PLUGIN_VERSION" = "latest" ]; then
    DOWNLOAD_URL="https://github.com/${PLUGIN_REPO}/releases/latest/download"
else
    DOWNLOAD_URL="https://github.com/${PLUGIN_REPO}/releases/download/${PLUGIN_VERSION}"
fi

# Download plugin binary
log "Downloading from: ${DOWNLOAD_URL}/libfalco-nginx-plugin-linux-amd64.so"
if ! wget --no-check-certificate "${DOWNLOAD_URL}/libfalco-nginx-plugin-linux-amd64.so" -O libfalco-nginx-plugin.so 2>&1; then
    error "Failed to download plugin binary from ${DOWNLOAD_URL}"
fi
success "Plugin binary downloaded"

# Download rules
log "Downloading from: ${DOWNLOAD_URL}/nginx_rules.yaml"
if ! wget --no-check-certificate "${DOWNLOAD_URL}/nginx_rules.yaml" -O nginx_rules.yaml 2>&1; then
    error "Failed to download rules file from ${DOWNLOAD_URL}"
fi
success "Rules file downloaded"

# Install plugin
log "Installing plugin..."
mkdir -p /usr/share/falco/plugins
cp libfalco-nginx-plugin.so /usr/share/falco/plugins/
chmod 644 /usr/share/falco/plugins/libfalco-nginx-plugin.so

mkdir -p /etc/falco/rules.d
cp nginx_rules.yaml /etc/falco/rules.d/
success "Plugin installed"

# Configure Falco
log "Configuring Falco..."
cp /etc/falco/falco.yaml /etc/falco/falco.yaml.backup

if ! grep -q "name: nginx" /etc/falco/falco.yaml; then
    cat >> /etc/falco/falco.yaml << 'FALCO_CONFIG'

plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
FALCO_CONFIG
fi

# Restart Falco
systemctl restart falco || service falco restart
sleep 3

# Cleanup
cd /
rm -rf "$TMP_DIR"

# Verify installation
log "Verifying installation..."

# Check if plugin is loaded
if falco --list-plugins 2>/dev/null | grep -q nginx; then
    success "nginx plugin is loaded"
else
    warning "nginx plugin may not be loaded. Check with: sudo falco --list-plugins"
fi

# Check if Falco service is running
if systemctl is-active --quiet falco || service falco status > /dev/null 2>&1; then
    success "Falco is running"
else
    warning "Falco service is not running. Try: sudo falco -c /etc/falco/falco.yaml --disable-source syscall"
fi

echo ""
success "========== Installation Complete =========="
echo ""
echo "Next steps:"
echo "1. Monitor alerts: sudo journalctl -u falco -f"
echo "2. Test detection:"
echo "   curl \"http://localhost/test.php?id=' OR '1'='1\""
echo "   curl \"http://localhost/test.php?q=<script>alert(1)</script>\""
echo ""
echo "For more information: https://github.com/${PLUGIN_REPO}"
echo ""