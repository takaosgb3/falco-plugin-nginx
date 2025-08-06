#!/bin/bash
#
# Falco nginx Plugin Direct Installer (v0.4.2)
# Installs without using GitHub API
#

set -euo pipefail

# Configuration
PLUGIN_VERSION="v0.4.2"
PLUGIN_REPO="takaosgb3/falco-plugin-nginx"

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
nginx security plugin installer (Direct v0.4.2)
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

# Check required commands
for cmd in curl wget; do
    if ! command -v $cmd &> /dev/null; then
        log "Installing $cmd..."
        apt-get update -qq && apt-get install -y $cmd || error "Failed to install $cmd"
    fi
done

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

# Direct download URLs
DOWNLOAD_URL="https://github.com/${PLUGIN_REPO}/releases/download/${PLUGIN_VERSION}"

# Download plugin binary
log "Downloading plugin binary..."
PLUGIN_URL="${DOWNLOAD_URL}/libfalco-nginx-plugin-linux-amd64.so"
log "URL: $PLUGIN_URL"

if ! curl -L --progress-bar "$PLUGIN_URL" -o libfalco-nginx-plugin.so; then
    error "Failed to download plugin binary from ${PLUGIN_URL}"
fi

# Verify file was downloaded
if [ ! -f libfalco-nginx-plugin.so ] || [ ! -s libfalco-nginx-plugin.so ]; then
    error "Plugin binary download failed or file is empty"
fi

success "Plugin binary downloaded"

# Download rules
log "Downloading rules file..."
RULES_URL="${DOWNLOAD_URL}/nginx_rules.yaml"
log "URL: $RULES_URL"

if ! curl -L --progress-bar "$RULES_URL" -o nginx_rules.yaml; then
    error "Failed to download rules file from ${RULES_URL}"
fi

# Verify file was downloaded
if [ ! -f nginx_rules.yaml ] || [ ! -s nginx_rules.yaml ]; then
    error "Rules file download failed or file is empty"
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

# Update load_plugins to include nginx
log "Updating load_plugins configuration..."
if grep -q "^load_plugins:" /etc/falco/falco.yaml; then
    # Check if it's empty array
    if grep -q "^load_plugins: \[\]" /etc/falco/falco.yaml; then
        sed -i 's/^load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml
        success "Updated load_plugins to include nginx"
    # Check if nginx is already in the array
    elif ! grep -q "nginx" /etc/falco/falco.yaml; then
        # Add nginx to existing array
        sed -i '/^load_plugins:/ s/\]/,nginx\]/' /etc/falco/falco.yaml
        success "Added nginx to existing load_plugins array"
    else
        success "nginx already in load_plugins"
    fi
else
    # Add load_plugins line near the top of the file
    sed -i '1s/^/load_plugins: [nginx]\n/' /etc/falco/falco.yaml
    success "Added load_plugins configuration"
fi

# Configure plugin section
log "Configuring nginx plugin..."
if ! grep -q "^plugins:" /etc/falco/falco.yaml; then
    log "Adding plugins configuration section..."
    cat >> /etc/falco/falco.yaml << 'FALCO_CONFIG'

# nginx plugin configuration
plugins:
  - name: nginx
    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so
    init_config:
      log_paths:
        - /var/log/nginx/access.log
FALCO_CONFIG
    success "Added nginx plugin configuration"
else
    # Check if nginx plugin is configured
    if ! grep -A5 "^plugins:" /etc/falco/falco.yaml | grep -q "name: nginx"; then
        log "Adding nginx plugin to existing plugins section..."
        # Find the plugins: line and add nginx config after it
        awk '/^plugins:/ {print; print "  - name: nginx"; print "    library_path: /usr/share/falco/plugins/libfalco-nginx-plugin.so"; print "    init_config:"; print "      log_paths:"; print "        - /var/log/nginx/access.log"; next} 1' /etc/falco/falco.yaml > /tmp/falco.yaml.tmp
        mv /tmp/falco.yaml.tmp /etc/falco/falco.yaml
        success "Added nginx plugin to plugins section"
    else
        success "nginx plugin already configured"
    fi
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

# Check if rules are loaded
if [ -f /etc/falco/rules.d/nginx_rules.yaml ]; then
    success "nginx rules are installed at /etc/falco/rules.d/nginx_rules.yaml"
    # Try to validate rules
    if falco --validate /etc/falco/rules.d/nginx_rules.yaml 2>/dev/null; then
        success "nginx rules validation passed"
    else
        warning "nginx rules validation failed. Check syntax with: sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml"
    fi
else
    error "nginx rules not found at /etc/falco/rules.d/nginx_rules.yaml"
fi

# Check if Falco service is running
if systemctl is-active --quiet falco || service falco status > /dev/null 2>&1; then
    success "Falco is running"
else
    warning "Falco service is not running. Try: sudo falco -c /etc/falco/falco.yaml --disable-source syscall"
fi

echo ""
success "========== Installation Complete =========="

# Ask if user wants to set up test content
echo ""
read -p "Would you like to set up test web content for security testing? (y/N) " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    log "Setting up test web content..."
    # Download and run the setup script
    if curl -fsSL "https://raw.githubusercontent.com/${PLUGIN_REPO}/main/scripts/setup-test-content.sh" | bash; then
        success "Test content setup complete"
    else
        warning "Failed to set up test content. You can run it manually later."
    fi
fi

echo ""
echo "Next steps:"
echo "1. Monitor alerts: sudo journalctl -u falco -f"
echo "2. Test detection:"
echo '   curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"'
echo '   curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"'
echo '   curl "http://localhost/upload.php?file=../../../../../../etc/passwd"'
echo ""
echo "For more information: https://github.com/${PLUGIN_REPO}"
echo ""