#!/bin/bash
#
# Falco nginx Plugin Installer
# One-liner installation script for easy deployment
#

set -euo pipefail

# Configuration
PLUGIN_REPO="takaosgb3/falco-plugin-nginx"
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

# Check required commands
for cmd in curl wget jq; do
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

if [ "$PLUGIN_VERSION" = "latest" ]; then
    # Get the actual latest version tag using GitHub API
    log "Fetching latest release information..."
    
    # Debug: Show the API URL being used
    API_URL="https://api.github.com/repos/${PLUGIN_REPO}/releases/latest"
    log "API URL: $API_URL"
    
    # Try curl with timeout and show errors
    LATEST_RESPONSE=$(curl -sSL --connect-timeout 10 --max-time 30 "$API_URL" 2>&1)
    CURL_EXIT_CODE=$?
    
    if [ $CURL_EXIT_CODE -ne 0 ]; then
        error "curl failed with exit code $CURL_EXIT_CODE. Response: $LATEST_RESPONSE"
    fi
    
    if [ -z "$LATEST_RESPONSE" ]; then
        error "Empty response from GitHub API"
    fi
    
    # Debug: Show first 200 chars of response
    log "API Response (first 200 chars): ${LATEST_RESPONSE:0:200}"
    
    # Try multiple parsing methods
    LATEST_VERSION=$(echo "$LATEST_RESPONSE" | grep '"tag_name":' | sed -E 's/.*"tag_name":[[:space:]]*"([^"]+)".*/\1/' | head -1)
    
    if [ -z "$LATEST_VERSION" ]; then
        # Try with jq if available
        if command -v jq &> /dev/null; then
            LATEST_VERSION=$(echo "$LATEST_RESPONSE" | jq -r '.tag_name' 2>/dev/null)
        fi
    fi
    
    if [ -z "$LATEST_VERSION" ]; then
        # Try another sed pattern
        LATEST_VERSION=$(echo "$LATEST_RESPONSE" | sed -n 's/.*"tag_name":[[:space:]]*"\([^"]*\)".*/\1/p' | head -1)
    fi
    
    if [ -z "$LATEST_VERSION" ]; then
        # Check if we got a rate limit or other error
        if echo "$LATEST_RESPONSE" | grep -q "rate limit"; then
            warning "GitHub API rate limit exceeded. Using fallback version v0.4.1"
            LATEST_VERSION="v0.4.1"
        elif echo "$LATEST_RESPONSE" | grep -q "Not Found"; then
            error "Repository not found: ${PLUGIN_REPO}. Please check the repository name."
        else
            warning "Failed to parse version from GitHub API. Using fallback version v0.4.1"
            LATEST_VERSION="v0.4.1"
        fi
    fi
    
    log "Latest version is: ${LATEST_VERSION}"
    DOWNLOAD_URL="https://github.com/${PLUGIN_REPO}/releases/download/${LATEST_VERSION}"
else
    DOWNLOAD_URL="https://github.com/${PLUGIN_REPO}/releases/download/${PLUGIN_VERSION}"
fi

# Download plugin binary
log "Downloading plugin binary..."
PLUGIN_URL="${DOWNLOAD_URL}/libfalco-nginx-plugin-linux-amd64.so"
log "Plugin URL: $PLUGIN_URL"

if ! wget --progress=bar:force --no-check-certificate "$PLUGIN_URL" -O libfalco-nginx-plugin.so 2>&1; then
    # If wget fails, try curl
    log "wget failed, trying curl..."
    if ! curl -L --progress-bar "$PLUGIN_URL" -o libfalco-nginx-plugin.so; then
        error "Failed to download plugin binary from ${PLUGIN_URL}"
    fi
fi

# Verify file was downloaded
if [ ! -f libfalco-nginx-plugin.so ] || [ ! -s libfalco-nginx-plugin.so ]; then
    error "Plugin binary download failed or file is empty"
fi

success "Plugin binary downloaded"

# Download rules
log "Downloading rules file..."
RULES_URL="${DOWNLOAD_URL}/nginx_rules.yaml"
log "Rules URL: $RULES_URL"

if ! wget --progress=bar:force --no-check-certificate "$RULES_URL" -O nginx_rules.yaml 2>&1; then
    # If wget fails, try curl
    log "wget failed, trying curl..."
    if ! curl -L --progress-bar "$RULES_URL" -o nginx_rules.yaml; then
        error "Failed to download rules file from ${RULES_URL}"
    fi
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

# Restart Falco to load the nginx plugin alongside kernel monitoring
log "Restarting Falco with nginx plugin enabled..."

# Simply restart Falco - it will load both kernel monitoring AND the nginx plugin
systemctl restart falco
sleep 3

# Check if Falco started successfully
if systemctl is-active --quiet falco; then
    success "Falco restarted with nginx plugin (both kernel and nginx monitoring active)"
else
    warning "Falco failed to start with kernel module. Checking eBPF support..."
    
    # First, check if we're on EC2 and if eBPF is available
    log "Checking for eBPF support..."
    
    # Try modern eBPF first
    if systemctl is-active --quiet falco-modern-bpf 2>/dev/null; then
        log "Switching to modern eBPF mode..."
        systemctl stop falco 2>/dev/null
        systemctl start falco-modern-bpf
        if systemctl is-active --quiet falco-modern-bpf; then
            success "Falco started with modern eBPF + nginx plugin"
            # Create override for regular falco service to use modern BPF
            mkdir -p /etc/systemd/system/falco.service.d
            cat > /etc/systemd/system/falco.service.d/modern-bpf.conf << 'FALCO_OVERRIDE'
[Service]
# Use modern eBPF driver
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --modern-bpf
FALCO_OVERRIDE
            systemctl daemon-reload
            systemctl stop falco-modern-bpf
            systemctl restart falco
            if systemctl is-active --quiet falco; then
                success "Falco configured with modern eBPF + nginx plugin"
            fi
        fi
    # Try legacy eBPF
    elif systemctl is-active --quiet falco-bpf 2>/dev/null; then
        log "Switching to legacy eBPF mode..."
        systemctl stop falco 2>/dev/null
        systemctl start falco-bpf
        if systemctl is-active --quiet falco-bpf; then
            success "Falco started with legacy eBPF + nginx plugin"
            # Create override for regular falco service to use BPF
            mkdir -p /etc/systemd/system/falco.service.d
            cat > /etc/systemd/system/falco.service.d/bpf.conf << 'FALCO_OVERRIDE'
[Service]
# Use eBPF driver
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --bpf
FALCO_OVERRIDE
            systemctl daemon-reload
            systemctl stop falco-bpf
            systemctl restart falco
            if systemctl is-active --quiet falco; then
                success "Falco configured with legacy eBPF + nginx plugin"
            fi
        fi
    else
        # Try to use eBPF directly
        log "Attempting to enable eBPF directly..."
        mkdir -p /etc/systemd/system/falco.service.d
        
        # Check kernel version for eBPF support
        KERNEL_VERSION=$(uname -r | cut -d. -f1,2)
        KERNEL_MAJOR=$(echo $KERNEL_VERSION | cut -d. -f1)
        KERNEL_MINOR=$(echo $KERNEL_VERSION | cut -d. -f2)
        
        if [ "$KERNEL_MAJOR" -gt 5 ] || ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -ge 8 ]); then
            # Modern eBPF is supported on kernel 5.8+
            log "Kernel $KERNEL_VERSION supports modern eBPF"
            cat > /etc/systemd/system/falco.service.d/modern-bpf.conf << 'FALCO_OVERRIDE'
[Service]
# Use modern eBPF driver (kernel 5.8+)
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --modern-bpf
FALCO_OVERRIDE
            systemctl daemon-reload
            systemctl restart falco
            if systemctl is-active --quiet falco; then
                success "Falco started with modern eBPF + nginx plugin"
            else
                # Fall back to plugin-only mode
                log "Modern eBPF failed, falling back to plugin-only mode..."
                cat > /etc/systemd/system/falco.service.d/plugin-only.conf << 'FALCO_OVERRIDE'
[Service]
# Fallback: run in plugin-only mode
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
FALCO_OVERRIDE
                systemctl daemon-reload
                systemctl restart falco
                if systemctl is-active --quiet falco; then
                    success "Falco started in plugin-only mode (eBPF not available)"
                else
                    error "Failed to start Falco. Check logs: sudo journalctl -u falco -n 50"
                fi
            fi
        elif [ "$KERNEL_MAJOR" -ge 4 ] && [ "$KERNEL_MINOR" -ge 14 ]; then
            # Legacy eBPF is supported on kernel 4.14+
            log "Kernel $KERNEL_VERSION supports legacy eBPF"
            cat > /etc/systemd/system/falco.service.d/bpf.conf << 'FALCO_OVERRIDE'
[Service]
# Use legacy eBPF driver (kernel 4.14+)
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --bpf
FALCO_OVERRIDE
            systemctl daemon-reload
            systemctl restart falco
            if systemctl is-active --quiet falco; then
                success "Falco started with legacy eBPF + nginx plugin"
            else
                # Fall back to plugin-only mode
                log "Legacy eBPF failed, falling back to plugin-only mode..."
                cat > /etc/systemd/system/falco.service.d/plugin-only.conf << 'FALCO_OVERRIDE'
[Service]
# Fallback: run in plugin-only mode
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
FALCO_OVERRIDE
                systemctl daemon-reload
                systemctl restart falco
                if systemctl is-active --quiet falco; then
                    success "Falco started in plugin-only mode (eBPF not available)"
                else
                    error "Failed to start Falco. Check logs: sudo journalctl -u falco -n 50"
                fi
            fi
        else
            # Kernel too old for eBPF
            log "Kernel $KERNEL_VERSION does not support eBPF, using plugin-only mode..."
            cat > /etc/systemd/system/falco.service.d/plugin-only.conf << 'FALCO_OVERRIDE'
[Service]
# Fallback: run in plugin-only mode (kernel too old for eBPF)
ExecStart=
ExecStart=/usr/bin/falco -c /etc/falco/falco.yaml --disable-source syscall
FALCO_OVERRIDE
            systemctl daemon-reload
            systemctl restart falco
            if systemctl is-active --quiet falco; then
                success "Falco started in plugin-only mode (kernel too old for eBPF)"
            else
                error "Failed to start Falco. Check logs: sudo journalctl -u falco -n 50"
            fi
        fi
    fi
fi

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

# Check if Falco service is running (check all possible service names)
FALCO_SERVICE=""
if systemctl is-active --quiet falco; then
    FALCO_SERVICE="falco"
    success "Falco is running with nginx plugin"
elif systemctl is-active --quiet falco-modern-bpf; then
    FALCO_SERVICE="falco-modern-bpf"
    success "Falco is running with nginx plugin (modern eBPF)"
elif systemctl is-active --quiet falco-bpf; then
    FALCO_SERVICE="falco-bpf"
    success "Falco is running with nginx plugin (legacy eBPF)"
fi

if [ -n "$FALCO_SERVICE" ]; then
    # Check what monitoring mode is active
    if lsmod | grep -q falco; then
        log "Mode: Both kernel module and nginx monitoring active"
    elif systemctl show falco -p ExecStart | grep -q "\-\-modern-bpf"; then
        log "Mode: Both modern eBPF and nginx monitoring active"
    elif systemctl show falco -p ExecStart | grep -q "\-\-bpf"; then
        log "Mode: Both legacy eBPF and nginx monitoring active"
    elif systemctl show falco -p ExecStart | grep -q "\-\-disable-source syscall"; then
        log "Mode: nginx monitoring only (no kernel monitoring)"
    else
        # Try to detect if eBPF is actually working
        if falco --list 2>/dev/null | grep -q "BPF"; then
            log "Mode: Both eBPF and nginx monitoring active"
        else
            log "Mode: nginx monitoring (kernel monitoring status unknown)"
        fi
    fi
else
    warning "Falco service is not running. Check with: sudo systemctl status falco falco-modern-bpf falco-bpf"
fi

echo ""
success "========== Installation Complete =========="

# Ask if user wants to set up test content (skip when piped)
if [ -t 0 ]; then
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
fi

echo ""
echo "========================================"
echo "📌 IMPORTANT: How to monitor Falco logs"
echo "========================================"
echo ""
if [ -n "$FALCO_SERVICE" ]; then
    echo "✅ Your Falco service is: $FALCO_SERVICE"
    echo ""
    echo "To monitor alerts, use this command:"
    echo "   sudo journalctl -u $FALCO_SERVICE -f"
    echo ""
    echo "To check service status:"
    echo "   sudo systemctl status $FALCO_SERVICE"
else
    echo "⚠️  Could not determine which Falco service is running."
    echo ""
    echo "Step 1: Find your active Falco service by running:"
    echo "   sudo systemctl status falco"
    echo ""
    echo "Step 2: Look at the first line of output:"
    echo "   - If it shows '● falco.service' and 'Active: active (running)' → Use: sudo journalctl -u falco -f"
    echo "   - If it shows 'Unit falco.service could not be found' or 'inactive' → Try next command"
    echo ""
    echo "   sudo systemctl status falco-modern-bpf"
    echo "   - If it shows '● falco-modern-bpf.service' and 'Active: active (running)' → Use: sudo journalctl -u falco-modern-bpf -f"
    echo "   - If not found or inactive → Try next command"
    echo ""
    echo "   sudo systemctl status falco-bpf"
    echo "   - If it shows '● falco-bpf.service' and 'Active: active (running)' → Use: sudo journalctl -u falco-bpf -f"
    echo ""
    echo "💡 Quick check - run this to see which is active:"
    echo '   for svc in falco falco-modern-bpf falco-bpf; do echo -n "$svc: "; systemctl is-active $svc 2>/dev/null || echo "not found"; done'
fi
echo ""
echo "========================================"
echo "📋 Next steps:"
echo "========================================"
echo ""
echo "1. Test nginx detection:"
echo '   curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"'  # SQL injection
echo '   curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"'  # XSS
echo '   curl "http://localhost/upload.php?file=../../../../../../etc/passwd"'  # Path traversal
echo ""
echo "2. View loaded plugins: sudo falco --list-plugins"
echo "3. Check nginx access log: tail -f /var/log/nginx/access.log"
echo ""
echo "For more information: https://github.com/${PLUGIN_REPO}"
echo ""