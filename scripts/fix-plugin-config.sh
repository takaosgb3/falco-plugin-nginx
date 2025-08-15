#!/bin/bash
#
# Fix script for Falco nginx plugin configuration
#

set -euo pipefail

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

log "Fixing Falco nginx plugin configuration..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    error "Please run as root (use sudo)"
fi

# Backup current config
if [ -f /etc/falco/falco.yaml ]; then
    cp /etc/falco/falco.yaml /etc/falco/falco.yaml.backup.$(date +%Y%m%d%H%M%S)
    success "Created backup of falco.yaml"
else
    error "Falco configuration file not found at /etc/falco/falco.yaml"
fi

# Check if plugin binary exists
if [ ! -f /usr/share/falco/plugins/libfalco-nginx-plugin.so ]; then
    error "Plugin binary not found at /usr/share/falco/plugins/libfalco-nginx-plugin.so"
fi

# Check if rules exist
if [ ! -f /etc/falco/rules.d/nginx_rules.yaml ]; then
    error "Rules file not found at /etc/falco/rules.d/nginx_rules.yaml"
fi

# Update load_plugins
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

# Check if plugins section exists
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

# Verify configuration
log "Verifying configuration..."
echo ""
echo "Current load_plugins setting:"
grep "^load_plugins:" /etc/falco/falco.yaml || echo "Not found"
echo ""
echo "nginx plugin configuration:"
grep -A5 "name: nginx" /etc/falco/falco.yaml || echo "Not found"
echo ""

# Test plugin loading
log "Testing plugin loading..."
if falco --list-plugins 2>/dev/null | grep -q nginx; then
    success "nginx plugin loads successfully!"
else
    warning "Plugin still not loading. Checking for issues..."

    # Try running Falco with verbose output
    echo ""
    echo "Attempting to run Falco with verbose output:"
    falco -c /etc/falco/falco.yaml --disable-source syscall --list-plugins 2>&1 | head -20
fi

echo ""
log "Configuration fix complete!"
echo ""
echo "Next steps:"
echo "1. Test plugin loading: sudo falco --list-plugins"
echo "2. Validate rules: sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml"
echo "3. Run Falco: sudo falco -c /etc/falco/falco.yaml --disable-source syscall"
echo ""
echo "If issues persist, check the full config with: cat /etc/falco/falco.yaml"