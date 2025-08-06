#!/bin/bash
#
# Setup log rotation for nginx logs
# Optimized for Falco nginx plugin
#

set -euo pipefail

# Check root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Create logrotate config
cat > /etc/logrotate.d/nginx-falco << 'EOF'
# Falco nginx plugin optimized log rotation
/var/log/nginx/*.log {
    daily
    size 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    create 0640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 $(cat /var/run/nginx.pid)
        fi
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx > /dev/null 2>&1 || true
        fi
    endscript
}
EOF

echo "✅ Log rotation configured successfully"
echo ""
echo "Settings:"
echo "  - Rotation: Daily or when size > 100MB"
echo "  - Keep: 14 rotated logs"
echo "  - Compression: Enabled"
echo ""
echo "Test with: sudo logrotate -f /etc/logrotate.d/nginx-falco"