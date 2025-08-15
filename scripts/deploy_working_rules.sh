#!/bin/bash

# Deploy Working Falco nginx Rules Script
# This script deploys a tested and working rules file

echo "🚀 Deploying working Falco nginx rules..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo "❌ Please run as root (use sudo)"
    exit 1
fi

# Clean up any problematic files
echo "🧹 Cleaning up old rule files..."
rm -f /etc/falco/rules.d/attack_test.yaml
rm -f /etc/falco/rules.d/query_string_test.yaml
rm -f /etc/falco/rules.d/nginx_rules_minimal.yaml

# Download the working rules file
echo "📥 Downloading working rules file..."
curl -fsSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules_simple.yaml -o /etc/falco/rules.d/nginx_rules.yaml

# Verify download
if [ ! -f /etc/falco/rules.d/nginx_rules.yaml ]; then
    echo "❌ Failed to download rules file"
    exit 1
fi

# Restart Falco service
echo "🔄 Restarting Falco nginx service..."
systemctl restart falco-nginx.service

# Check service status
sleep 2
if systemctl is-active --quiet falco-nginx.service; then
    echo "✅ Falco nginx service is running successfully!"
    echo ""
    echo "🎯 To test attack detection, run:"
    echo "   curl \"http://localhost/search.php?q=' OR '1'='1\""
    echo ""
    echo "📋 To monitor alerts:"
    echo "   sudo journalctl -u falco-nginx.service -f"
else
    echo "❌ Falco nginx service failed to start"
    echo "Check logs with: sudo journalctl -u falco-nginx.service -n 50"
    exit 1
fi