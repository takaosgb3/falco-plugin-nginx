#!/bin/bash
#
# Test script to verify GitHub API access for falco-plugin-nginx
#

set -euo pipefail

PLUGIN_REPO="takaosgb3/falco-plugin-nginx"

echo "Testing GitHub API access..."
echo "Repository: $PLUGIN_REPO"
echo ""

# Test 1: Direct API call with curl
echo "Test 1: Direct curl to GitHub API"
echo "Command: curl -s https://api.github.com/repos/${PLUGIN_REPO}/releases/latest | jq -r '.tag_name'"
curl -s "https://api.github.com/repos/${PLUGIN_REPO}/releases/latest" | jq -r '.tag_name' || echo "Failed"
echo ""

# Test 2: Check with verbose output
echo "Test 2: Verbose curl output"
echo "Command: curl -sSL -v https://api.github.com/repos/${PLUGIN_REPO}/releases/latest 2>&1 | head -20"
curl -sSL -v "https://api.github.com/repos/${PLUGIN_REPO}/releases/latest" 2>&1 | head -20
echo ""

# Test 3: Try wget
echo "Test 3: Using wget"
echo "Command: wget -qO- https://api.github.com/repos/${PLUGIN_REPO}/releases/latest | jq -r '.tag_name'"
wget -qO- "https://api.github.com/repos/${PLUGIN_REPO}/releases/latest" | jq -r '.tag_name' || echo "Failed"
echo ""

# Test 4: Check release assets
echo "Test 4: List release assets"
LATEST_VERSION=$(curl -s "https://api.github.com/repos/${PLUGIN_REPO}/releases/latest" | jq -r '.tag_name')
if [ -n "$LATEST_VERSION" ]; then
    echo "Latest version: $LATEST_VERSION"
    echo "Binary URL: https://github.com/${PLUGIN_REPO}/releases/download/${LATEST_VERSION}/libfalco-nginx-plugin-linux-amd64.so"
    echo "Rules URL: https://github.com/${PLUGIN_REPO}/releases/download/${LATEST_VERSION}/nginx_rules.yaml"
    
    # Test download
    echo ""
    echo "Test 5: Test binary download"
    if curl -sL --head "https://github.com/${PLUGIN_REPO}/releases/download/${LATEST_VERSION}/libfalco-nginx-plugin-linux-amd64.so" | grep -q "200 OK"; then
        echo "✓ Binary is accessible"
    else
        echo "✗ Binary download failed"
    fi
    
    if curl -sL --head "https://github.com/${PLUGIN_REPO}/releases/download/${LATEST_VERSION}/nginx_rules.yaml" | grep -q "200 OK"; then
        echo "✓ Rules file is accessible"
    else
        echo "✗ Rules file download failed"
    fi
else
    echo "Failed to get latest version"
fi