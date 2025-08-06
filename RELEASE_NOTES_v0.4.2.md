# Release v0.4.2 - Falco 0.41.x Compatibility Fix

## 🐛 Critical Bug Fix

This release fixes compatibility issues with Falco 0.41.x by updating rule priority values.

## 🔄 What's Changed

### Rule Priority Updates
- Changed `HIGH` → `WARNING`
- Changed `MEDIUM` → `NOTICE`
- Changed `LOW` → `INFO`
- `CRITICAL` remains unchanged

### Installation Script Improvements
- Fixed `load_plugins` array update to ensure nginx plugin is loaded
- Added automatic load_plugins configuration

## 🚨 Important for Users

If you're using Falco 0.41.x and experiencing "Unknown source nginx" or priority validation errors, this release fixes those issues.

### Quick Fix for Existing Installations
```bash
# Update rules file
sudo curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/rules/nginx_rules.yaml \
  -o /etc/falco/rules.d/nginx_rules.yaml

# Update load_plugins if needed
sudo sed -i 's/load_plugins: \[\]/load_plugins: [nginx]/' /etc/falco/falco.yaml

# Restart Falco
sudo systemctl restart falco
```

## 💾 Installation

Use the same installation methods as before:

### One-liner Installation
```bash
curl -sSL https://raw.githubusercontent.com/takaosgb3/falco-plugin-nginx/main/install.sh | sudo bash
```

## 🔧 Compatibility

- **Falco**: 0.36.0+ (Tested with 0.41.3)
- **Architecture**: Linux x86_64
- **nginx**: 1.14.0+ with combined log format

## 📝 Note

No changes to the plugin binary - only rules and installation script were updated.

---
**Full Changelog**: https://github.com/takaosgb3/falco-plugin-nginx/compare/v0.4.1...v0.4.2