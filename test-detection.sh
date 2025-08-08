#\!/bin/bash

echo "=== Checking Falco nginx plugin detection ==="

# 1. Check if plugin is loaded
echo "1. Checking plugin status:"
sudo falco --list-plugins | grep nginx || echo "Plugin not listed"

# 2. Check if rules are loaded
echo -e "\n2. Checking rules:"
ls -la /etc/falco/rules.d/nginx_rules.yaml 2>/dev/null || echo "Rules file not found"

# 3. Check nginx access log
echo -e "\n3. Checking nginx access log:"
sudo tail -5 /var/log/nginx/access.log

# 4. Check what's in the access log for the attacks
echo -e "\n4. Searching for attack patterns in log:"
sudo grep -E "(%27|%3C|\.\.)" /var/log/nginx/access.log | tail -3

# 5. Check Falco configuration
echo -e "\n5. Checking Falco configuration:"
sudo grep -A 5 "plugins:" /etc/falco/falco.yaml | head -10

# 6. Check if Falco is running with the right flags
echo -e "\n6. Checking Falco service:"
sudo systemctl status falco --no-pager | grep "Active:"

# 7. Test Falco rule validation
echo -e "\n7. Validating nginx rules:"
sudo falco --validate /etc/falco/rules.d/nginx_rules.yaml 2>&1 | grep -E "(Ok|Error|Invalid)"
