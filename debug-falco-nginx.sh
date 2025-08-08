#\!/bin/bash

echo "=== Falco nginx Plugin Debug Script ==="
echo "Date: $(date)"
echo ""

# 1. Check Falco is running in plugin mode
echo "1. Checking Falco process:"
ps aux | grep falco | grep -v grep

# 2. Check if plugin is actually loaded
echo -e "\n2. Checking loaded plugins:"
sudo falco --list-plugins 2>/dev/null | grep nginx

# 3. Check load_plugins configuration
echo -e "\n3. Checking load_plugins setting:"
sudo grep "load_plugins:" /etc/falco/falco.yaml

# 4. Check nginx log format
echo -e "\n4. Recent nginx access log entries:"
sudo tail -3 /var/log/nginx/access.log

# 5. Check if the log file is being monitored
echo -e "\n5. Checking plugin configuration:"
sudo grep -A 10 "name: nginx" /etc/falco/falco.yaml

# 6. Try to run Falco in foreground with debug
echo -e "\n6. Testing Falco with nginx plugin (10 seconds):"
echo "Running: sudo timeout 10 falco -c /etc/falco/falco.yaml --disable-source syscall -A 2>&1"
sudo timeout 10 falco -c /etc/falco/falco.yaml --disable-source syscall -A 2>&1 | grep -E "(nginx|Loaded|Error|Warning)"

# 7. Check if rules file exists and is valid
echo -e "\n7. Checking rules file:"
if [ -f /etc/falco/rules.d/nginx_rules.yaml ]; then
    echo "Rules file exists"
    echo "First rule in file:"
    grep -A 3 "^- rule:" /etc/falco/rules.d/nginx_rules.yaml | head -5
else
    echo "ERROR: Rules file not found at /etc/falco/rules.d/nginx_rules.yaml"
fi

# 8. Generate test traffic
echo -e "\n8. Generating test attack traffic:"
curl -s "http://localhost/test.php?q=%27%20OR%20%271%27%3D%271" > /dev/null
echo "Sent SQL injection test"
sleep 2

# 9. Check if anything was detected
echo -e "\n9. Checking Falco logs for detections:"
sudo journalctl -u falco --since "1 minute ago" --no-pager | grep -E "(SQL|XSS|Path|injection|attack)" || echo "No detections found"

echo -e "\n=== Debug complete ==="
