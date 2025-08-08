#\!/bin/bash

echo "=== Manual Falco nginx Plugin Test ==="
echo ""
echo "1. Stopping Falco service temporarily..."
sudo systemctl stop falco

echo ""
echo "2. Running Falco in foreground with nginx plugin only..."
echo "   (Press Ctrl+C to stop)"
echo ""
echo "In another terminal, run:"
echo '  curl "http://localhost/test.php?q=%27%20OR%20%271%27%3D%271"'
echo '  curl "http://localhost/test.php?q=%3Cscript%3Ealert(1)%3C/script%3E"'
echo ""
echo "Starting Falco..."
sudo falco -c /etc/falco/falco.yaml \
    --disable-source syscall \
    -r /etc/falco/rules.d/nginx_rules.yaml \
    -A
