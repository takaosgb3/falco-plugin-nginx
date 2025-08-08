#!/bin/bash
#
# Setup test web content for Falco nginx plugin testing
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

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    error "Please run as root (use sudo)"
fi

log "Setting up test web content for security testing..."

# Create web root directory
WEB_ROOT="/var/www/test-site"
mkdir -p "$WEB_ROOT"

# Create index.html
cat > "$WEB_ROOT/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Falco Nginx Plugin Test Site</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        .warning { background-color: #ffe6e6; padding: 10px; border-radius: 5px; }
        code { background-color: #f0f0f0; padding: 2px 5px; border-radius: 3px; }
    </style>
</head>
<body>
    <h1>🛡️ Falco Nginx Plugin Test Site</h1>
    <div class="warning">
        <strong>⚠️ WARNING:</strong> This site is designed for security testing only. 
        It contains vulnerable endpoints for testing Falco nginx plugin detection capabilities.
    </div>
    
    <h2>Available Test Endpoints</h2>
    <ul>
        <li><a href="/search.php">Search Page</a> - Test SQL injection detection</li>
        <li><a href="/api/users.php">User API</a> - Test various API attacks</li>
        <li><a href="/upload.php">File Upload</a> - Test directory traversal</li>
        <li><a href="/admin/">Admin Area</a> - Test brute force detection</li>
    </ul>
    
    <h2>Attack Examples</h2>
    <h3>SQL Injection:</h3>
    <code>curl "http://localhost/search.php?q=' OR '1'='1"</code>
    
    <h3>XSS Attack:</h3>
    <code>curl "http://localhost/search.php?q=&lt;script&gt;alert('XSS')&lt;/script&gt;"</code>
    
    <h3>Directory Traversal:</h3>
    <code>curl "http://localhost/upload.php?file=../../../../../../etc/passwd"</code>
</body>
</html>
EOF

# Create search.php (dummy file for logging)
cat > "$WEB_ROOT/search.php" << 'EOF'
<?php
// This is a dummy file for Falco nginx plugin testing
// Actual PHP processing is not required - nginx will log the requests
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Search Page</title>
</head>
<body>
    <h1>Product Search</h1>
    <form method="GET">
        <input type="text" name="q" placeholder="Search products..." 
               value="<?php echo htmlspecialchars($_GET['q'] ?? ''); ?>">
        <input type="submit" value="Search">
    </form>
    <p>This is a test page for SQL injection detection.</p>
</body>
</html>
EOF

# Create API directory and files
mkdir -p "$WEB_ROOT/api"
cat > "$WEB_ROOT/api/users.php" << 'EOF'
<?php
// Dummy API endpoint for testing
header('Content-Type: application/json; charset=UTF-8');
echo json_encode([
    'status' => 'ok',
    'message' => 'This is a test API endpoint',
    'users' => []
]);
?>
EOF

# Create upload.php
cat > "$WEB_ROOT/upload.php" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>File Upload</title>
</head>
<body>
    <h1>File Upload Test</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <input type="submit" value="Upload">
    </form>
    <p>This is a test page for directory traversal detection.</p>
</body>
</html>
EOF

# Create admin directory
mkdir -p "$WEB_ROOT/admin"
cat > "$WEB_ROOT/admin/index.html" << 'EOF'
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Admin Login</title>
</head>
<body>
    <h1>Administrator Login</h1>
    <form method="POST" action="/admin/login.php">
        <label>Username: <input type="text" name="username"></label><br>
        <label>Password: <input type="password" name="password"></label><br>
        <input type="submit" value="Login">
    </form>
    <p>This is a test page for brute force detection.</p>
</body>
</html>
EOF

cat > "$WEB_ROOT/admin/login.php" << 'EOF'
<?php
// Dummy login page
http_response_code(401);
?>
<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>Login Failed</title>
</head>
<body>
    <h1>Login Failed</h1>
    <p>Invalid username or password.</p>
    <a href="/admin/">Try again</a>
</body>
</html>
EOF

# Set permissions
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

# Configure nginx site
cat > /etc/nginx/sites-available/test-site << 'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/test-site;
    index index.html index.php;

    server_name _;

    # Ensure access log is enabled
    access_log /var/log/nginx/access.log combined;
    error_log /var/log/nginx/error.log;

    location / {
        try_files $uri $uri/ =404;
    }

    # PHP files (even without PHP installed, nginx will log the requests)
    location ~ \.php$ {
        # Return a dummy response for PHP files
        add_header Content-Type "text/html; charset=UTF-8";
        return 200 "PHP endpoint accessed. Request logged for Falco detection.";
    }

    # Admin area
    location /admin {
        try_files $uri $uri/ /admin/index.html;
    }
}
EOF

# Enable the test site
rm -f /etc/nginx/sites-enabled/default
ln -sf /etc/nginx/sites-available/test-site /etc/nginx/sites-enabled/

# Test nginx configuration
if nginx -t; then
    success "Nginx configuration is valid"
else
    error "Nginx configuration test failed"
fi

# Reload nginx
systemctl reload nginx || service nginx reload

success "Test web content setup complete!"
echo ""
log "You can now test security detection with commands like:"
echo '  curl "http://localhost/search.php?q=%27%20OR%20%271%27%3D%271"'
echo '  curl "http://localhost/search.php?q=%3Cscript%3Ealert(1)%3C/script%3E"'
echo '  curl "http://localhost/upload.php?file=../../../../../../etc/passwd"'
echo '  curl "http://localhost/api/users.php?cmd=;cat /etc/passwd"'
echo ""
log "Monitor Falco alerts with: sudo journalctl -u falco-nginx -f"