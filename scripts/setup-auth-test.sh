#!/bin/bash
#
# Setup authentication test endpoints for brute force detection testing
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "Setting up authentication test endpoints..."

# Check if nginx is installed
if ! command -v nginx &> /dev/null; then
    echo "Error: nginx is not installed"
    exit 1
fi

# Create test authentication endpoints
WEB_ROOT="/var/www/html"
mkdir -p "$WEB_ROOT/admin"
mkdir -p "$WEB_ROOT/api"

# Create login page with basic auth simulation
cat > "$WEB_ROOT/login.php" << 'EOF'
<?php
// Simulate login endpoint
header('Content-Type: application/json');

// Get credentials from POST or GET
$username = $_POST['username'] ?? $_GET['username'] ?? '';
$password = $_POST['password'] ?? $_GET['password'] ?? '';

// Simulate authentication
if ($username === 'admin' && $password === 'admin123') {
    http_response_code(200);
    echo json_encode(['status' => 'success', 'message' => 'Login successful']);
} elseif ($username === 'test' && $password === 'test123') {
    http_response_code(200);
    echo json_encode(['status' => 'success', 'message' => 'Login successful']);
} else {
    // Return 401 for failed authentication
    http_response_code(401);
    echo json_encode(['status' => 'error', 'message' => 'Invalid credentials']);
}
?>
EOF

# Create admin login page
cat > "$WEB_ROOT/admin/index.php" << 'EOF'
<?php
// Simulate admin panel with basic auth
$auth_header = $_SERVER['HTTP_AUTHORIZATION'] ?? '';

if (!$auth_header || !preg_match('/Basic\s+(.*)$/i', $auth_header, $matches)) {
    header('WWW-Authenticate: Basic realm="Admin Area"');
    http_response_code(401);
    echo "Authorization required";
    exit;
}

$credentials = base64_decode($matches[1]);
list($username, $password) = explode(':', $credentials, 2);

if ($username !== 'admin' || $password !== 'secret') {
    http_response_code(401);
    echo "Invalid credentials";
    exit;
}

echo "Welcome to admin panel!";
?>
EOF

# Create API login endpoint
cat > "$WEB_ROOT/api/login.php" << 'EOF'
<?php
// API login endpoint
header('Content-Type: application/json');

$data = json_decode(file_get_contents('php://input'), true);
$username = $data['username'] ?? $_POST['username'] ?? '';
$password = $data['password'] ?? $_POST['password'] ?? '';

if (empty($username) || empty($password)) {
    http_response_code(400);
    echo json_encode(['error' => 'Missing credentials']);
    exit;
}

// Simulate different response codes
if ($username === 'blocked') {
    http_response_code(403);
    echo json_encode(['error' => 'Account blocked']);
} elseif ($username === 'admin' && $password === 'admin') {
    http_response_code(200);
    echo json_encode(['token' => 'jwt_token_here']);
} else {
    http_response_code(401);
    echo json_encode(['error' => 'Invalid username or password']);
}
?>
EOF

# Create password reset endpoint
cat > "$WEB_ROOT/password-reset.php" << 'EOF'
<?php
// Password reset endpoint
header('Content-Type: application/json');

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

$email = $_POST['email'] ?? json_decode(file_get_contents('php://input'), true)['email'] ?? '';

if (empty($email)) {
    http_response_code(400);
    echo json_encode(['error' => 'Email required']);
} else {
    http_response_code(200);
    echo json_encode(['message' => 'Password reset link sent']);
}
?>
EOF

# Create WordPress login simulation
mkdir -p "$WEB_ROOT/wp-admin"
cat > "$WEB_ROOT/wp-login.php" << 'EOF'
<?php
// WordPress login simulation
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $user = $_POST['log'] ?? '';
    $pass = $_POST['pwd'] ?? '';

    if ($user === 'admin' && $pass === 'wordpress') {
        http_response_code(302);
        header('Location: /wp-admin/');
    } else {
        http_response_code(401);
        echo "Login failed";
    }
} else {
    echo '<form method="post">
        Username: <input name="log"><br>
        Password: <input name="pwd" type="password"><br>
        <input type="submit" value="Login">
    </form>';
}
?>
EOF

# Set permissions
chown -R www-data:www-data "$WEB_ROOT"
chmod -R 755 "$WEB_ROOT"

# Restart nginx
systemctl restart nginx

echo -e "${GREEN}✅ Authentication test endpoints created${NC}"
echo ""
echo "Test endpoints available:"
echo "  - /login.php - Basic login endpoint (returns 401 on failure)"
echo "  - /admin/ - HTTP Basic Auth protected (401 without auth)"
echo "  - /api/login.php - API login endpoint (JSON)"
echo "  - /password-reset.php - Password reset endpoint"
echo "  - /wp-login.php - WordPress login simulation"
echo ""
echo -e "${YELLOW}Test brute force detection:${NC}"
echo ""
echo "# Single failed login:"
echo 'curl -X POST "http://localhost/login.php" -d "username=test&password=wrong"'
echo ""
echo "# Multiple failed attempts (simulate brute force):"
echo 'for i in {1..10}; do curl -X POST "http://localhost/login.php" -d "username=admin&password=pass$i"; done'
echo ""
echo "# API authentication failure:"
echo 'curl -X POST "http://localhost/api/login.php" -H "Content-Type: application/json" -d "{\"username\":\"test\",\"password\":\"wrong\"}"'
echo ""
echo "# Basic Auth failure:"
echo 'curl -u wrong:pass "http://localhost/admin/"'
echo ""
echo "# Password reset abuse:"
echo 'for i in {1..5}; do curl -X POST "http://localhost/password-reset.php" -d "email=test$i@example.com"; done'
echo ""
echo "Monitor with: sudo journalctl -u falco -f"