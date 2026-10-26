<?php
// Security functions and configurations

// CSRF Protection
function generate_csrf_token() {
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function verify_csrf_token($token) {
    if (!isset($_SESSION['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $token)) {
        return false;
    }
    return true;
}

// Rate Limiting
function check_rate_limit($identifier, $max_attempts = 5, $time_window = 120) {
    $key = 'rate_limit_' . md5($identifier);
    
    if (!isset($_SESSION[$key])) {
        $_SESSION[$key] = ['attempts' => 0, 'first_attempt' => time()];
    }
    
    $data = $_SESSION[$key];
    
    // Reset if time window has passed
    if (time() - $data['first_attempt'] > $time_window) {
        $_SESSION[$key] = ['attempts' => 1, 'first_attempt' => time()];
        return true;
    }
    
    // Check if max attempts exceeded
    if ($data['attempts'] >= $max_attempts) {
        return false;
    }
    
    $_SESSION[$key]['attempts']++;
    return true;
}

function get_rate_limit_remaining($identifier, $max_attempts = 5, $time_window = 120) {
    $key = 'rate_limit_' . md5($identifier);
    
    if (!isset($_SESSION[$key])) {
        return $max_attempts;
    }
    
    $data = $_SESSION[$key];
    
    // Reset if time window has passed
    if (time() - $data['first_attempt'] > $time_window) {
        return $max_attempts;
    }
    
    return max(0, $max_attempts - $data['attempts']);
}

// Password Strength Validation
function validate_password_strength($password) {
    $errors = [];
    
    if (strlen($password) < 8) {
        $errors[] = 'Password must be at least 8 characters long';
    }
    
    if (!preg_match('/[A-Z]/', $password)) {
        $errors[] = 'Password must contain at least one uppercase letter';
    }
    
    if (!preg_match('/[a-z]/', $password)) {
        $errors[] = 'Password must contain at least one lowercase letter';
    }
    
    if (!preg_match('/[0-9]/', $password)) {
        $errors[] = 'Password must contain at least one number';
    }
    
    if (!preg_match('/[^A-Za-z0-9]/', $password)) {
        $errors[] = 'Password must contain at least one special character';
    }
    
    return $errors;
}

// Security Headers
function send_security_headers() {
    header('X-Frame-Options: DENY');
    header('X-Content-Type-Options: nosniff');
    header('X-XSS-Protection: 1; mode=block');
    header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    header('Content-Security-Policy: default-src \'self\'; script-src \'self\' \'unsafe-inline\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data: https:; font-src \'self\'; connect-src \'self\'; frame-ancestors \'none\';');
    header('Referrer-Policy: strict-origin-when-cross-origin');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
}

// Secure Session Configuration (must be called BEFORE session_start())
function configure_session_ini() {
    ini_set('session.cookie_httponly', 1);
    ini_set('session.cookie_secure', 1);
    ini_set('session.use_strict_mode', 1);
    ini_set('session.cookie_samesite', 'Strict');
}

// Session security after session is started
function configure_secure_session() {
    // Regenerate session ID on login
    if (isset($_SESSION['user']) && !isset($_SESSION['regenerated'])) {
        session_regenerate_id(true);
        $_SESSION['regenerated'] = true;
    }
}

// Logging function
function log_access($db, $action) {
    if (!isset($_SESSION['user'])) {
        return;
    }
    
    $userId = $_SESSION['user']['id'];
    $username = $_SESSION['user']['username'];
    $ipAddress = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    $userAgent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
    
    try {
        $stmt = $db->prepare('INSERT INTO access_logs (user_id, username, action, ip_address, user_agent) VALUES (?, ?, ?, ?, ?)');
        $stmt->execute([$userId, $username, $action, $ipAddress, $userAgent]);
    } catch (Exception $e) {
        // Log silently to avoid breaking functionality
    }
}

// Input Sanitization
function sanitize_input($input) {
    return htmlspecialchars(trim($input), ENT_QUOTES, 'UTF-8');
}

function create_account_notification($db, $userId, $title, $message) {
    if (empty($userId) || empty($title) || empty($message)) {
        return false;
    }

    try {
        $stmt = $db->prepare('INSERT INTO account_notifications (user_id, title, message) VALUES (?, ?, ?)');
        return $stmt->execute([$userId, $title, $message]);
    } catch (Exception $e) {
        return false;
    }
}

// Check for common attack patterns
function detect_suspicious_activity($input) {
    $patterns = [
        '/<script\b[^>]*>(.*?)<\/script>/is',
        '/javascript:/i',
        '/on\w+\s*=/i',
        '/<\?php/',
        '/\.\.\//',
        '/union\s+select/i',
        '/drop\s+table/i',
        '/exec\s*\(/i',
        '/eval\s*\(/i'
    ];
    
    foreach ($patterns as $pattern) {
        if (preg_match($pattern, $input)) {
            return true;
        }
    }
    
    return false;
}
?>
