<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();
if ($_SERVER['REQUEST_METHOD'] === 'POST'){
    // CSRF protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: login.php'); exit;
    }
    
    $username = trim($_POST['username']);
    $password = $_POST['password'];
    
    // Rate limiting check
    if (!check_rate_limit($_SERVER['REMOTE_ADDR'] ?? 'unknown', 5, 300)) {
        $_SESSION['error'] = 'Too many login attempts. Please try again in 5 minutes.';
        header('Location: login.php'); exit;
    }
    
    // Suspicious activity detection
    if (detect_suspicious_activity($username) || detect_suspicious_activity($password)) {
        $_SESSION['error'] = 'Suspicious activity detected.';
        header('Location: login.php'); exit;
    }
    $stmt = $db->prepare('SELECT * FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if ($user && password_verify($password, $user['password'])){
        if ($user['locked'] || $user['banned']){ 
            $_SESSION['error'] = 'Account unavailable. Please contact the administrator.';
            header('Location: login.php'); exit; 
        }
        $_SESSION['user'] = ['id'=>$user['id'],'username'=>$user['username'],'role'=>$user['role']];
        // Clear rate limit on successful login
        $key = 'rate_limit_' . md5($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        unset($_SESSION[$key]);
        log_access($db, 'login_success');
        header('Location: index.php'); exit;
    } else { 
        // Track failed login attempts for automatic lockout
        $failed_key = 'failed_login_' . md5($username);
        if (!isset($_SESSION[$failed_key])) {
            $_SESSION[$failed_key] = ['attempts' => 0, 'first_attempt' => time()];
        }
        $_SESSION[$failed_key]['attempts']++;
        
        // Auto-lock account after 10 failed attempts within 15 minutes
        if ($_SESSION[$failed_key]['attempts'] >= 10 && (time() - $_SESSION[$failed_key]['first_attempt']) < 900) {
            if ($user) {
                $stmt = $db->prepare('UPDATE users SET locked = 1 WHERE id = ?');
                $stmt->execute([$user['id']]);
                $_SESSION['error'] = 'Account locked due to too many failed login attempts. Contact administrator.';
            }
        } else {
            $_SESSION['error'] = 'Invalid credentials. Attempts remaining: ' . get_rate_limit_remaining($_SERVER['REMOTE_ADDR'] ?? 'unknown', 5, 300);
        }
        header('Location: login.php'); exit; 
    }
}
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>Login</h2>
  <p>Enter your username and password to access your account.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input name="username" placeholder="Enter your username" required>
    <input type="password" name="password" placeholder="Enter your password" required>
    <button type="submit">Login</button>
  </form>
  <p><a href="register.php">Create an account</a></p>
  <p><a href="recover.php">Forgot your password?</a></p>
</div>
</body>
</html>
