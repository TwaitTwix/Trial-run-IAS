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
        header('Location: recover.php');
        exit;
    }
    
    $username = trim($_POST['username']);
    
    // Rate limiting check
    if (!check_rate_limit($_SERVER['REMOTE_ADDR'] ?? 'unknown', 3, 900)) {
        $_SESSION['error'] = 'Too many recovery attempts. Please try again in 15 minutes.';
        header('Location: recover.php');
        exit;
    }
    
    // Suspicious activity detection
    if (detect_suspicious_activity($username)) {
        $_SESSION['error'] = 'Suspicious activity detected.';
        header('Location: recover.php');
        exit;
    }
    
    $stmt = $db->prepare('SELECT id, username, email, recovery_email FROM users WHERE username = ?');
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$user) {
        // Don't reveal if user exists or not for security
        $_SESSION['info'] = 'If the username exists, a recovery code will be sent to the recovery email.';
        header('Location: recover.php');
        exit;
    }
    
    if (empty($user['recovery_email'])) {
        $_SESSION['error'] = 'No recovery email configured for this account. Contact administrator.';
        header('Location: recover.php');
        exit;
    }
    
    // Generate OTP
    $code = rand(100000, 999999);
    $expires = time() + 60 * 15; // 15 minutes
    
    $stmt = $db->prepare('INSERT INTO otps (user_id, code, expires_at) VALUES (?, ?, ?)');
    $stmt->execute([$user['id'], $code, $expires]);
    
    // Send OTP via PHPMailer
    $sent = false;
    if (file_exists(__DIR__ . '/../vendor/autoload.php')) {
        require_once __DIR__ . '/../vendor/autoload.php';
        require_once __DIR__ . '/../app/config.php';
        if (!empty($config['smtp']['host'])) {
            $mail = new PHPMailer\PHPMailer\PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host = $config['smtp']['host'];
                $mail->SMTPAuth = true;
                $mail->Username = $config['smtp']['user'];
                $mail->Password = $config['smtp']['pass'];
                $port = intval($config['smtp']['port'] ?? 587);
                $mail->Port = $port;
                if ($port === 465) {
                    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
                } else {
                    $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
                }
                $fromEmail = $config['smtp']['from_email'] ?: $config['smtp']['user'];
                $fromName = $config['smtp']['from_name'] ?: 'Movie Stream';
                $mail->setFrom($fromEmail, $fromName);
                $mail->addAddress($user['recovery_email']);
                $mail->isHTML(false);
                $mail->CharSet = 'UTF-8';
                $mail->Subject = 'Password Recovery Code';
                $mail->Body = "Your password recovery code: $code\n\nThis code will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.";
                $mail->send();
                $sent = true;
            } catch (PHPMailer\PHPMailer\Exception $e) {
                $_SESSION['error'] = 'Failed to send email: ' . $e->getMessage();
                header('Location: recover.php');
                exit;
            }
        }
    }
    
    if (!$sent) {
        $_SESSION['error'] = 'SMTP not configured. Please configure email settings.';
        header('Location: recover.php');
        exit;
    }
    
    // Store recovery info in session
    $_SESSION['password_recovery'] = [
        'user_id' => $user['id'],
        'username' => $user['username'],
        'recovery_email' => $user['recovery_email']
    ];
    
    $_SESSION['info'] = 'Recovery code sent to your recovery email.';
    header('Location: reset_password.php');
    exit;
}

// Log page access
log_access($db, 'page_view_recover');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Recover Account</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>Recover Account</h2>
  <p>Enter your username to receive a password recovery code at your recovery email address.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input name="username" placeholder="Enter your username" required>
    <button type="submit">Send Recovery Code</button>
  </form>
  <p><a href="login.php">Return to Login</a></p>
</div>
</body>
</html>
