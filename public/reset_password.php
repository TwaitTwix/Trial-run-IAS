<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();

// Check if user has pending password recovery
if (!isset($_SESSION['password_recovery'])) {
    $_SESSION['error'] = 'No pending password recovery. Please start the recovery process.';
    header('Location: recover.php');
    exit;
}

$recovery = $_SESSION['password_recovery'];

if ($_SERVER['REQUEST_METHOD'] === 'POST'){
    // CSRF protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: reset_password.php');
        exit;
    }
    
    // Resend OTP
    if (isset($_POST['resend'])) {
        $userId = $recovery['user_id'];
        $newCode = rand(100000, 999999);
        $expires = time() + 60 * 15; // 15 minutes
        
        $stmt = $db->prepare('INSERT INTO otps (user_id, code, expires_at) VALUES (?, ?, ?)');
        $stmt->execute([$userId, $newCode, $expires]);
        
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
                    $mail->addAddress($recovery['recovery_email']);
                    $mail->isHTML(false);
                    $mail->CharSet = 'UTF-8';
                    $mail->Subject = 'Password Recovery Code';
                    $mail->Body = "Your password recovery code: $newCode\n\nThis code will expire in 15 minutes.\n\nIf you did not request this, please ignore this email.";
                    $mail->send();
                    $sent = true;
                } catch (PHPMailer\PHPMailer\Exception $e) {
                    $_SESSION['error'] = 'Failed to send email: ' . $e->getMessage();
                    header('Location: reset_password.php');
                    exit;
                }
            }
        }
        
        if (!$sent) {
            $_SESSION['error'] = 'SMTP not configured. Please configure email settings.';
            header('Location: reset_password.php');
            exit;
        }
        
        $_SESSION['info'] = 'New recovery code sent to your recovery email.';
        header('Location: reset_password.php');
        exit;
    }
    
    $code = trim($_POST['code']);
    $newPassword = $_POST['new_password'];
    $confirmPassword = $_POST['confirm_password'];
    
    // Verify OTP first
    $stmt = $db->prepare('SELECT * FROM otps WHERE user_id = ? AND code = ? ORDER BY id DESC LIMIT 1');
    $stmt->execute([$recovery['user_id'], $code]);
    $otp = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$otp || $otp['expires_at'] < time()) {
        $_SESSION['error'] = 'Invalid or expired recovery code';
        header('Location: reset_password.php');
        exit;
    }
    
    // Validate new password
    if ($newPassword !== $confirmPassword) {
        $_SESSION['error'] = 'Passwords do not match';
        header('Location: reset_password.php');
        exit;
    }
    
    // Password strength validation
    $password_errors = validate_password_strength($newPassword);
    if (!empty($password_errors)) {
        $_SESSION['error'] = implode(', ', $password_errors);
        header('Location: reset_password.php');
        exit;
    }
    
    // Update password
    $hash = password_hash($newPassword, PASSWORD_DEFAULT);
    $stmt = $db->prepare('UPDATE users SET password = ? WHERE id = ?');
    $stmt->execute([$hash, $recovery['user_id']]);
    
    // Clear recovery session
    unset($_SESSION['password_recovery']);
    
    // Clear used OTP
    $stmt = $db->prepare('DELETE FROM otps WHERE id = ?');
    $stmt->execute([$otp['id']]);

    create_account_notification($db, $recovery['user_id'], 'Password reset', 'Your password was reset successfully using the recovery code sent to your email address.');
    
    $_SESSION['info'] = 'Password successfully reset. You can now login with your new password.';
    header('Location: login.php');
    exit;
}

// Log page access
log_access($db, 'page_view_reset_password');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>Reset Password</h2>
  <p>Enter the recovery code sent to your recovery email and set a new password.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input type="text" name="code" placeholder="Enter the 6-digit recovery code" required pattern="[0-9]{6}" maxlength="6">
    <div class="password-input-wrap">
      <input type="password" name="new_password" placeholder="Enter your new password" aria-describedby="password-rules" required>
      <span id="password-rules" class="input-tooltip">Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character.</span>
    </div>
    <input type="password" name="confirm_password" placeholder="Confirm your new password" required>
    <button type="submit">Reset Password</button>
  </form>
  <form method="post" style="margin-top: 10px;">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <button type="submit" name="resend" value="1">Resend Recovery Code</button>
  </form>
  <p><a href="recover.php">Return to Account Recovery</a></p>
</div>
</body>
</html>
