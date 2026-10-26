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
        header('Location: register.php'); exit;
    }
    
    $username = trim($_POST['username']);
    $email = trim($_POST['email']);
    $recovery = trim($_POST['recovery']);
    $password = $_POST['password'];
    $passwordRepeat = $_POST['passwordRepeat'];
    
    // Suspicious activity detection
    if (detect_suspicious_activity($username) || detect_suspicious_activity($email) || detect_suspicious_activity($password)) {
        $_SESSION['error'] = 'Suspicious activity detected.';
        header('Location: register.php'); exit;
    }
    
    if (!$username || !$email || !$password || $password !== $passwordRepeat){
        $_SESSION['error'] = 'Invalid input or passwords do not match.';
        header('Location: register.php'); exit;
    }
    
    // Password strength validation
    $password_errors = validate_password_strength($password);
    if (!empty($password_errors)) {
        $_SESSION['error'] = implode(', ', $password_errors);
        header('Location: register.php'); exit;
    }
    $stmt = $db->prepare('SELECT id FROM users WHERE username = ? OR email = ?');
    $stmt->execute([$username,$email]);
    if ($stmt->fetch()){
        $_SESSION['error'] = 'Username or email already in use.'; header('Location: register.php'); exit;
    }
    $hash = password_hash($password, PASSWORD_DEFAULT);
    $stmt = $db->prepare('INSERT INTO users (username,password,email,recovery_email,verified) VALUES (?,?,?,?,0)');
    $stmt->execute([$username,$hash,$email,$recovery]);
    $userId = $db->lastInsertId();
    
    // Store username in session for OTP verification
    $_SESSION['pending_verification'] = ['username' => $username, 'user_id' => $userId];
    $code = rand(100000,999999);
    $expires = time() + 60*15;
    $stmt = $db->prepare('INSERT INTO otps (user_id,code,expires_at) VALUES (?,?,?)');
    $stmt->execute([$userId,$code,$expires]);
    // Send OTP via PHPMailer if SMTP configured, otherwise keep preview in session.
    $sent = false;
    if (file_exists(__DIR__.'/../vendor/autoload.php')){
      require_once __DIR__.'/../vendor/autoload.php';
      require_once __DIR__.'/../app/config.php';
      if (!empty($config['smtp']['host'])){
        $mail = new PHPMailer\PHPMailer\PHPMailer(true);
        $smtpDebugEnabled = !empty($config['smtp']['debug']);
        $smtpDebugLog = '';
        try {
          $mail->isSMTP();
          $mail->Host = $config['smtp']['host'];
          $mail->SMTPAuth = true;
          $mail->Username = $config['smtp']['user'];
          $mail->Password = $config['smtp']['pass'];
          $port = intval($config['smtp']['port'] ?? 587);
          $mail->Port = $port;
          // choose encryption based on port if not explicitly set
          if ($port === 465) {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_SMTPS;
          } else {
            $mail->SMTPSecure = PHPMailer\PHPMailer\PHPMailer::ENCRYPTION_STARTTLS;
          }
          $fromEmail = $config['smtp']['from_email'] ?: $config['smtp']['user'];
          $fromName = $config['smtp']['from_name'] ?: 'Movie Stream';
          $mail->setFrom($fromEmail, $fromName);
          $mail->addAddress($email);
          $mail->isHTML(false);
          $mail->CharSet = 'UTF-8';
          $mail->Subject = 'Your verification code';
          $mail->Body = "Your OTP code: $code";
          if ($smtpDebugEnabled) {
            // capture debug output into $smtpDebugLog
            $mail->SMTPDebug = 2;
            $mail->Debugoutput = function($str, $level) use (&$smtpDebugLog) { $smtpDebugLog .= "[{$level}] {$str}\n"; };
          }
          $mail->send();
          $sent = true;
        } catch (PHPMailer\PHPMailer\Exception $e){
          $_SESSION['info'] = 'Account created but failed to send email: '.$e->getMessage();
          if (!empty($smtpDebugLog)) $_SESSION['smtp_debug'] = $smtpDebugLog;
        }
        if ($smtpDebugEnabled && !empty($smtpDebugLog)) {
          $_SESSION['smtp_debug'] = $smtpDebugLog;
        }
      }
    }
    if (!$sent){
        $_SESSION['error'] = 'Email settings are not configured correctly. Please configure your email settings to receive the verification code.';
      header('Location: register.php'); exit;
    } else {
      $_SESSION['info'] = 'Your account has been created successfully. A verification code has been sent to your email address.';
      header('Location: verify_otp.php'); exit;
    }
}

// Log page access
log_access($db, 'page_view_register');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Register</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>Create Account</h2>
  <p>Fill in the form below to create your new account.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input name="username" placeholder="Enter your username" required>
    <input name="email" placeholder="Enter your email address" required>
    <input name="recovery" placeholder="Enter your recovery email (optional)">
    <div class="password-input-wrap">
      <input type="password" name="password" placeholder="Enter your password" aria-describedby="password-rules" required>
      <span id="password-rules" class="input-tooltip">Password must be at least 8 characters long and include an uppercase letter, lowercase letter, number, and special character.</span>
    </div>
    <input type="password" name="passwordRepeat" placeholder="Confirm your password" required>
    <button type="submit">Create Account</button>
  </form>
  <?php if(!empty($_SESSION['smtp_debug'])){ echo '<pre class="debug">'.htmlspecialchars($_SESSION['smtp_debug']).'</pre>'; unset($_SESSION['smtp_debug']); } ?>
  <p><a href="login.php">Already have an account? Log in</a></p>
</div>
</body>
</html>
