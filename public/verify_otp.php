<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();

// Check if user has pending verification
if (!isset($_SESSION['pending_verification'])) {
    $_SESSION['error'] = 'No pending verification. Please register first.';
    header('Location: register.php');
    exit;
}

$pending = $_SESSION['pending_verification'];

if ($_SERVER['REQUEST_METHOD'] === 'POST'){
    // CSRF protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: verify_otp.php');
        exit;
    }
    
    $code = trim($_POST['code']);
    
    // Resend OTP
    if (isset($_POST['resend'])) {
        $userId = $pending['user_id'];
        $newCode = rand(100000,999999);
        $expires = time() + 60*15;
        
        $stmt = $db->prepare('INSERT INTO otps (user_id,code,expires_at) VALUES (?,?,?)');
        $stmt->execute([$userId,$newCode,$expires]);
        
        // Get user email
        $stmt = $db->prepare('SELECT email FROM users WHERE id = ?');
        $stmt->execute([$userId]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);
        $email = $user['email'];
        
        // Send OTP via PHPMailer if SMTP configured, otherwise keep preview in session.
        $sent = false;
        if (file_exists(__DIR__.'/../vendor/autoload.php')){
            require_once __DIR__.'/../vendor/autoload.php';
            require_once __DIR__.'/../app/config.php';
            if (!empty($config['smtp']['host'])){
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
                    $mail->addAddress($email);
                    $mail->isHTML(false);
                    $mail->CharSet = 'UTF-8';
                    $mail->Subject = 'Your verification code';
                    $mail->Body = "Your OTP code: $newCode";
                    $mail->send();
                    $sent = true;
                } catch (PHPMailer\PHPMailer\Exception $e){
                    $_SESSION['error'] = 'Failed to send email: '.$e->getMessage();
                }
            }
        }
        
        if (!$sent){
            $_SESSION['error'] = 'SMTP not configured. Please configure email settings to send OTP codes.';
        } else {
            $_SESSION['info'] = 'New OTP sent to your email.';
        }
        header('Location: verify_otp.php');
        exit;
    }
    
    // Verify OTP
    $stmt = $db->prepare('SELECT * FROM otps WHERE user_id = ? AND code = ? ORDER BY id DESC LIMIT 1');
    $stmt->execute([$pending['user_id'],$code]);
    $otp = $stmt->fetch(PDO::FETCH_ASSOC);
    
    if (!$otp || $otp['expires_at'] < time()){
        $_SESSION['error'] = 'Invalid or expired code';
        header('Location: verify_otp.php');
        exit;
    }
    
    $stmt = $db->prepare('UPDATE users SET verified = 1 WHERE id = ?');
    $stmt->execute([$pending['user_id']]);
    
    // Clear pending verification
    unset($_SESSION['pending_verification']);
    
    $_SESSION['info'] = 'Account verified. You can now login.';
    header('Location: login.php');
    exit;
}

// Log page access
log_access($db, 'page_view_verify_otp');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Verify Email</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>Verify Your Email</h2>
  <p>A verification code has been sent to your email address. Enter the code below to complete your registration.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <input type="text" name="code" placeholder="Enter the 6-digit verification code" required pattern="[0-9]{6}" maxlength="6">
    <button type="submit">Verify Email</button>
  </form>
  <form method="post" style="margin-top: 10px;">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    <button type="submit" name="resend" value="1">Resend Verification Code</button>
  </form>
  <p><a href="register.php">Return to Registration</a></p>
</div>
</body>
</html>
