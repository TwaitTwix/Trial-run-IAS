<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();

if (empty($_SESSION['user'])) {
    header('Location: login.php');
    exit;
}

$userId = $_SESSION['user']['id'];
$stmt = $db->prepare('SELECT username,email,recovery_email FROM users WHERE id = ?');
$stmt->execute([$userId]);
$u = $stmt->fetch(PDO::FETCH_ASSOC);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: account.php');
        exit;
    }

    $action = $_POST['action'] ?? '';

    if ($action === 'send_password_code') {
        if (empty($u['email'])) {
            $_SESSION['error'] = 'No email is configured for this account.';
            header('Location: account.php');
            exit;
        }

        $code = (string) random_int(100000, 999999);
        $expiresAt = time() + 900;
        $stmt = $db->prepare('INSERT INTO otps (user_id, code, expires_at) VALUES (?, ?, ?)');
        $stmt->execute([$userId, $code, $expiresAt]);

        $mailSent = false;
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
                    $mail->addAddress($u['email']);
                    $mail->isHTML(false);
                    $mail->CharSet = 'UTF-8';
                    $mail->Subject = 'Your Account Password Update Code';
                    $mail->Body = "Your account password update code is: $code\n\nThis code expires in 15 minutes.\n\nIf you did not request this change, please secure your account immediately.";
                    $mail->send();
                    $mailSent = true;
                } catch (PHPMailer\PHPMailer\Exception $e) {
                    $_SESSION['error'] = 'Failed to send the verification code: ' . $e->getMessage();
                    header('Location: account.php');
                    exit;
                }
            }
        }

        if (!$mailSent) {
            $_SESSION['error'] = 'SMTP is not configured. Please configure email settings before requesting a password reset code.';
            header('Location: account.php');
            exit;
        }

        $_SESSION['account_password_reset'] = [
            'user_id' => $userId,
            'email' => $u['email'],
            'expires_at' => $expiresAt,
        ];
        $_SESSION['info'] = 'A verification code has been sent to your email address.';
        header('Location: account.php');
        exit;
    }

    if ($action === 'reset_password') {
        if (empty($_SESSION['account_password_reset']) || $_SESSION['account_password_reset']['user_id'] != $userId) {
            $_SESSION['error'] = 'No active password reset request found. Please request a new code.';
            header('Location: account.php');
            exit;
        }

        $code = trim((string)($_POST['verification_code'] ?? ''));
        $newPassword = (string)($_POST['new_password'] ?? '');
        $confirmPassword = (string)($_POST['confirm_password'] ?? '');

        $stmt = $db->prepare('SELECT * FROM otps WHERE user_id = ? AND code = ? ORDER BY id DESC LIMIT 1');
        $stmt->execute([$userId, $code]);
        $otp = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$otp || (int)$otp['expires_at'] < time()) {
            $_SESSION['error'] = 'Invalid or expired verification code.';
            header('Location: account.php');
            exit;
        }

        if ($newPassword !== $confirmPassword) {
            $_SESSION['error'] = 'Passwords do not match.';
            header('Location: account.php');
            exit;
        }

        $passwordErrors = validate_password_strength($newPassword);
        if (!empty($passwordErrors)) {
            $_SESSION['error'] = implode(', ', $passwordErrors);
            header('Location: account.php');
            exit;
        }

        $hash = password_hash($newPassword, PASSWORD_DEFAULT);
        $stmt = $db->prepare('UPDATE users SET password = ? WHERE id = ?');
        $stmt->execute([$hash, $userId]);

        $db->prepare('DELETE FROM otps WHERE user_id = ?')->execute([$userId]);
        unset($_SESSION['account_password_reset']);

        create_account_notification($db, $userId, 'Password updated', 'Your account password was changed successfully and verified using your email code.');

        $_SESSION['info'] = 'Your password was updated successfully.';
        header('Location: account.php');
        exit;
    }

    if ($action === 'update_recovery_email') {
        $recoveryEmail = trim((string)($_POST['recovery_email'] ?? ''));

        if ($recoveryEmail !== '' && !filter_var($recoveryEmail, FILTER_VALIDATE_EMAIL)) {
            $_SESSION['error'] = 'Recovery email must be a valid email address or left blank.';
            header('Location: account.php');
            exit;
        }

        $stmt = $db->prepare('UPDATE users SET recovery_email = ? WHERE id = ?');
        $stmt->execute([$recoveryEmail !== '' ? $recoveryEmail : null, $userId]);

        create_account_notification($db, $userId, 'Recovery email updated', 'Your account recovery email was updated.');

        $_SESSION['info'] = 'Your recovery email was updated successfully.';
        header('Location: account.php');
        exit;
    }
}

$notifications = $db->prepare('SELECT title, message, created_at FROM account_notifications WHERE user_id = ? ORDER BY created_at DESC LIMIT 10');
$notifications->execute([$userId]);
$notifications = $notifications->fetchAll(PDO::FETCH_ASSOC);

log_access($db, 'page_view_account');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Account</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box">
  <h2>My Account</h2>
  <p>View and manage your account information.</p>
  <?php if (!empty($_SESSION['error'])) { echo '<div class="err">' . htmlspecialchars($_SESSION['error']) . '</div>'; unset($_SESSION['error']); } ?>
  <?php if (!empty($_SESSION['info'])) { echo '<div class="info">' . htmlspecialchars($_SESSION['info']) . '</div>'; unset($_SESSION['info']); } ?>
  <div style="background: rgba(255, 255, 255, 0.1); border-radius: 20px; padding: 20px; margin-bottom: 15px;">
    <p style="text-align: left; margin-bottom: 10px;"><strong>Username:</strong> <?php echo htmlspecialchars($u['username']); ?></p>
    <p style="text-align: left; margin-bottom: 10px;"><strong>Email Address:</strong> <?php echo htmlspecialchars($u['email']); ?></p>
    <p style="text-align: left; margin-bottom: 10px;"><strong>Recovery Email:</strong> <?php echo htmlspecialchars($u['recovery_email'] ?: 'Not configured'); ?></p>
  </div>

  <div style="background: rgba(255, 255, 255, 0.08); border-radius: 20px; padding: 20px; margin-bottom: 20px;">
    <h3 style="margin-bottom: 15px;">Update Password</h3>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
      <input type="hidden" name="action" value="send_password_code">
      <button type="submit">Send Verification Code to My Email</button>
    </form>

    <?php if (!empty($_SESSION['account_password_reset'])): ?>
      <form method="post" style="margin-top: 15px;">
        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
        <input type="hidden" name="action" value="reset_password">
        <input type="text" name="verification_code" placeholder="Enter 6-digit verification code" required pattern="[0-9]{6}" maxlength="6">
        <input type="password" name="new_password" placeholder="New password" required>
        <input type="password" name="confirm_password" placeholder="Confirm new password" required>
        <button type="submit">Confirm Password Change</button>
      </form>
    <?php endif; ?>
  </div>

  <div style="background: rgba(255, 255, 255, 0.08); border-radius: 20px; padding: 20px; margin-bottom: 20px;">
    <h3 style="margin-bottom: 15px;">Update Recovery Email</h3>
    <form method="post">
      <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
      <input type="hidden" name="action" value="update_recovery_email">
      <input type="email" name="recovery_email" value="<?php echo htmlspecialchars($u['recovery_email'] ?: ''); ?>" placeholder="Enter recovery email">
      <button type="submit">Save Recovery Email</button>
    </form>
  </div>

  <div style="background: rgba(255, 255, 255, 0.08); border-radius: 20px; padding: 20px; margin-bottom: 15px;">
    <h3 style="margin-bottom: 15px;">Account Notifications</h3>
    <?php if (empty($notifications)): ?>
      <p style="color: rgba(255,255,255,0.7); margin: 0;">No account notifications yet.</p>
    <?php else: ?>
      <?php foreach ($notifications as $notification): ?>
        <div style="background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 15px; padding: 12px 14px; margin-bottom: 10px;">
          <strong><?php echo htmlspecialchars($notification['title']); ?></strong>
          <div style="margin-top: 5px; color: rgba(255,255,255,0.8); font-size: 0.9rem;">
            <?php echo htmlspecialchars($notification['message']); ?>
          </div>
          <div style="margin-top: 6px; color: rgba(255,255,255,0.6); font-size: 0.75rem;">
            <?php echo date('Y-m-d H:i:s', (int)$notification['created_at']); ?>
          </div>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>

  <p><a href="index.php">Return to Dashboard</a></p>
</div>
</body>
</html>
