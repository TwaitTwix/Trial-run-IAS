<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();

// Check if user is logged in and is admin
if (!isset($_SESSION['user']) || $_SESSION['user']['role'] !== 'admin') {
    $_SESSION['error'] = 'Access denied. Administrator privileges required.';
    header('Location: index.php');
    exit;
}

// Handle user deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: archived_accounts.php');
        exit;
    }
    
    $userId = intval($_POST['user_id']);
    $stmt = $db->prepare('DELETE FROM users WHERE id = ? AND archived = 1');
    $stmt->execute([$userId]);
    
    $_SESSION['info'] = 'Archived account deleted successfully.';
    header('Location: archived_accounts.php');
    exit;
}

// Handle unarchive
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'unarchive') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: archived_accounts.php');
        exit;
    }
    
    $userId = intval($_POST['user_id']);
    $stmt = $db->prepare('UPDATE users SET archived = 0 WHERE id = ?');
    $stmt->execute([$userId]);
    
    $_SESSION['info'] = 'Account unarchived successfully.';
    header('Location: archived_accounts.php');
    exit;
}

// Fetch archived users only
$archived_users = $db->query('SELECT id,username,email,role,verified FROM users WHERE archived = 1')->fetchAll(PDO::FETCH_ASSOC);

// Log page access
log_access($db, 'page_view_archived_accounts');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Archived Accounts</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="box" style="max-width: 1000px;">
  <h2>Archived Accounts</h2>
  <p>Manage archived user accounts. You can unarchive or permanently delete them.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  
  <?php if (empty($archived_users)): ?>
    <p style="text-align: center; color: rgba(255,255,255,0.7);">No archived accounts found.</p>
  <?php else: ?>
    <?php foreach($archived_users as $user): ?>
      <div class="user" style="display: flex; align-items: center; justify-content: space-between;">
        <div>
          <strong><?php echo htmlspecialchars($user['username']); ?></strong> (<?php echo htmlspecialchars($user['email']); ?>)
          <div style="margin-top: 8px; opacity: 0.8;">
            <span>Role: <?php echo htmlspecialchars($user['role']); ?></span> | 
            <span>Verified: <?php echo $user['verified']? 'Yes':'No'; ?></span>
          </div>
        </div>
        <div style="display: flex; gap: 10px;">
          <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
            <input type="hidden" name="action" value="unarchive">
            <button type="submit" style="width: auto; padding: 8px 20px; margin: 0;">Unarchive</button>
          </form>
          <form method="post">
            <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
            <input type="hidden" name="user_id" value="<?php echo $user['id']; ?>">
            <input type="hidden" name="action" value="delete">
            <button type="submit" style="width: auto; padding: 8px 20px; margin: 0; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%); box-shadow: 0 5px 20px rgba(255, 107, 107, 0.4);">Delete</button>
          </form>
        </div>
      </div>
    <?php endforeach; ?>
  <?php endif; ?>
  
  <p style="text-align: center; margin-top: 30px;">
    <a href="admin.php">Admin Panel</a> | 
    <a href="index.php">Return to Dashboard</a>
  </p>
</div>
</body>
</html>
