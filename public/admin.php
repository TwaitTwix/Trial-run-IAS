<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();
if (empty($_SESSION['user']) || $_SESSION['user']['role']!=='admin'){ header('Location: login.php'); exit; }
if ($_SERVER['REQUEST_METHOD']==='POST'){
    // CSRF protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: admin.php'); exit;
    }
    $userId = intval($_POST['userId']); $action = $_POST['action'];
    if ($action === 'ban') $db->exec("UPDATE users SET banned = 1 WHERE id = $userId");
    if ($action === 'unban') $db->exec("UPDATE users SET banned = 0 WHERE id = $userId");
    if ($action === 'archive') $db->exec("UPDATE users SET archived = 1 WHERE id = $userId");
    if ($action === 'unarchive') $db->exec("UPDATE users SET archived = 0 WHERE id = $userId");
}
$users = $db->query('SELECT id,username,email,role,banned,archived,verified FROM users')->fetchAll(PDO::FETCH_ASSOC);

// Log page access
log_access($db, 'page_view_admin');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Admin Panel</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="box" style="max-width: 800px;">
  <h2>Admin Panel</h2>
  <p>Manage user accounts and their access permissions.</p>
  
  <div style="margin-bottom: 20px; display: flex; gap: 10px; flex-wrap: wrap;">
    <a href="manage_movies.php" style="display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 25px; text-decoration: none; font-weight: 600;">Manage Movies</a>
    <a href="archived_accounts.php" style="display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); color: white; border-radius: 25px; text-decoration: none; font-weight: 600;">Archived Accounts</a>
    <a href="access_logs.php" style="display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%); color: white; border-radius: 25px; text-decoration: none; font-weight: 600;">Access Logs</a>
  </div>
  <?php foreach($users as $u): ?>
    <div class="user">
      <strong><?php echo htmlspecialchars($u['username']); ?></strong> (<?php echo htmlspecialchars($u['email']); ?>)
      <div style="margin-top: 10px; opacity: 0.8;">Account banned: <?php echo $u['banned']? 'Yes':'No'; ?> | Account archived: <?php echo $u['archived']? 'Yes':'No'; ?> | Email verified: <?php echo $u['verified']? 'Yes':'No'; ?></div>
      <form method="post" style="display:inline; margin-top: 10px;">
        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
        <input type="hidden" name="userId" value="<?php echo $u['id']; ?>">
        <button name="action" value="<?php echo $u['banned']? 'unban':'ban'; ?>"><?php echo $u['banned']? 'Unban':'Ban'; ?></button>
        <button name="action" value="<?php echo $u['archived']? 'unarchive':'archive'; ?>"><?php echo $u['archived']? 'Unarchive':'Archive'; ?></button>
      </form>
    </div>
  <?php endforeach; ?>
  <p style="text-align: center; margin-top: 30px;"><a href="index.php">Return to Dashboard</a></p>
</div>
</body>
</html>
