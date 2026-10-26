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

// Fetch access logs with pagination
$page = isset($_GET['page']) ? max(1, intval($_GET['page'])) : 1;
$limit = 50;
$offset = ($page - 1) * $limit;

$logs = $db->query("SELECT * FROM access_logs ORDER BY timestamp DESC LIMIT $limit OFFSET $offset")->fetchAll(PDO::FETCH_ASSOC);

// Get total count for pagination
$total_logs = $db->query('SELECT COUNT(*) FROM access_logs')->fetchColumn();
$total_pages = ceil($total_logs / $limit);

// Log page access
log_access($db, 'page_view_access_logs');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Access Logs</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="box" style="max-width: 1200px;">
  <h2>Access Logs</h2>
  <p>View all user access and activity logs.</p>
  
  <div style="margin-bottom: 20px; color: rgba(255,255,255,0.7);">
    Total entries: <?php echo $total_logs; ?> | Page <?php echo $page; ?> of <?php echo $total_pages; ?>
  </div>
  
  <?php if (empty($logs)): ?>
    <p style="text-align: center; color: rgba(255,255,255,0.7);">No access logs found.</p>
  <?php else: ?>
    <div style="overflow-x: auto;">
      <table style="width: 100%; border-collapse: collapse; color: white;">
        <thead>
          <tr style="border-bottom: 1px solid rgba(255,255,255,0.2);">
            <th style="padding: 12px; text-align: left;">Timestamp</th>
            <th style="padding: 12px; text-align: left;">Username</th>
            <th style="padding: 12px; text-align: left;">Action</th>
            <th style="padding: 12px; text-align: left;">IP Address</th>
            <th style="padding: 12px; text-align: left;">User Agent</th>
          </tr>
        </thead>
        <tbody>
          <?php foreach($logs as $log): ?>
            <tr style="border-bottom: 1px solid rgba(255,255,255,0.1);">
              <td style="padding: 12px;">
                <?php 
                $timestamp = $log['timestamp'];
                if (is_numeric($timestamp)) {
                    echo date('Y-m-d H:i:s', $timestamp);
                } else {
                    echo htmlspecialchars($timestamp);
                }
                ?>
              </td>
              <td style="padding: 12px;"><?php echo htmlspecialchars($log['username']); ?></td>
              <td style="padding: 12px;"><?php echo htmlspecialchars($log['action']); ?></td>
              <td style="padding: 12px;"><?php echo htmlspecialchars($log['ip_address']); ?></td>
              <td style="padding: 12px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;" title="<?php echo htmlspecialchars($log['user_agent']); ?>">
                <?php echo htmlspecialchars(substr($log['user_agent'], 0, 50)); ?>...
              </td>
            </tr>
          <?php endforeach; ?>
        </tbody>
      </table>
    </div>
    
    <?php if ($total_pages > 1): ?>
      <div style="margin-top: 20px; display: flex; justify-content: center; gap: 10px;">
        <?php if ($page > 1): ?>
          <a href="?page=<?php echo $page - 1; ?>" style="padding: 8px 16px; background: rgba(255,255,255,0.1); color: white; text-decoration: none; border-radius: 20px;">Previous</a>
        <?php endif; ?>
        
        <?php for ($i = 1; $i <= min($total_pages, 10); $i++): ?>
          <?php if ($i == $page): ?>
            <span style="padding: 8px 16px; background: rgba(102, 126, 234, 0.5); color: white; border-radius: 20px;"><?php echo $i; ?></span>
          <?php else: ?>
            <a href="?page=<?php echo $i; ?>" style="padding: 8px 16px; background: rgba(255,255,255,0.1); color: white; text-decoration: none; border-radius: 20px;"><?php echo $i; ?></a>
          <?php endif; ?>
        <?php endfor; ?>
        
        <?php if ($page < $total_pages): ?>
          <a href="?page=<?php echo $page + 1; ?>" style="padding: 8px 16px; background: rgba(255,255,255,0.1); color: white; text-decoration: none; border-radius: 20px;">Next</a>
        <?php endif; ?>
      </div>
    <?php endif; ?>
  <?php endif; ?>
  
  <p style="text-align: center; margin-top: 30px;">
    <a href="admin.php">Admin Panel</a> | 
    <a href="index.php">Return to Dashboard</a>
  </p>
</div>
</body>
</html>
