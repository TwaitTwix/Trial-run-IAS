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

// Handle movie deletion
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'delete') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: manage_movies.php');
        exit;
    }
    
    $movieId = intval($_POST['movie_id']);
    $stmt = $db->prepare('DELETE FROM movies WHERE id = ?');
    $stmt->execute([$movieId]);
    
    $_SESSION['info'] = 'Movie deleted successfully.';
    header('Location: manage_movies.php');
    exit;
}

// Fetch all movies
$movies = $db->query('SELECT * FROM movies ORDER BY created_at DESC')->fetchAll(PDO::FETCH_ASSOC);

// Log page access
log_access($db, 'page_view_manage_movies');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Manage Movies</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="box" style="max-width: 1000px;">
  <h2>Manage Movies</h2>
  <p>Add, edit, or remove movies from the streaming platform.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  
  <div style="margin-bottom: 20px;">
    <a href="add_movie.php" style="display: inline-block; padding: 12px 24px; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; border-radius: 25px; text-decoration: none; font-weight: 600;">Add New Movie</a>
  </div>
  
  <?php if (empty($movies)): ?>
    <p style="text-align: center; color: rgba(255,255,255,0.7);">No movies found. Add your first movie to get started.</p>
  <?php else: ?>
    <?php foreach($movies as $movie): ?>
      <div class="user" style="display: flex; align-items: center; gap: 20px;">
        <?php if (!empty($movie['poster_url'])): ?>
          <img src="<?php echo htmlspecialchars($movie['poster_url']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" style="width: 80px; height: 120px; object-fit: cover; border-radius: 10px;">
        <?php else: ?>
          <div style="width: 80px; height: 120px; background: rgba(255,255,255,0.1); border-radius: 10px; display: flex; align-items: center; justify-content: center; color: rgba(255,255,255,0.5);">No Poster</div>
        <?php endif; ?>
        
        <div style="flex: 1;">
          <strong style="font-size: 1.2rem;"><?php echo htmlspecialchars($movie['title']); ?></strong>
          <div style="margin-top: 8px; opacity: 0.8;">
            <span>Genre: <?php echo htmlspecialchars($movie['genre']); ?></span> | 
            <span>Category: <?php echo htmlspecialchars($movie['category']); ?></span> | 
            <span>Year: <?php echo htmlspecialchars($movie['release_year']); ?></span> | 
            <span>Rating: <?php echo htmlspecialchars($movie['rating']); ?>/10</span>
          </div>
          <?php if (!empty($movie['description'])): ?>
            <div style="margin-top: 8px; opacity: 0.7; font-size: 0.9rem;">
              <?php echo htmlspecialchars(substr($movie['description'], 0, 150)); ?>...
            </div>
          <?php endif; ?>
        </div>
        
        <form method="post" style="margin: 0;">
          <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
          <input type="hidden" name="movie_id" value="<?php echo $movie['id']; ?>">
          <input type="hidden" name="action" value="delete">
          <button type="submit" style="width: auto; padding: 8px 20px; margin: 0; background: linear-gradient(135deg, #ff6b6b 0%, #ee5a5a 100%); box-shadow: 0 5px 20px rgba(255, 107, 107, 0.4);">Delete</button>
        </form>
      </div>
    <?php endforeach; ?>
  <?php endif; ?>
  
  <p style="text-align: center; margin-top: 30px;">
    <a href="add_movie.php">Add New Movie</a> | 
    <a href="admin.php">Admin Panel</a> | 
    <a href="index.php">Return to Dashboard</a>
  </p>
</div>
</body>
</html>
