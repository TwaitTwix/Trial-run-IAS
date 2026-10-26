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

if ($_SERVER['REQUEST_METHOD'] === 'POST'){
    // CSRF protection
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $_SESSION['error'] = 'Invalid request. Please try again.';
        header('Location: add_movie.php');
        exit;
    }
    
    $title = trim($_POST['title']);
    $description = trim($_POST['description']);
    $genre = trim($_POST['genre']);
    $release_year = intval($_POST['release_year']);
    $poster_url = trim($_POST['poster_url']);
    $trailer_url = trim($_POST['trailer_url']);
    $video_url = trim($_POST['video_url']);
    $category = trim($_POST['category']);
    $duration = intval($_POST['duration']);
    $rating = floatval($_POST['rating']);
    
    // Validation
    if (empty($title) || empty($description) || empty($genre) || empty($category)) {
        $_SESSION['error'] = 'Please fill in all required fields.';
        header('Location: add_movie.php');
        exit;
    }
    
    if ($release_year < 1900 || $release_year > date('Y') + 5) {
        $_SESSION['error'] = 'Invalid release year.';
        header('Location: add_movie.php');
        exit;
    }
    
    if ($rating < 0 || $rating > 10) {
        $_SESSION['error'] = 'Rating must be between 0 and 10.';
        header('Location: add_movie.php');
        exit;
    }
    
    // Insert movie into database
    $stmt = $db->prepare('INSERT INTO movies (title, description, genre, release_year, poster_url, trailer_url, video_url, category, duration, rating) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)');
    $stmt->execute([$title, $description, $genre, $release_year, $poster_url, $trailer_url, $video_url, $category, $duration, $rating]);
    
    $_SESSION['info'] = 'Movie added successfully.';
    header('Location: manage_movies.php');
    exit;
}

// Log page access
log_access($db, 'page_view_add_movie');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Add Movie</title>
  <link rel="stylesheet" href="style.css">
  <script src="form_cache.js" defer></script>
</head>
<body>
<div class="box" style="max-width: 800px;">
  <h2>Add Movie</h2>
  <p>Add a new movie to the streaming platform.</p>
  <?php if(!empty($_SESSION['error'])){ echo '<div class="err">'.htmlspecialchars($_SESSION['error']).'</div>'; unset($_SESSION['error']); } ?>
  <?php if(!empty($_SESSION['info'])){ echo '<div class="info">'.htmlspecialchars($_SESSION['info']).'</div>'; unset($_SESSION['info']); } ?>
  <form method="post">
    <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
    
    <input name="title" placeholder="Movie Title" required>
    <input name="description" placeholder="Movie Description" required>
    <input name="genre" placeholder="Genre (e.g., Action, Drama, Comedy)" required>
    <input name="category" placeholder="Category (e.g., Movies, TV Shows, K-Dramas)" required>
    <input name="release_year" type="number" placeholder="Release Year" min="1900" max="<?php echo date('Y') + 5; ?>" required>
    <input name="duration" type="number" placeholder="Duration (minutes)" min="1">
    <input name="rating" type="number" placeholder="Rating (0-10)" min="0" max="10" step="0.1">
    <input name="poster_url" placeholder="Poster Image URL">
    <input name="trailer_url" placeholder="Trailer Video URL">
    <input name="video_url" placeholder="Full Movie Video URL">
    
    <button type="submit">Add Movie</button>
  </form>
  <p style="text-align: center; margin-top: 20px;">
    <a href="manage_movies.php">Manage Movies</a> | 
    <a href="admin.php">Admin Panel</a> | 
    <a href="index.php">Return to Dashboard</a>
  </p>
</div>
</body>
</html>
