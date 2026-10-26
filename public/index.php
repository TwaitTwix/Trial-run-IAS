<?php
require '../app/db.php';
require '../app/security.php';
configure_session_ini();
session_start();
send_security_headers();
configure_secure_session();
function is_logged(){ return !empty($_SESSION['user']); }

// Always start on the login page for unauthenticated visitors
if (!is_logged()){
  header('Location: login.php');
  exit;
}

// Fetch movies by category
$categories = ['Movies', 'TV Shows', 'K-Dramas'];
$movies_by_category = [];
foreach ($categories as $category) {
    $stmt = $db->prepare('SELECT * FROM movies WHERE category = ? ORDER BY created_at DESC LIMIT 10');
    $stmt->execute([$category]);
    $movies_by_category[$category] = $stmt->fetchAll(PDO::FETCH_ASSOC);
}

// Fetch recommended movies (all movies, sorted by rating)
$stmt = $db->prepare('SELECT * FROM movies ORDER BY rating DESC LIMIT 10');
$stmt->execute();
$recommended_movies = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Log page access
log_access($db, 'page_view_index');
?>
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Dashboard</title>
  <link rel="stylesheet" href="style.css">
</head>
<body>
<div class="top">
  <h1>Movie Stream</h1>
  <div class="nav">
    <?php if(is_logged()){ echo 'Hello, '.htmlspecialchars($_SESSION['user']['username']).' | <a href="account.php">My Account</a> | <a href="logout.php">Log Out</a>'; if($_SESSION['user']['role']==='admin') echo ' | <a href="admin.php">Admin Panel</a>'; } else { echo '<a href="login.php">Log In</a> | <a href="register.php">Create Account</a>'; } ?>
  </div>
</div>
<div class="content">
  <form method="get" action="">
    <input name="q" placeholder="Search for movies...">
    <button>Search</button>
  </form>
  
  <h3 style="color: white; margin-bottom: 20px;">Recommended Movies</h3>
  <div class="movie-carousel">
    <?php if (empty($recommended_movies)): ?>
      <p style="color: rgba(255,255,255,0.7);">No movies available yet.</p>
    <?php else: ?>
      <?php foreach($recommended_movies as $movie): ?>
        <div class="movie-card">
          <?php if (!empty($movie['poster_url'])): ?>
            <img src="<?php echo htmlspecialchars($movie['poster_url']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" class="movie-poster">
          <?php else: ?>
            <div class="movie-poster-placeholder">No Poster</div>
          <?php endif; ?>
          <div class="movie-info">
            <h4><?php echo htmlspecialchars($movie['title']); ?></h4>
            <p class="movie-meta"><?php echo htmlspecialchars($movie['genre']); ?> | <?php echo htmlspecialchars($movie['release_year']); ?> | ⭐ <?php echo htmlspecialchars($movie['rating']); ?></p>
          </div>
        </div>
      <?php endforeach; ?>
    <?php endif; ?>
  </div>
  
  <?php foreach($categories as $category): ?>
    <?php if (!empty($movies_by_category[$category])): ?>
      <h3 style="color: white; margin: 40px 0 20px;">Latest <?php echo htmlspecialchars($category); ?></h3>
      <div class="movie-carousel">
        <?php foreach($movies_by_category[$category] as $movie): ?>
          <div class="movie-card">
            <?php if (!empty($movie['poster_url'])): ?>
              <img src="<?php echo htmlspecialchars($movie['poster_url']); ?>" alt="<?php echo htmlspecialchars($movie['title']); ?>" class="movie-poster">
            <?php else: ?>
              <div class="movie-poster-placeholder">No Poster</div>
            <?php endif; ?>
            <div class="movie-info">
              <h4><?php echo htmlspecialchars($movie['title']); ?></h4>
              <p class="movie-meta"><?php echo htmlspecialchars($movie['genre']); ?> | <?php echo htmlspecialchars($movie['release_year']); ?> | ⭐ <?php echo htmlspecialchars($movie['rating']); ?></p>
            </div>
          </div>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
  <?php endforeach; ?>
</div>
</body>
</html>
