<?php
// Database connection: supports SQLite (default) or MySQL if configured in config.php
require_once __DIR__ . '/config.php';

try {
    if (!empty($config['mysql']['enabled'])) {
        $mysql = $config['mysql'];
        $dsn = "mysql:host={$mysql['host']};dbname={$mysql['database']};charset=utf8mb4";
        $db = new PDO($dsn, $mysql['user'], $mysql['pass']);
    } else {
        $db = new PDO('sqlite:' . __DIR__ . '/../storage/database.sqlite');
    }
    $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch (Exception $e) {
    die('DB connection error: ' . $e->getMessage());
}

function init_db($db){
    $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite'){
        $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE, password TEXT, email TEXT UNIQUE, recovery_email TEXT, role TEXT DEFAULT 'user', locked INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, archived INTEGER DEFAULT 0, verified INTEGER DEFAULT 0);");
        $db->exec("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, code TEXT, expires_at INTEGER);");
        $db->exec("CREATE TABLE IF NOT EXISTS movies (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, genre TEXT, release_year INTEGER, poster_url TEXT, trailer_url TEXT, video_url TEXT, category TEXT, duration INTEGER, rating REAL, created_at INTEGER DEFAULT (strftime('%s', 'now')));");
        $db->exec("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, username TEXT, action TEXT, ip_address TEXT, user_agent TEXT, timestamp INTEGER DEFAULT (strftime('%s', 'now')));");
        $db->exec("CREATE TABLE IF NOT EXISTS account_notifications (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT, message TEXT, created_at INTEGER DEFAULT (strftime('%s', 'now')));");
    } else {
        // assume MySQL
        $db->exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTO_INCREMENT, username TEXT UNIQUE, password TEXT, email TEXT UNIQUE, recovery_email TEXT, role TEXT DEFAULT 'user', locked INTEGER DEFAULT 0, banned INTEGER DEFAULT 0, archived INTEGER DEFAULT 0, verified INTEGER DEFAULT 0);");
        $db->exec("CREATE TABLE IF NOT EXISTS otps (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, code TEXT, expires_at INTEGER);");
        $db->exec("CREATE TABLE IF NOT EXISTS movies (id INTEGER PRIMARY KEY AUTO_INCREMENT, title VARCHAR(255), description TEXT, genre VARCHAR(100), release_year INT, poster_url VARCHAR(500), trailer_url VARCHAR(500), video_url VARCHAR(500), category VARCHAR(50), duration INT, rating DECIMAL(3,1), created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);");
        $db->exec("CREATE TABLE IF NOT EXISTS access_logs (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INT, username VARCHAR(255), action VARCHAR(100), ip_address VARCHAR(45), user_agent TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP);");
        $db->exec("CREATE TABLE IF NOT EXISTS account_notifications (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INT, title VARCHAR(255), message TEXT, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);");
    }
}

init_db($db);
?>
