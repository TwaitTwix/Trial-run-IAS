<?php
/**
 * mysql_setup.php
 * Attempts to create the configured MySQL database and required tables.
 * Usage: visit in browser (http://localhost/php_app/mysql_setup.php) or run via CLI: php mysql_setup.php
 */
require_once __DIR__ . '/../app/config.php';

if (empty($config['mysql']) || empty($config['mysql']['host'])) {
    echo "MySQL not configured in config.php.\n";
    exit(1);
}

$host = $config['mysql']['host'];
$dbName = $config['mysql']['database'];
$user = $config['mysql']['user'];
$pass = $config['mysql']['pass'];

function try_connect($host, $user, $pass, $dbname = null){
    try {
        $dsn = $dbname ? "mysql:host=$host;dbname=$dbname;charset=utf8mb4" : "mysql:host=$host;charset=utf8mb4";
        $pdo = new PDO($dsn, $user, $pass);
        $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        return $pdo;
    } catch (Exception $e){
        return false;
    }
}

echo "Checking MySQL server at $host...\n";

$pdo = try_connect($host, $user, $pass, $dbName);
if ($pdo) {
    echo "Connected to database $dbName as $user.\n";
} else {
    echo "Could not connect as configured user ($user). Trying to connect without database...\n";
    $adminPdo = try_connect($host, $user, $pass, null);
    if (!$adminPdo) {
        // try connecting as root with no password (common XAMPP default)
        echo "Configured user failed. Trying root with empty password...\n";
        $adminPdo = try_connect($host, 'root', '', null);
        if (!$adminPdo) {
            echo "Failed to connect to MySQL as configured user or root. Please verify MySQL credentials and that MySQL is running.\n";
            exit(1);
        }
    }

    // Create database if missing
    try {
        $adminPdo->exec("CREATE DATABASE IF NOT EXISTS `$dbName` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
        echo "Database $dbName ensured.\n";
        // Grant privileges to configured user if not root
        if ($user !== 'root'){
            // create user if not exists and grant
            $adminPdo->exec("CREATE USER IF NOT EXISTS '$user'@'localhost' IDENTIFIED BY '$pass'");
            $adminPdo->exec("GRANT ALL PRIVILEGES ON `$dbName`.* TO '$user'@'localhost'");
            $adminPdo->exec("FLUSH PRIVILEGES");
            echo "User $user granted privileges on $dbName.\n";
        }
        $pdo = try_connect($host, $user, $pass, $dbName);
        if (!$pdo) { echo "Warning: unable to connect with configured user after creating DB.\n"; }
    } catch (Exception $e){ echo "Error creating database: ".$e->getMessage()."\n"; exit(1); }
}

// Create tables if missing
if ($pdo){
    try {
        $pdo->exec("CREATE TABLE IF NOT EXISTS users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(190) UNIQUE,
            password TEXT,
            email VARCHAR(255) UNIQUE,
            recovery_email VARCHAR(255),
            role VARCHAR(32) DEFAULT 'user',
            locked TINYINT DEFAULT 0,
            banned TINYINT DEFAULT 0,
            verified TINYINT DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        $pdo->exec("CREATE TABLE IF NOT EXISTS otps (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            code VARCHAR(32),
            expires_at INT,
            INDEX(user_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        $pdo->exec("CREATE TABLE IF NOT EXISTS credentials (
            id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT,
            cred_id TEXT,
            public_key TEXT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;");

        echo "Tables ensured (users, otps, credentials).\n";
    } catch (Exception $e){ echo "Error creating tables: ".$e->getMessage()."\n"; exit(1); }
}

echo "MySQL setup complete.\n";

?>
