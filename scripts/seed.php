<?php
require '../app/db.php';

function seed($db){
    $adminPass = password_hash('AdminPass123!', PASSWORD_DEFAULT);
    $userPass = password_hash('UserPass123!', PASSWORD_DEFAULT);
    // Use INSERT IGNORE / ON DUPLICATE KEY depending on DB driver
    $driver = $db->getAttribute(PDO::ATTR_DRIVER_NAME);
    if ($driver === 'sqlite'){
        $stmt = $db->prepare('INSERT OR IGNORE INTO users (username,password,email,role,verified) VALUES (?,?,?,?,?)');
        $stmt->execute(['admin',$adminPass,'admin@example.com','admin',1]);
        $stmt->execute(['user',$userPass,'user@example.com','user',1]);
    } else {
        $stmt = $db->prepare('INSERT INTO users (username,password,email,role,verified) VALUES (?,?,?,?,?) ON DUPLICATE KEY UPDATE username = username');
        $stmt->execute(['admin',$adminPass,'admin@example.com','admin',1]);
        $stmt->execute(['user',$userPass,'user@example.com','user',1]);
    }
    echo "Seeded users.\n";
}

seed($db);

?>
