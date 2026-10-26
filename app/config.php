<?php
// Config for php_app
$config = [];

// MySQL (XAMPP) settings. To enable, set 'enabled' => true and adjust params.
$config['mysql'] = [
    'enabled' => false,
    'host' => '127.0.0.1',
    'database' => 'php_app_db',
    'user' => 'root',
    'pass' => ''
];

// SMTP settings for PHPMailer. If left empty, register shows OTP preview instead.
$config['smtp'] = [
    'host' => 'smtp.gmail.com',
    'port' => 587,
    'user' => 'leonardolllmacalinaoisap2@gmail.com',
    'pass' => 'vaoc fnqg pzjp vvtn',
    'from_email' => 'no-reply@example.com',
    'from_name' => 'Secure Stream',
    // Enable SMTP debug capture (false by default). Set true to capture SMTP conversation in session for debugging.
    'debug' => false
];

?>
