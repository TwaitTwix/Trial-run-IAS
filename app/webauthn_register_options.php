<?php
// Generates a challenge for WebAuthn registration and stores it in session.
session_start();
require_once __DIR__.'/config.php';
if (!file_exists(__DIR__.'/../vendor/autoload.php')){
    http_response_code(500); echo json_encode(['error'=>'Composer dependencies not installed. Run composer install.']); exit;
}
// For a full implementation, install web-auth/webauthn-lib and implement challenge generation and attestation verification.
// This endpoint provides a demo challenge for client-side WebAuthn calls.

$challenge = bin2hex(random_bytes(32));
$_SESSION['webauthn_challenge'] = $challenge;
header('Content-Type: application/json');
echo json_encode(['challenge'=>$challenge, 'rp'=>['name'=>'Movie Stream Demo'], 'user'=>['id'=>session_id(),'name'=>($_SESSION['user']['username'] ?? 'guest')]]);
