<?php
// Generates a challenge for WebAuthn authentication and stores it in session.
session_start();
if (empty($_SESSION['user'])){ http_response_code(403); echo json_encode(['error'=>'Not logged in']); exit; }
$challenge = bin2hex(random_bytes(32));
$_SESSION['webauthn_challenge'] = $challenge;
header('Content-Type: application/json');
echo json_encode(['challenge'=>$challenge]);
