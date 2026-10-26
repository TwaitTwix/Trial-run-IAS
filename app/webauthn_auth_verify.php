<?php
// Demo endpoint: receives assertion from client and does basic matching against stored credential id.
session_start();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
$data = json_decode(file_get_contents('php://input'), true);
require 'db.php';
$userId = $_SESSION['user']['id'] ?? null;
if (!$userId){ http_response_code(403); echo json_encode(['error'=>'Not logged in']); exit; }
if (empty($data['id'])){ http_response_code(400); echo json_encode(['error'=>'Invalid data']); exit; }
$stmt = $db->prepare('SELECT * FROM credentials WHERE user_id = ? AND cred_id = ? LIMIT 1');
$stmt->execute([$userId, $data['id']]);
$cred = $stmt->fetch(PDO::FETCH_ASSOC);
if ($cred){
    // NOTE: This does NOT verify signature. For production, verify assertion using webauthn-lib.
    echo json_encode(['ok'=>true,'warning'=>'Assertion not cryptographically verified in demo.']);
} else {
    http_response_code(403); echo json_encode(['error'=>'Unknown credential']);
}
