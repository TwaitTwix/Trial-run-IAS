<?php
// Demo endpoint: receives client attestation and stores credential id. Full attestation verification requires a library.
session_start();
if ($_SERVER['REQUEST_METHOD'] !== 'POST') { http_response_code(405); exit; }
// Accept JSON body
$data = json_decode(file_get_contents('php://input'), true);
if (!$data || empty($data['id'])){ http_response_code(400); echo json_encode(['error'=>'Invalid data']); exit; }
// In production, validate attestation using webauthn-lib. Here we store credential id for demo.
require 'db.php';
$userId = $_SESSION['user']['id'] ?? null;
if (!$userId){ http_response_code(403); echo json_encode(['error'=>'Not logged in']); exit; }
$credId = $data['id'];
$stmt = $db->prepare('CREATE TABLE IF NOT EXISTS credentials (id INTEGER PRIMARY KEY AUTO_INCREMENT, user_id INTEGER, cred_id TEXT, public_key TEXT)');
$stmt->execute();
$stmt = $db->prepare('INSERT INTO credentials (user_id,cred_id,public_key) VALUES (?,?,?)');
$stmt->execute([$userId,$credId,json_encode($data['publicKey'] ?? [])]);
echo json_encode(['ok'=>true]);
