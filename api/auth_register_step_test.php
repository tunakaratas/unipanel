<?php
header('Content-Type: application/json; charset=utf-8');

$raw = file_get_contents('php://input');
$input = json_decode($raw, true);

die(json_encode([
    'test' => true,
    'method' => $_SERVER['REQUEST_METHOD'] ?? 'NOT SET',
    'raw_input' => $raw,
    'input' => $input,
    'step' => $input['step'] ?? 'NOT SET',
    'step_type' => isset($input['step']) ? gettype($input['step']) : 'NOT SET'
], JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
