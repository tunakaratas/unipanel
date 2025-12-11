<?php
/**
 * Mobil API - Phone Verification Code Verification Endpoint
 * POST /api/verify_phone_code.php - Telefon numarası doğrulama kodu kontrolü
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/auth_middleware.php';
require_once __DIR__ . '/../lib/autoload.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');

// OPTIONS request için hemen cevap ver
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Rate limiting
if (!checkRateLimit(10, 60)) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'error' => 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

function sendResponse($success, $data = null, $message = null, $error = null) {
    http_response_code($success ? 200 : 400);
    echo json_encode([
        'success' => $success,
        'data' => $data,
        'message' => $message,
        'error' => $error
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// Authentication kontrolü
$currentUser = requireAuth();
if (!$currentUser) {
    sendResponse(false, null, null, 'Giriş yapmanız gerekiyor');
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(false, null, null, 'Sadece POST istekleri kabul edilir');
    }
    
    $rawInput = @file_get_contents('php://input');
    if (empty($rawInput) && !empty($_POST)) {
        $rawInput = json_encode($_POST);
    }
    if (empty($rawInput)) {
        sendResponse(false, null, null, 'Request body boş');
    }
    
    $input = json_decode($rawInput, true);
    if (json_last_error() !== JSON_ERROR_NONE) {
        sendResponse(false, null, null, 'Geçersiz JSON formatı: ' . json_last_error_msg());
    }
    
    if (!isset($input['phone_number']) || empty(trim($input['phone_number']))) {
        sendResponse(false, null, null, 'Telefon numarası gerekli');
    }
    
    if (!isset($input['code']) || empty(trim($input['code']))) {
        sendResponse(false, null, null, 'Doğrulama kodu gerekli');
    }
    
    $phone_number = sanitizeInput(trim($input['phone_number']), 'string');
    $code = sanitizeInput(trim($input['code']), 'string');
    
    // Telefon numarası format kontrolü
    $phone_number = preg_replace('/[^0-9+]/', '', $phone_number);
    if (strpos($phone_number, '+90') === 0) {
        $phone_number = '0' . substr($phone_number, 3);
    } elseif (strpos($phone_number, '90') === 0 && strlen($phone_number) == 12) {
        $phone_number = '0' . substr($phone_number, 2);
    } elseif (strpos($phone_number, '0') !== 0 && strlen($phone_number) == 10) {
        $phone_number = '0' . $phone_number;
    }
    
    // Kod format kontrolü (6 haneli sayı)
    if (!preg_match('/^\d{6}$/', $code)) {
        sendResponse(false, null, null, 'Geçersiz kod formatı. 6 haneli sayı olmalıdır.');
    }
    
    // Genel sistem veritabanı yolu
    $system_db_path = __DIR__ . '/../public/unipanel.sqlite';
    
    if (!file_exists($system_db_path)) {
        sendResponse(false, null, null, 'Veritabanı bulunamadı');
    }
    
    $db = new SQLite3($system_db_path);
    if (!$db) {
        sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı');
    }
    
    @$db->exec('PRAGMA journal_mode = DELETE');
    
    // Kodu kontrol et
    $check_stmt = $db->prepare("SELECT id, expires_at, used, verified FROM phone_verification_codes WHERE user_id = ? AND phone_number = ? AND code = ? ORDER BY created_at DESC LIMIT 1");
    if (!$check_stmt) {
        $db->close();
        sendResponse(false, null, null, 'Veritabanı sorgusu hazırlanamadı: ' . $db->lastErrorMsg());
    }
    
    $check_stmt->bindValue(1, $currentUser['id'], SQLITE3_INTEGER);
    $check_stmt->bindValue(2, $phone_number, SQLITE3_TEXT);
    $check_stmt->bindValue(3, $code, SQLITE3_TEXT);
    $result = $check_stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    if (!$row) {
        $check_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Geçersiz doğrulama kodu');
    }
    
    // Kod kullanılmış mı kontrol et
    if ($row['used'] == 1 && $row['verified'] == 1) {
        $check_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Bu kod daha önce kullanılmış');
    }
    
    // Kod süresi dolmuş mu kontrol et
    $expires_at = $row['expires_at'];
    if (strtotime($expires_at) < time()) {
        $check_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Doğrulama kodu süresi dolmuş. Lütfen yeni kod isteyin.');
    }
    
    // Kodu kullanıldı ve doğrulandı olarak işaretle
    $update_stmt = $db->prepare("UPDATE phone_verification_codes SET used = 1, verified = 1 WHERE id = ?");
    if ($update_stmt) {
        $update_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
        @$update_stmt->execute();
        $update_stmt->close();
    }
    
    // Kullanıcının telefon numarasını güncelle ve doğrulanmış olarak işaretle
    $update_user_stmt = $db->prepare("UPDATE system_users SET phone_number = ?, phone_verified = 1 WHERE id = ?");
    if ($update_user_stmt) {
        $update_user_stmt->bindValue(1, $phone_number, SQLITE3_TEXT);
        $update_user_stmt->bindValue(2, $currentUser['id'], SQLITE3_INTEGER);
        @$update_user_stmt->execute();
        $update_user_stmt->close();
    }
    
    $check_stmt->close();
    $db->close();
    
    sendResponse(true, [
        'phone_number' => $phone_number,
        'verified' => true
    ], 'Telefon numaranız başarıyla doğrulandı!');
    
} catch (Exception $e) {
    error_log("verify_phone_code.php fatal error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'Doğrulama kodu kontrol edilirken bir hata oluştu: ' . $e->getMessage());
} catch (Error $e) {
    error_log("verify_phone_code.php fatal error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'Doğrulama kodu kontrol edilirken bir hata oluştu: ' . $e->getMessage());
}
