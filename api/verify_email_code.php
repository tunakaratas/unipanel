<?php
/**
 * Mobil API - Email Verification Code Verification Endpoint
 * POST /api/verify_email_code.php - E-posta doğrulama kodu doğrulama
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// OPTIONS request için hemen cevap ver
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

function sendResponse($success, $data = null, $message = null, $error = null) {
    echo json_encode([
        'success' => $success,
        'data' => $data,
        'message' => $message,
        'error' => $error
    ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(false, null, null, 'Sadece POST istekleri kabul edilir');
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['email']) || empty(trim($input['email']))) {
        sendResponse(false, null, null, 'E-posta adresi gerekli');
    }
    
    if (!isset($input['code']) || empty(trim($input['code']))) {
        sendResponse(false, null, null, 'Doğrulama kodu gerekli');
    }
    
    $email = sanitizeInput(trim($input['email']), 'email');
    $code = sanitizeInput(trim($input['code']), 'string');
    
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
    $check_stmt = $db->prepare("SELECT id, expires_at, used FROM email_verification_codes WHERE email = ? AND code = ? ORDER BY created_at DESC LIMIT 1");
    $check_stmt->bindValue(1, $email, SQLITE3_TEXT);
    $check_stmt->bindValue(2, $code, SQLITE3_TEXT);
    $result = $check_stmt->execute();
    $row = $result->fetchArray(SQLITE3_ASSOC);
    
    if (!$row) {
        $db->close();
        sendResponse(false, null, null, 'Geçersiz doğrulama kodu');
    }
    
    // Kod kullanılmış mı kontrol et
    if ($row['used'] == 1) {
        $db->close();
        sendResponse(false, null, null, 'Bu kod daha önce kullanılmış');
    }
    
    // Kod süresi dolmuş mu kontrol et
    $expires_at = $row['expires_at'];
    if (strtotime($expires_at) < time()) {
        $db->close();
        sendResponse(false, null, null, 'Doğrulama kodu süresi dolmuş. Lütfen yeni kod isteyin.');
    }
    
    // Kodu kullanıldı olarak işaretle (kayıt işlemi sırasında tekrar kontrol edilecek)
    try {
        $mark_used_stmt = $db->prepare("UPDATE email_verification_codes SET used = 1 WHERE id = ?");
        if ($mark_used_stmt) {
            $mark_used_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
            @$mark_used_stmt->execute();
        }
    } catch (Exception $e) {
        // Hata olsa bile devam et
        error_log("Failed to mark code as used: " . $e->getMessage());
    }
    
    $db->close();
    
    sendResponse(true, ['email' => $email, 'verified' => true], 'E-posta başarıyla doğrulandı! Artık kayıt olabilirsiniz.');
    
} catch (Exception $e) {
    error_log("verify_email_code.php error: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
    
    // Database bağlantısını kapat (varsa)
    if (isset($db) && $db) {
        @$db->close();
    }
    
    // Güvenli hata mesajı
    $error_message = 'Doğrulama kodu kontrol edilirken bir hata oluştu. Lütfen tekrar deneyin.';
    
    // Veritabanı hatası kontrolü
    if (strpos($e->getMessage(), 'database') !== false || strpos($e->getMessage(), 'SQLite') !== false) {
        $error_message = 'Veritabanı hatası oluştu. Lütfen daha sonra tekrar deneyin.';
    }
    
    sendResponse(false, null, null, $error_message);
}

