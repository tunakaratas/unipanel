<?php
/**
 * Mobil API - Phone Verification Code Sending Endpoint
 * POST /api/send_phone_verification_code.php - Telefon numarası doğrulama kodu gönderme
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

// Authentication kontrolü - Telefon numarası doğrulama için giriş yapmış olmalı
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
    
    $phone_number = sanitizeInput(trim($input['phone_number']), 'string');
    
    // Telefon numarası format kontrolü (Türkiye formatı: 05XX XXX XX XX veya +905XX XXX XX XX)
    $phone_number = preg_replace('/[^0-9+]/', '', $phone_number);
    
    // +90 ile başlıyorsa kaldır, 0 ile başlamıyorsa 0 ekle
    if (strpos($phone_number, '+90') === 0) {
        $phone_number = '0' . substr($phone_number, 3);
    } elseif (strpos($phone_number, '90') === 0 && strlen($phone_number) == 12) {
        $phone_number = '0' . substr($phone_number, 2);
    } elseif (strpos($phone_number, '0') !== 0 && strlen($phone_number) == 10) {
        $phone_number = '0' . $phone_number;
    }
    
    // Telefon numarası format kontrolü (10 haneli, 0 ile başlamalı)
    if (!preg_match('/^0[0-9]{10}$/', $phone_number)) {
        sendResponse(false, null, null, 'Geçersiz telefon numarası formatı. Örnek: 05551234567');
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
    
    // Phone verification codes tablosunu oluştur
    @$db->exec("CREATE TABLE IF NOT EXISTS phone_verification_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        phone_number TEXT NOT NULL,
        code TEXT NOT NULL,
        expires_at DATETIME NOT NULL,
        used INTEGER DEFAULT 0,
        verified INTEGER DEFAULT 0,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    // Eski kodları temizle (24 saatten eski veya kullanılmış)
    @$db->exec("DELETE FROM phone_verification_codes WHERE expires_at < datetime('now') OR (used = 1 AND verified = 1)");
    
    // Aynı telefon numarası için son 1 dakika içinde kod gönderilmiş mi kontrol et
    $check_stmt = $db->prepare("SELECT created_at FROM phone_verification_codes WHERE phone_number = ? AND created_at > datetime('now', '-1 minute') ORDER BY created_at DESC LIMIT 1");
    if (!$check_stmt) {
        $db->close();
        sendResponse(false, null, null, 'Veritabanı sorgusu hazırlanamadı: ' . $db->lastErrorMsg());
    }
    
    $check_stmt->bindValue(1, $phone_number, SQLITE3_TEXT);
    $result = $check_stmt->execute();
    if (!$result) {
        $check_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Veritabanı sorgusu çalıştırılamadı: ' . $db->lastErrorMsg());
    }
    
    if ($result->fetchArray()) {
        $result->finalize();
        $check_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Kod çok kısa süre önce gönderildi. Lütfen 1 dakika bekleyin.');
    }
    $result->finalize();
    $check_stmt->close();
    
    // 6 haneli rastgele kod oluştur
    $code = str_pad((string)rand(100000, 999999), 6, '0', STR_PAD_LEFT);
    
    // Kod 10 dakika geçerli
    $expires_at = date('Y-m-d H:i:s', strtotime('+10 minutes'));
    
    // Kodu veritabanına kaydet
    $insert_stmt = $db->prepare("INSERT INTO phone_verification_codes (user_id, phone_number, code, expires_at) VALUES (?, ?, ?, ?)");
    if (!$insert_stmt) {
        $db->close();
        sendResponse(false, null, null, 'Insert sorgusu hazırlanamadı: ' . $db->lastErrorMsg());
    }
    
    $insert_stmt->bindValue(1, $currentUser['id'], SQLITE3_INTEGER);
    $insert_stmt->bindValue(2, $phone_number, SQLITE3_TEXT);
    $insert_stmt->bindValue(3, $code, SQLITE3_TEXT);
    $insert_stmt->bindValue(4, $expires_at, SQLITE3_TEXT);
    
    $insertResult = $insert_stmt->execute();
    if (!$insertResult) {
        $insert_stmt->close();
        $db->close();
        sendResponse(false, null, null, 'Kod kaydedilemedi: ' . $db->lastErrorMsg());
    }
    $insert_stmt->close();
    
    // SMS gönder
    $smsSent = false;
    
    try {
        // Communication modülünü yükle
        $communicationPath = __DIR__ . '/../templates/functions/communication.php';
        if (!function_exists('send_sms_netgsm') && file_exists($communicationPath)) {
            require_once $communicationPath;
        }
        
        // NetGSM ayarlarını al
        $netgsm_username = '';
        $netgsm_password = '';
        $netgsm_msgheader = '';
        
        $credentialsPath = __DIR__ . '/../config/credentials.php';
        if (file_exists($credentialsPath)) {
            $credentials = require $credentialsPath;
            if (isset($credentials['netgsm'])) {
                $netgsm_config = $credentials['netgsm'];
                $netgsm_username = $netgsm_config['username'] ?? '';
                $netgsm_password = $netgsm_config['password'] ?? '';
                $netgsm_msgheader = $netgsm_config['msgheader'] ?? '';
            }
        }
        
        if (!empty($netgsm_username) && !empty($netgsm_password) && function_exists('send_sms_netgsm')) {
            $message = "UniFour telefon numarası doğrulama kodunuz: {$code}\n\nBu kod 10 dakika geçerlidir.\n\nEğer bu işlemi siz yapmadıysanız, bu mesajı görmezden gelebilirsiniz.";
            
            $smsResult = send_sms_netgsm($phone_number, $message, $netgsm_username, $netgsm_password, $netgsm_msgheader);
            
            if ($smsResult['success'] ?? false) {
                $smsSent = true;
                error_log("Phone verification SMS sent successfully to: $phone_number");
            } else {
                error_log("Phone verification SMS failed: " . ($smsResult['error'] ?? 'Unknown error'));
            }
        } else {
            error_log("NetGSM config incomplete or function missing");
        }
    } catch (Exception $smsException) {
        error_log("SMS sending error: " . $smsException->getMessage());
    }
    
    $db->close();
    
    // Kod oluşturuldu, SMS gönderilse de gönderilmese de başarılı say
    if ($smsSent) {
        sendResponse(true, ['phone_number' => $phone_number], 'Doğrulama kodu telefon numaranıza gönderildi.');
    } else {
        sendResponse(true, ['phone_number' => $phone_number], 'Doğrulama kodu oluşturuldu. SMS gönderiminde sorun olabilir, lütfen tekrar deneyin.');
    }
    
} catch (Exception $e) {
    error_log("send_phone_verification_code.php fatal error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'Doğrulama kodu gönderilirken bir hata oluştu: ' . $e->getMessage());
} catch (Error $e) {
    error_log("send_phone_verification_code.php fatal error: " . $e->getMessage() . "\nStack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'Doğrulama kodu gönderilirken bir hata oluştu: ' . $e->getMessage());
}
