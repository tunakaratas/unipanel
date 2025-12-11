<?php
/**
 * Mobil API - System User Registration Endpoint
 * POST /api/auth_register.php - Sistem kullanıcı kaydı
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

// Öğrenci e-postası domain kontrolü - sadece @ogr.bandirma.edu.tr
function isStudentEmail($email) {
    $emailLower = strtolower($email);
    return strpos($emailLower, '@ogr.bandirma.edu.tr') !== false;
}

try {
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        sendResponse(false, null, null, 'Sadece POST istekleri kabul edilir');
    }
    
    // CSRF koruması (opsiyonel - public registration için)
    // Web formlarından geliyorsa CSRF kontrolü yap
    if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
        $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'];
        if (!verifyCSRFToken($csrfToken)) {
            sendResponse(false, null, null, 'CSRF token geçersiz');
        }
    }
    
    $input = json_decode(file_get_contents('php://input'), true);
    
    if (!isset($input['email']) || empty(trim($input['email']))) {
        sendResponse(false, null, null, 'Email adresi gerekli');
    }
    
    if (!isset($input['password']) || empty($input['password'])) {
        sendResponse(false, null, null, 'Şifre gerekli');
    }
    
    if (!isset($input['first_name']) || empty(trim($input['first_name']))) {
        sendResponse(false, null, null, 'Ad gerekli');
    }
    
    if (!isset($input['last_name']) || empty(trim($input['last_name']))) {
        sendResponse(false, null, null, 'Soyad gerekli');
    }
    
    // Güçlü şifre kontrolü
    $passwordValidation = validatePassword($input['password']);
    if (!$passwordValidation['valid']) {
        sendResponse(false, null, null, $passwordValidation['message']);
    }
    
    $email = sanitizeInput(trim($input['email']), 'email');
    $password = $input['password']; // Şifre sanitize edilmez, password_hash için ham kalmalı
    $first_name = sanitizeInput(trim($input['first_name']), 'string');
    $last_name = sanitizeInput(trim($input['last_name']), 'string');
    $student_id = isset($input['student_id']) ? sanitizeInput(trim($input['student_id']), 'string') : null;
    $phone_number = isset($input['phone_number']) ? sanitizeInput(trim($input['phone_number']), 'string') : null;
    $university = isset($input['university']) ? sanitizeInput(trim($input['university']), 'string') : null;
    $department = isset($input['department']) ? sanitizeInput(trim($input['department']), 'string') : null;
    
    // Input validation
    if (strlen($first_name) > 100 || strlen($last_name) > 100) {
        sendResponse(false, null, null, 'Ad veya soyad çok uzun (maksimum 100 karakter)');
    }
    
    if (!empty($phone_number) && !validatePhone($phone_number)) {
        sendResponse(false, null, null, 'Geçersiz telefon numarası formatı');
    }
    
    if (!empty($student_id) && strlen($student_id) > 50) {
        sendResponse(false, null, null, 'Öğrenci numarası çok uzun');
    }
    
    // Genel sistem veritabanı yolu
    $system_db_path = __DIR__ . '/../public/unipanel.sqlite';
    
    // Veritabanı dizinini kontrol et ve oluştur
    $db_dir = dirname($system_db_path);
    if (!is_dir($db_dir)) {
        if (!mkdir($db_dir, 0755, true)) {
            sendResponse(false, null, null, 'Veritabanı dizini oluşturulamadı');
        }
    }
    
    // Veritabanı dosyasını oluştur (yoksa)
    if (!file_exists($system_db_path)) {
        touch($system_db_path);
        chmod($system_db_path, 0666);
    }
    
    $db = new SQLite3($system_db_path);
    if (!$db) {
        sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı');
    }
    
    @$db->exec('PRAGMA journal_mode = DELETE');
    
    // system_users tablosunu oluştur
    $db->exec("CREATE TABLE IF NOT EXISTS system_users (
        id INTEGER PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        student_id TEXT UNIQUE,
        password_hash TEXT NOT NULL,
        first_name TEXT NOT NULL,
        last_name TEXT NOT NULL,
        phone_number TEXT,
        university TEXT,
        department TEXT,
        email_verified INTEGER DEFAULT 0,
        is_active INTEGER DEFAULT 1,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        last_login DATETIME
    )");
    
    // email_verified kolonu yoksa ekle
    $columns = $db->query("PRAGMA table_info(system_users)");
    $hasEmailVerified = false;
    while ($col = $columns->fetchArray(SQLITE3_ASSOC)) {
        if ($col['name'] === 'email_verified') {
            $hasEmailVerified = true;
            break;
        }
    }
    if (!$hasEmailVerified) {
        $db->exec("ALTER TABLE system_users ADD COLUMN email_verified INTEGER DEFAULT 0");
    }
    
    // Email validation
    if (!validateEmail($email)) {
        $db->close();
        sendResponse(false, null, null, 'Geçersiz email formatı');
    }
    
    // Öğrenci e-postası kontrolü
    if (!isStudentEmail($email)) {
        $db->close();
        sendResponse(false, null, null, 'Sadece @ogr.bandirma.edu.tr e-posta adresleri kabul edilir');
    }
    
    // E-posta doğrulaması kontrolü
    $emailVerified = isset($input['email_verified']) && $input['email_verified'] === true;
    if (!$emailVerified) {
        // E-posta doğrulama kodu kontrolü
        $verificationCode = isset($input['verification_code']) ? trim($input['verification_code']) : '';
        
        error_log("Register - Email: $email, Verification Code: '" . ($verificationCode ?: 'BOŞ') . "', Length: " . strlen($verificationCode));
        
        if (empty($verificationCode)) {
            error_log("Register - Verification code is empty");
            $db->close();
            sendResponse(false, null, null, 'E-posta doğrulaması gerekli. Lütfen önce e-posta adresinizi doğrulayın.');
        }
        
        if (strlen($verificationCode) != 6) {
            error_log("Register - Verification code length is not 6: " . strlen($verificationCode));
            $db->close();
            sendResponse(false, null, null, 'Geçersiz doğrulama kodu formatı. Kod 6 haneli olmalıdır.');
        }
        
        // Doğrulama kodunu kontrol et
        $verify_db_path = __DIR__ . '/../public/unipanel.sqlite';
        if (file_exists($verify_db_path)) {
            $verify_db = new SQLite3($verify_db_path);
            @$verify_db->exec('PRAGMA journal_mode = DELETE');
            
            $check_code_stmt = $verify_db->prepare("SELECT id, expires_at, used FROM email_verification_codes WHERE email = ? AND code = ? ORDER BY created_at DESC LIMIT 1");
            $check_code_stmt->bindValue(1, $email, SQLITE3_TEXT);
            $check_code_stmt->bindValue(2, $verificationCode, SQLITE3_TEXT);
            $code_result = $check_code_stmt->execute();
            $code_row = $code_result->fetchArray(SQLITE3_ASSOC);
            
            error_log("Register - Code check result: " . ($code_row ? 'FOUND' : 'NOT FOUND'));
            
            if (!$code_row) {
                $verify_db->close();
                $db->close();
                error_log("Register - Code not found in database");
                sendResponse(false, null, null, 'Geçersiz doğrulama kodu. Lütfen doğru kodu girin.');
            }
            
            if ($code_row['used'] == 1) {
                $verify_db->close();
                $db->close();
                error_log("Register - Code already used");
                sendResponse(false, null, null, 'Bu doğrulama kodu daha önce kullanılmış. Lütfen yeni kod isteyin.');
            }
            
            if (strtotime($code_row['expires_at']) < time()) {
                $verify_db->close();
                $db->close();
                error_log("Register - Code expired");
                sendResponse(false, null, null, 'Doğrulama kodu süresi dolmuş. Lütfen yeni kod isteyin.');
            }
            
            // Kodu kullanıldı olarak işaretle (kayıt başarılı olacak)
            $mark_used_stmt = $verify_db->prepare("UPDATE email_verification_codes SET used = 1 WHERE id = ?");
            $mark_used_stmt->bindValue(1, $code_row['id'], SQLITE3_INTEGER);
            $mark_used_stmt->execute();
            
            // Kodu kullanıldı olarak işaretle
            $update_code_stmt = $verify_db->prepare("UPDATE email_verification_codes SET used = 1 WHERE id = ?");
            $update_code_stmt->bindValue(1, $code_row['id'], SQLITE3_INTEGER);
            $update_code_stmt->execute();
            
            error_log("Register - Code verified successfully");
            $verify_db->close();
            $emailVerified = true;
        } else {
            $db->close();
            error_log("Register - Verification database not found");
            sendResponse(false, null, null, 'E-posta doğrulama sistemi kullanılamıyor');
        }
    }
    
    // Email kontrolü
    $check_stmt = $db->prepare("SELECT id, email_verified FROM system_users WHERE email = ?");
    $check_stmt->bindValue(1, $email, SQLITE3_TEXT);
    $result = $check_stmt->execute();
    $existingUser = $result->fetchArray(SQLITE3_ASSOC);
    if ($existingUser) {
        $db->close();
        $isVerified = $existingUser['email_verified'] ?? 0;
        if ($isVerified) {
            sendResponse(false, null, null, 'Bu e-posta adresi zaten kayıtlı. Lütfen giriş yapın.');
        } else {
            sendResponse(false, null, null, 'Bu e-posta adresi zaten kayıtlı ancak henüz doğrulanmamış. Lütfen e-posta adresinizi kontrol edin veya farklı bir e-posta kullanın.');
        }
    }
    
    // Student ID kontrolü (varsa)
    if ($student_id) {
        $check_stmt = $db->prepare("SELECT id FROM system_users WHERE student_id = ?");
        $check_stmt->bindValue(1, $student_id, SQLITE3_TEXT);
        $result = $check_stmt->execute();
        if ($result->fetchArray()) {
            $db->close();
            sendResponse(false, null, null, 'Bu öğrenci numarası zaten kayıtlı');
        }
    }
    
    // Şifreyi hashle
    $password_hash = password_hash($password, PASSWORD_BCRYPT);
    if ($password_hash === false) {
        $db->close();
        error_log("Register - Password hash failed for email: $email");
        sendResponse(false, null, null, 'Şifre işleme hatası. Lütfen tekrar deneyin.');
    }
    
    // Kullanıcıyı kaydet
    $insert_stmt = $db->prepare("INSERT INTO system_users (email, student_id, password_hash, first_name, last_name, phone_number, university, department, email_verified) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
    if (!$insert_stmt) {
        $error_msg = $db->lastErrorMsg();
        $db->close();
        error_log("Register - Prepare failed: $error_msg");
        sendResponse(false, null, null, 'Kayıt işlemi başlatılamadı. Lütfen tekrar deneyin.');
    }
    
    $insert_stmt->bindValue(1, $email, SQLITE3_TEXT);
    $insert_stmt->bindValue(2, $student_id, SQLITE3_TEXT);
    $insert_stmt->bindValue(3, $password_hash, SQLITE3_TEXT);
    $insert_stmt->bindValue(4, $first_name, SQLITE3_TEXT);
    $insert_stmt->bindValue(5, $last_name, SQLITE3_TEXT);
    $insert_stmt->bindValue(6, $phone_number, SQLITE3_TEXT);
    $insert_stmt->bindValue(7, $university, SQLITE3_TEXT);
    $insert_stmt->bindValue(8, $department, SQLITE3_TEXT);
    $insert_stmt->bindValue(9, $emailVerified ? 1 : 0, SQLITE3_INTEGER);
    
    $execute_result = $insert_stmt->execute();
    if (!$execute_result) {
        $error_msg = $db->lastErrorMsg();
        $insert_stmt->close();
        $db->close();
        error_log("Register - Execute failed: $error_msg for email: $email");
        
        // Eğer email zaten kayıtlıysa (UNIQUE constraint violation)
        if (strpos($error_msg, 'UNIQUE constraint') !== false || strpos($error_msg, 'UNIQUE') !== false) {
            sendResponse(false, null, null, 'Bu e-posta adresi zaten kayıtlı. Lütfen giriş yapın.');
        }
        
        sendResponse(false, null, null, 'Kayıt işlemi başarısız oldu. Lütfen tekrar deneyin.');
    }
    
    $user_id = $db->lastInsertRowID();
    $insert_stmt->close();
    
    if (!$user_id || $user_id == 0) {
        $db->close();
        error_log("Register - lastInsertRowID failed for email: $email");
        sendResponse(false, null, null, 'Kullanıcı kaydedildi ancak ID alınamadı. Lütfen giriş yapmayı deneyin.');
    }
    
    // Son giriş zamanını güncelle
    try {
        $update_stmt = $db->prepare("UPDATE system_users SET last_login = CURRENT_TIMESTAMP WHERE id = ?");
        $update_stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
        @$update_stmt->execute();
    } catch (Exception $e) {
        error_log("Failed to update last_login: " . $e->getMessage());
    }
    
    // Otomatik giriş için token oluştur
    $token = null;
    $token_hash = null;
    try {
        // Token oluştur (güvenli random) ve hash'le
        $token = bin2hex(random_bytes(32));
        $token_hash = hash('sha256', $token);
        $expires_at = date('Y-m-d H:i:s', strtotime('+30 days'));
        $created_at = date('Y-m-d H:i:s');
        
        // api_tokens tablosunun varlığını kontrol et ve yoksa oluştur
        $table_check = $db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='api_tokens'");
        if (!$table_check || !$table_check->fetchArray()) {
            $create_table = "CREATE TABLE IF NOT EXISTS api_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token TEXT NOT NULL UNIQUE,
                token_hash TEXT,
                expires_at DATETIME NOT NULL,
                created_at DATETIME NOT NULL,
                last_used_at DATETIME DEFAULT NULL,
                revoked_at DATETIME DEFAULT NULL,
                FOREIGN KEY (user_id) REFERENCES system_users(id) ON DELETE CASCADE
            )";
            $db->exec($create_table);
            $db->exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_user_id ON api_tokens(user_id)");
            $db->exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_token ON api_tokens(token)");
            $db->exec("CREATE INDEX IF NOT EXISTS idx_api_tokens_expires_at ON api_tokens(expires_at)");
        }
        
        // token_hash kolonu yoksa ekle (migration)
        try {
            $db->exec("ALTER TABLE api_tokens ADD COLUMN token_hash TEXT");
        } catch (Exception $e) {
            // Kolon zaten varsa hata vermez
        }
        
        // Yeni token'ı ekle
        $token_stmt = $db->prepare("INSERT INTO api_tokens (user_id, token, token_hash, expires_at, created_at, last_used_at) VALUES (?, ?, ?, ?, ?, datetime('now'))");
        if ($token_stmt) {
            $token_stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
            $token_stmt->bindValue(2, $token, SQLITE3_TEXT);
            $token_stmt->bindValue(3, $token_hash, SQLITE3_TEXT);
            $token_stmt->bindValue(4, $expires_at, SQLITE3_TEXT);
            $token_stmt->bindValue(5, $created_at, SQLITE3_TEXT);
            @$token_stmt->execute();
        }
    } catch (Exception $e) {
        // Token oluşturma hatası kritik değil, kayıt başarılı
        error_log("Token creation error during registration: " . $e->getMessage());
    }
    
    $db->close();
    
    // Başarılı yanıt gönder - token ile birlikte
    http_response_code(200);
    sendResponse(true, [
        'user_id' => (int)$user_id,
        'email' => $email,
        'first_name' => $first_name,
        'last_name' => $last_name,
        'full_name' => $first_name . ' ' . $last_name,
        'token' => $token, // Otomatik giriş için token
        'user' => [
            'id' => (int)$user_id,
            'email' => $email,
            'first_name' => $first_name,
            'last_name' => $last_name,
            'full_name' => $first_name . ' ' . $last_name,
            'student_id' => $student_id,
            'phone_number' => $phone_number,
            'university' => $university,
            'department' => $department,
            'email_verified' => $emailVerified
        ]
    ], 'Kayıt başarılı! Hoş geldiniz, otomatik olarak giriş yapıldı.');
    
} catch (Exception $e) {
    error_log("Register - Exception: " . $e->getMessage() . " | Trace: " . $e->getTraceAsString());
    
    // Database bağlantısını kapat (varsa)
    if (isset($db) && $db) {
        @$db->close();
    }
    if (isset($verify_db) && $verify_db) {
        @$verify_db->close();
    }
    
    // Güvenli hata mesajı gönder
    $error_message = 'Kayıt işlemi sırasında bir hata oluştu. Lütfen tekrar deneyin.';
    
    // Eğer email zaten kayıtlıysa özel mesaj
    if (strpos($e->getMessage(), 'UNIQUE') !== false || strpos($e->getMessage(), 'already exists') !== false) {
        $error_message = 'Bu e-posta adresi zaten kayıtlı. Lütfen giriş yapın.';
    }
    
    // Veritabanı hatası kontrolü
    if (strpos($e->getMessage(), 'database') !== false || strpos($e->getMessage(), 'SQLite') !== false) {
        $error_message = 'Veritabanı hatası oluştu. Lütfen daha sonra tekrar deneyin.';
    }
    
    http_response_code(500);
    sendResponse(false, null, null, $error_message);
}

