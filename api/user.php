<?php
/**
 * Mobil API - User Profile Endpoint
 * GET /api/user.php?user_id={id} - Kullanıcı profil bilgilerini getir
 * PUT /api/user.php?user_id={id} - Kullanıcı profil bilgilerini güncelle
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';
require_once __DIR__ . '/auth_middleware.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: GET, PUT, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// OPTIONS request için hemen cevap ver
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Rate limiting
if (!checkRateLimit(60, 60)) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'data' => null,
        'message' => null,
        'error' => 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Authentication zorunlu
$currentUser = requireAuth(true);

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
    // user_id parametresi yoksa veya token'dan gelen kullanıcı ID'si ile eşleşmiyorsa, token'dan gelen ID'yi kullan
    if (!isset($_GET['user_id']) || empty($_GET['user_id'])) {
        // user_id parametresi yoksa, token'dan gelen kullanıcı ID'sini kullan
        $user_id = $currentUser['id'];
    } else {
        $user_id = (int)$_GET['user_id'];
        
        // Kullanıcı sadece kendi profilini görebilir/güncelleyebilir
        if ($user_id !== $currentUser['id']) {
            sendResponse(false, null, null, 'Bu işlem için yetkiniz yok');
        }
    }
    $system_db_path = __DIR__ . '/../public/unipanel.sqlite';
    
    if (!file_exists($system_db_path)) {
        sendResponse(false, null, null, 'Veritabanı dosyası bulunamadı');
    }
    
    $db = new SQLite3($system_db_path);
    @$db->exec('PRAGMA journal_mode = DELETE');
    
    // PUT isteği - Profil güncelleme
    if ($_SERVER['REQUEST_METHOD'] === 'PUT') {
        // CSRF koruması
        if (isset($_SERVER['HTTP_X_CSRF_TOKEN'])) {
            $csrfToken = $_SERVER['HTTP_X_CSRF_TOKEN'];
            if (!verifyCSRFToken($csrfToken)) {
                sendResponse(false, null, null, 'CSRF token geçersiz');
            }
        }
        
        $input = json_decode(file_get_contents('php://input'), true);
        
        // Email kontrolü (başka bir kullanıcıda var mı?)
        if (!empty($input['email'])) {
            // Email validation
            if (!validateEmail($input['email'])) {
                $db->close();
                sendResponse(false, null, null, 'Geçersiz email formatı');
            }
            
            $check_stmt = $db->prepare("SELECT id FROM system_users WHERE email = ? AND id != ?");
            $check_stmt->bindValue(1, $input['email'], SQLITE3_TEXT);
            $check_stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
            $check_result = $check_stmt->execute();
            if ($check_result->fetchArray()) {
                $db->close();
                sendResponse(false, null, null, 'Bu email adresi zaten kullanılıyor');
            }
        }
        
        // Student ID kontrolü (varsa)
        if (!empty($input['student_id'])) {
            $check_stmt = $db->prepare("SELECT id FROM system_users WHERE student_id = ? AND id != ?");
            $check_stmt->bindValue(1, $input['student_id'], SQLITE3_TEXT);
            $check_stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
            $check_result = $check_stmt->execute();
            if ($check_result->fetchArray()) {
                $db->close();
                sendResponse(false, null, null, 'Bu öğrenci numarası zaten kullanılıyor');
            }
        }
        
        // Güncelleme sorgusu
        $update_fields = [];
        $update_values = [];
        
        if (isset($input['first_name'])) {
            $first_name = sanitizeInput(trim($input['first_name']), 'string');
            if (strlen($first_name) > 100) {
                $db->close();
                sendResponse(false, null, null, 'Ad çok uzun (maksimum 100 karakter)');
            }
            $update_fields[] = "first_name = ?";
            $update_values[] = $first_name;
        }
        if (isset($input['last_name'])) {
            $last_name = sanitizeInput(trim($input['last_name']), 'string');
            if (strlen($last_name) > 100) {
                $db->close();
                sendResponse(false, null, null, 'Soyad çok uzun (maksimum 100 karakter)');
            }
            $update_fields[] = "last_name = ?";
            $update_values[] = $last_name;
        }
        if (isset($input['email'])) {
            $email = sanitizeInput(trim($input['email']), 'email');
            if (!validateEmail($email)) {
                $db->close();
                sendResponse(false, null, null, 'Geçersiz email formatı');
            }
            $update_fields[] = "email = ?";
            $update_values[] = $email;
        }
        if (isset($input['student_id'])) {
            $student_id = sanitizeInput(trim($input['student_id']), 'string');
            if (strlen($student_id) > 50) {
                $db->close();
                sendResponse(false, null, null, 'Öğrenci numarası çok uzun');
            }
            $update_fields[] = "student_id = ?";
            $update_values[] = $student_id;
        }
        if (isset($input['phone_number'])) {
            $phone_number = sanitizeInput(trim($input['phone_number']), 'string');
            if (!empty($phone_number) && !validatePhone($phone_number)) {
                $db->close();
                sendResponse(false, null, null, 'Geçersiz telefon numarası formatı');
            }
            $update_fields[] = "phone_number = ?";
            $update_values[] = $phone_number;
        }
        if (isset($input['university'])) {
            $university = sanitizeInput(trim($input['university']), 'string');
            if (strlen($university) > 200) {
                $db->close();
                sendResponse(false, null, null, 'Üniversite adı çok uzun');
            }
            $update_fields[] = "university = ?";
            $update_values[] = $university;
        }
        if (isset($input['department'])) {
            $department = sanitizeInput(trim($input['department']), 'string');
            if (strlen($department) > 200) {
                $db->close();
                sendResponse(false, null, null, 'Bölüm adı çok uzun');
            }
            $update_fields[] = "department = ?";
            $update_values[] = $department;
        }
        if (isset($input['password']) && !empty($input['password'])) {
            // Güçlü şifre kontrolü
            $passwordValidation = validatePassword($input['password']);
            if (!$passwordValidation['valid']) {
                $db->close();
                sendResponse(false, null, null, $passwordValidation['message']);
            }
            
            $update_fields[] = "password_hash = ?";
            $update_values[] = password_hash($input['password'], PASSWORD_BCRYPT);
        }
        
        if (empty($update_fields)) {
            $db->close();
            sendResponse(false, null, null, 'Güncellenecek alan bulunamadı');
        }
        
        $update_values[] = $user_id;
        $sql = "UPDATE system_users SET " . implode(", ", $update_fields) . " WHERE id = ?";
        $update_stmt = $db->prepare($sql);
        
        $i = 1;
        foreach ($update_values as $value) {
            $update_stmt->bindValue($i, $value, SQLITE3_TEXT);
            $i++;
        }
        
        $update_stmt->execute();
        $db->close();
        
        sendResponse(true, null, 'Profil başarıyla güncellendi');
    }
    
    // GET isteği - Profil bilgilerini getir
    // phone_verified kolonu yoksa ekle
    @$db->exec("ALTER TABLE system_users ADD COLUMN phone_verified INTEGER DEFAULT 0");
    
    $stmt = $db->prepare("SELECT id, email, first_name, last_name, student_id, phone_number, phone_verified, university, department, created_at, last_login FROM system_users WHERE id = ? AND is_active = 1");
    $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
    $result = $stmt->execute();
    $user = $result->fetchArray(SQLITE3_ASSOC);
    
    if (!$user) {
        $db->close();
        sendResponse(false, null, null, 'Kullanıcı bulunamadı');
    }
    
    $db->close();
    
    sendResponse(true, [
        'id' => (int)$user['id'],
        'email' => $user['email'],
        'first_name' => $user['first_name'],
        'last_name' => $user['last_name'],
        'full_name' => $user['first_name'] . ' ' . $user['last_name'],
        'student_id' => $user['student_id'] ?? null,
        'phone_number' => $user['phone_number'] ?? null,
        'phone_verified' => isset($user['phone_verified']) ? (bool)$user['phone_verified'] : false,
        'university' => $user['university'] ?? null,
        'department' => $user['department'] ?? null,
        'created_at' => $user['created_at'] ?? null,
        'last_login' => $user['last_login'] ?? null
    ]);
    
} catch (Exception $e) {
    $response = sendSecureErrorResponse('İşlem sırasında bir hata oluştu', $e);
    sendResponse($response['success'], $response['data'], $response['message'], $response['error']);
}

