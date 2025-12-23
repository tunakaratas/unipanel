<?php
/**
 * API Security Helper Functions
 * Merkezi güvenlik fonksiyonları
 */

/**
 * Environment kontrolü - Production mı?
 */
function isProduction() {
    $env = getenv('APP_ENV') ?: getenv('ENVIRONMENT');
    return $env === 'production' || $env === 'prod';
}

/**
 * CORS yapılandırması - Güvenli
 */
function setSecureCORS() {
    // İzin verilen origin'ler
    $allowed_origins = [
        'https://fourkampus.com.tr',
        'https://www.fourkampus.com.tr',
        'https://api.fourkampus.com.tr',
        'https://community.foursoftware.net',
        'https://app.foursoftware.net',
        'https://admin.foursoftware.net',
        // Mobile app origins
        'capacitor://localhost',
        'ionic://localhost',
        // Development origins
        'http://localhost',
        'http://127.0.0.1',
        'http://localhost:8080',
        'http://127.0.0.1:8080',
        'http://localhost:3000',
        'http://127.0.0.1:3000',
        'http://localhost:5173',
        'http://127.0.0.1:5173'
    ];
    
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    
    // Development için localhost'a izin ver
    if (!isProduction()) {
        $allowed_origins[] = 'http://localhost';
        $allowed_origins[] = 'http://127.0.0.1';
        $allowed_origins[] = 'http://localhost:80';
        $allowed_origins[] = 'http://127.0.0.1:80';
    }
    
    if (in_array($origin, $allowed_origins)) {
        header('Access-Control-Allow-Origin: ' . $origin);
        header('Access-Control-Allow-Credentials: true');
    } elseif (empty($origin)) {
        // Origin yoksa (mobile app'lerden gelebilir) production domain'e izin ver
        if (isProduction()) {
            header('Access-Control-Allow-Origin: https://fourkampus.com.tr');
        } else {
            header('Access-Control-Allow-Origin: http://localhost');
        }
    } else {
        // Origin belirtilmiş ama whitelist'te yok - production'da izin verme
        if (!isProduction()) {
            header('Access-Control-Allow-Origin: ' . $origin);
        }
    }
    
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token, X-Requested-With');
    header('Access-Control-Max-Age: 3600');
}

/**
 * Community ID sanitization - Path traversal koruması
 */
function sanitizeCommunityId($id) {
    if (empty($id)) {
        throw new Exception('Topluluk ID boş olamaz');
    }
    
    $id = basename($id);
    
    // Sadece alfanumerik, alt çizgi ve tire karakterlerine izin ver
    if (!preg_match('/^[a-zA-Z0-9_-]+$/', $id)) {
        throw new Exception('Geçersiz topluluk ID formatı');
    }
    
    // Path traversal karakterlerini kontrol et
    if (strpos($id, '..') !== false || strpos($id, '/') !== false || strpos($id, '\\') !== false) {
        throw new Exception('Geçersiz topluluk ID - path traversal tespit edildi');
    }
    
    return $id;
}

/**
 * Güvenli IP adresi alma - IP spoofing koruması
 */
function getRealIP() {
    $ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
    
    // IP adresini doğrula
    if (!filter_var($ip, FILTER_VALIDATE_IP)) {
        return 'unknown';
    }
    
    // Güvenilir proxy'lerden gelen header'ları kontrol et
    $trustedProxies = [
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
        '127.0.0.0/8'
    ];
    
    $isTrustedProxy = false;
    foreach ($trustedProxies as $proxy) {
        if (ipInRange($ip, $proxy)) {
            $isTrustedProxy = true;
            break;
        }
    }
    
    // Sadece güvenilir proxy'lerden gelen X-Forwarded-For'u kabul et
    if ($isTrustedProxy && isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        $forwardedFor = $_SERVER['HTTP_X_FORWARDED_FOR'];
        $ips = explode(',', $forwardedFor);
        $realIp = trim($ips[0]);
        
        if (filter_var($realIp, FILTER_VALIDATE_IP)) {
            return $realIp;
        }
    }
    
    return $ip;
}

/**
 * IP range kontrolü
 */
function ipInRange($ip, $range) {
    if (strpos($range, '/') === false) {
        return $ip === $range;
    }
    
    list($subnet, $mask) = explode('/', $range);
    $ipLong = ip2long($ip);
    $subnetLong = ip2long($subnet);
    $maskLong = -1 << (32 - (int)$mask);
    
    return ($ipLong & $maskLong) === ($subnetLong & $maskLong);
}

/**
 * Password validation - Güçlü şifre kontrolü
 */
function validatePassword($password) {
    if (empty($password)) {
        return ['valid' => false, 'message' => 'Şifre boş olamaz'];
    }
    
    if (strlen($password) < 8) {
        return ['valid' => false, 'message' => 'Şifre en az 8 karakter olmalıdır'];
    }
    
    if (strlen($password) > 128) {
        return ['valid' => false, 'message' => 'Şifre çok uzun (maksimum 128 karakter)'];
    }
    
    // En az bir büyük harf
    if (!preg_match('/[A-Z]/', $password)) {
        return ['valid' => false, 'message' => 'Şifre en az bir büyük harf içermelidir'];
    }
    
    // En az bir küçük harf
    if (!preg_match('/[a-z]/', $password)) {
        return ['valid' => false, 'message' => 'Şifre en az bir küçük harf içermelidir'];
    }
    
    // En az bir rakam
    if (!preg_match('/[0-9]/', $password)) {
        return ['valid' => false, 'message' => 'Şifre en az bir rakam içermelidir'];
    }
    
    // Yaygın şifreler kontrolü (basit)
    $commonPasswords = ['password', '12345678', 'qwerty', 'abc123', 'password123'];
    if (in_array(strtolower($password), $commonPasswords)) {
        return ['valid' => false, 'message' => 'Bu şifre çok yaygın, lütfen daha güvenli bir şifre seçin'];
    }
    
    return ['valid' => true, 'message' => 'Şifre geçerli'];
}

/**
 * Email validation - Güçlendirilmiş
 */
function validateEmail($email) {
    if (empty($email)) {
        return false;
    }
    
    $email = trim($email);
    
    // PHP'nin built-in validation
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return false;
    }
    
    // Uzunluk kontrolü
    if (strlen($email) > 255) {
        return false;
    }
    
    // Tehlikeli karakterler
    if (preg_match('/[<>"\']/', $email)) {
        return false;
    }
    
    return true;
}

/**
 * Phone validation
 */
function validatePhone($phone) {
    if (empty($phone)) {
        return false;
    }
    
    $phone = preg_replace('/\s+/', '', $phone);
    
    // Türkiye telefon formatı: 5 ile başlayan 10 haneli
    return preg_match('/^5[0-9]{9}$/', $phone);
}

/**
 * URL validation
 */
function validateURL($url) {
    if (empty($url)) {
        return false;
    }
    
    return filter_var($url, FILTER_VALIDATE_URL) !== false;
}

/**
 * File upload validation
 */
function validateUploadedFile($file, $allowedTypes = null, $maxSize = null) {
    if (!isset($file['tmp_name']) || !is_uploaded_file($file['tmp_name'])) {
        return ['valid' => false, 'message' => 'Geçersiz dosya yükleme'];
    }
    
    // Varsayılan ayarlar
    if ($allowedTypes === null) {
        $allowedTypes = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
    }
    
    if ($maxSize === null) {
        $maxSize = 5 * 1024 * 1024; // 5MB
    }
    
    // Dosya tipi kontrolü
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mimeType = finfo_file($finfo, $file['tmp_name']);
    finfo_close($finfo);
    
    if (!in_array($mimeType, $allowedTypes)) {
        return ['valid' => false, 'message' => 'Geçersiz dosya tipi. İzin verilen tipler: ' . implode(', ', $allowedTypes)];
    }
    
    // Dosya boyutu kontrolü
    if ($file['size'] > $maxSize) {
        return ['valid' => false, 'message' => 'Dosya çok büyük. Maksimum boyut: ' . ($maxSize / 1024 / 1024) . 'MB'];
    }
    
    // Dosya içeriği kontrolü (magic bytes)
    $handle = fopen($file['tmp_name'], 'rb');
    $bytes = fread($handle, 4);
    fclose($handle);
    
    // JPEG: FF D8 FF
    // PNG: 89 50 4E 47
    // GIF: 47 49 46 38
    $validSignatures = [
        "\xFF\xD8\xFF", // JPEG
        "\x89\x50\x4E\x47", // PNG
        "\x47\x49\x46\x38", // GIF
    ];
    
    $isValid = false;
    foreach ($validSignatures as $signature) {
        if (substr($bytes, 0, strlen($signature)) === $signature) {
            $isValid = true;
            break;
        }
    }
    
    if (!$isValid && in_array($mimeType, ['image/jpeg', 'image/png', 'image/gif'])) {
        return ['valid' => false, 'message' => 'Dosya içeriği dosya tipiyle uyuşmuyor'];
    }
    
    return ['valid' => true, 'message' => 'Dosya geçerli'];
}

/**
 * Güvenli error response - Production için
 */
function sendSecureErrorResponse($error, $exception = null) {
    if (isProduction()) {
        // Production'da genel mesaj
        return [
            'success' => false,
            'data' => null,
            'message' => null,
            'error' => 'Bir hata oluştu. Lütfen daha sonra tekrar deneyin.'
        ];
    } else {
        // Development'ta detaylı mesaj
        $errorMessage = $error;
        if ($exception instanceof Exception) {
            $errorMessage .= ': ' . $exception->getMessage();
        }
        
        return [
            'success' => false,
            'data' => null,
            'message' => null,
            'error' => $errorMessage
        ];
    }
}

/**
 * Güvenli logging - Production'da hassas bilgileri loglama
 */
function secureLog($message, $level = 'info') {
    if (isProduction()) {
        // Production'da sadece kritik hataları logla
        if ($level === 'error' || $level === 'critical') {
            error_log("[{$level}] " . $message);
        }
    } else {
        // Development'ta tüm logları göster
        error_log("[{$level}] " . $message);
    }
}

/**
 * Input sanitization - XSS koruması
 */
function sanitizeInput($input, $type = 'string') {
    if (is_array($input)) {
        return array_map(function($item) use ($type) {
            return sanitizeInput($item, $type);
        }, $input);
    }
    
    if (!is_string($input)) {
        return $input;
    }
    
    $input = trim($input);
    
    switch ($type) {
        case 'string':
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
        case 'email':
            return filter_var($input, FILTER_SANITIZE_EMAIL);
        case 'url':
            return filter_var($input, FILTER_SANITIZE_URL);
        case 'int':
            return (int)$input;
        case 'float':
            return (float)$input;
        default:
            return htmlspecialchars($input, ENT_QUOTES, 'UTF-8');
    }
}

/**
 * CSRF Token oluştur
 */
function generateCSRFToken() {
    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }
    
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    
    return $_SESSION['csrf_token'];
}

/**
 * CSRF Token doğrula
 */
function verifyCSRFToken($token) {
    if (session_status() === PHP_SESSION_NONE) {
        @session_start();
    }
    
    if (empty($token) || !isset($_SESSION['csrf_token'])) {
        return false;
    }
    
    return hash_equals($_SESSION['csrf_token'], $token);
}

/**
 * Session güvenlik ayarları
 */
function configureSecureSession() {
    if (session_status() === PHP_SESSION_NONE) {
        ini_set('session.cookie_httponly', 1);
        ini_set('session.use_strict_mode', 1);
        ini_set('session.cookie_samesite', 'Strict');
        
        if (isProduction() && (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')) {
            ini_set('session.cookie_secure', 1);
        }
        
        @session_start();
    }
}

