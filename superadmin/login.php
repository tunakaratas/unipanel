<?php
/**
 * SuperAdmin Login Page
 * 
 * Handles superadmin authentication with 2FA (SMS) and CSRF protection.
 */

// Config ve Security Helper dosyalarını dahil et
$config = require __DIR__ . '/config.php';
require_once __DIR__ . '/security_helper.php';

const SUPERADMIN_DB_PATH = __DIR__ . '/../unipanel.sqlite';
define('SUPERADMIN_SESSION_LIFETIME', $config['security']['session_lifetime']);
const SUPERADMIN_SMS_COOLDOWN = 60;
const SUPERADMIN_CODE_TTL = 600;
const SUPERADMIN_LOGIN_MAX_ATTEMPTS = 5;
const SUPERADMIN_LOGIN_LOCK_SECONDS = 900;
const SUPERADMIN_VERIFY_MAX_ATTEMPTS = 5;
const SUPERADMIN_VERIFY_LOCK_SECONDS = 900;

// Session başlat
if (session_status() === PHP_SESSION_NONE) {
    $secure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    $cookieParams = [
        'lifetime' => SUPERADMIN_SESSION_LIFETIME,
        'path' => '/',
        'domain' => '',
        'secure' => $secure,
        'httponly' => true,
        'samesite' => 'Strict'
    ];
    if (PHP_VERSION_ID >= 70300) {
        session_set_cookie_params($cookieParams);
    } else {
        session_set_cookie_params($cookieParams['lifetime'], $cookieParams['path'], $cookieParams['domain'], $cookieParams['secure'], $cookieParams['httponly']);
    }
session_start();
}

error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Template logging helper (tpl_error_log, etc.)
if (!function_exists('tpl_error_log')) {
    require_once __DIR__ . '/../templates/partials/logging.php';
}

// Helper Fonksiyonlar
function superadmin_extend_session_cookie($lifetime = SUPERADMIN_SESSION_LIFETIME): void {
    if (PHP_SAPI === 'cli') {
        return;
    }
    $params = session_get_cookie_params();
    $options = [
        'expires' => time() + $lifetime,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => $params['secure'] ?? (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on'),
        'httponly' => true,
        'samesite' => $params['samesite'] ?? 'Strict'
    ];
    setcookie(session_name(), session_id(), $options);
}

function superadmin_sms_cooldown_remaining(): int {
    if (!isset($_SESSION['superadmin_verification_last_sent'])) {
        return 0;
    }
    $elapsed = time() - (int) $_SESSION['superadmin_verification_last_sent'];
    $remaining = SUPERADMIN_SMS_COOLDOWN - $elapsed;
    return $remaining > 0 ? $remaining : 0;
}

function ensure_superadmin_phone_column(SQLite3 $db): void {
    $columns = @$db->query("PRAGMA table_info(superadmins)");
    $hasPhone = false;
    if ($columns) {
        while ($row = $columns->fetchArray(SQLITE3_ASSOC)) {
            if (($row['name'] ?? '') === 'phone_number') {
                $hasPhone = true;
                break;
            }
        }
    }
    if (!$hasPhone) {
        @$db->exec("ALTER TABLE superadmins ADD COLUMN phone_number TEXT");
    }
}

function get_superadmin_phone(SQLite3 $db, array $admin): string {
    global $config;
    $phone = '';
    
    if (!empty($admin['phone_number'])) {
        $phone = $admin['phone_number'];
    } elseif (!empty($config['superadmin']['phone_number'])) {
        $phone = $config['superadmin']['phone_number'];
    }
    
    // Telefon numarasını normalize et
    if (!empty($phone)) {
        // Sadece rakamları al
        $phone = preg_replace('/[^0-9]/', '', $phone);
        
        // Türk telefon numarası formatına çevir
        if (strlen($phone) == 11 && substr($phone, 0, 1) == '0') {
            $phone = substr($phone, 1); // Başındaki 0'ı kaldır
        } elseif (strlen($phone) == 13 && substr($phone, 0, 3) == '900') {
            $phone = substr($phone, 2); // 90'ı kaldır (900... -> 0... -> ...)
        } elseif (strlen($phone) == 12 && substr($phone, 0, 2) == '90') {
            $phone = substr($phone, 2); // 90'ı kaldır
        } elseif (strlen($phone) == 13 && substr($phone, 0, 3) == '+90') {
            // Bu durum zaten rakamlar alındığı için olmaz ama yine de kontrol
            $phone = preg_replace('/^\+?90/', '', $phone);
        }
    }
    
    return $phone;
}

function superadmin_send_verification_sms(string $phone, string $code): array {
    global $config;
    
    // Static cache - aynı request içinde tekrar kullanılabilir
    static $cached_config = null;
    static $functions_loaded = false;
    
    // Fonksiyonları sadece bir kez yükle
    if (!$functions_loaded) {
        if (!function_exists('send_sms_netgsm') && !function_exists('send_sms_twilio')) {
            require_once __DIR__ . '/../templates/functions/communication.php';
        }
        $functions_loaded = true;
    }
    
    // Config'i cache'le
    if ($cached_config === null) {
        $provider = strtolower($config['superadmin']['sms_provider'] ?? 'netgsm');
        $cached_config = [
            'provider' => $provider,
            'netgsm_user' => $config['netgsm']['user'] ?? '',
            'netgsm_pass' => $config['netgsm']['pass'] ?? '',
            'netgsm_header' => $config['netgsm']['header'] ?? '',
            'twilio_sid' => $config['twilio']['sid'] ?? '',
            'twilio_token' => $config['twilio']['token'] ?? '',
            'twilio_from' => $config['twilio']['from'] ?? '',
            'twilio_messaging' => $config['twilio']['messaging_sid'] ?? ''
        ];
    }
    
    $message = sprintf(
        'UniFour SuperAdmin Güvenli Giriş Kodunuz: %s. Bu kod 10 dakika boyunca geçerlidir. Paylaşmayın.',
        $code
    );
    
    if ($cached_config['provider'] === 'twilio') {
        if (empty($cached_config['twilio_sid']) || empty($cached_config['twilio_token']) || 
            (empty($cached_config['twilio_from']) && empty($cached_config['twilio_messaging']))) {
            return ['success' => false, 'error' => 'Twilio ayarları eksik.'];
        }
        return send_sms_twilio($phone, $message, $cached_config['twilio_from'], 
            $cached_config['twilio_sid'], $cached_config['twilio_token'], $cached_config['twilio_messaging']);
    }
    
    // NetGSM (varsayılan)
    if (empty($cached_config['netgsm_user']) || empty($cached_config['netgsm_pass'])) {
        return ['success' => false, 'error' => 'NetGSM ayarları eksik.'];
    }
    
    return send_sms_netgsm($phone, $message, $cached_config['netgsm_user'], 
        $cached_config['netgsm_pass'], $cached_config['netgsm_header']);
}

function superadmin_is_locked(string $type): int {
    $lockUntil = $_SESSION["{$type}_lock_until"] ?? 0;
    if ($lockUntil > time()) {
        return $lockUntil - time();
    }
    return 0;
}

function superadmin_register_failure(string $type, int $maxAttempts, int $lockSeconds): void {
    $countKey = "{$type}_attempts";
    $count = ($_SESSION[$countKey] ?? 0) + 1;
    $_SESSION[$countKey] = $count;
    if ($count >= $maxAttempts) {
        $_SESSION["{$type}_lock_until"] = time() + $lockSeconds;
        $_SESSION[$countKey] = 0;
    }
}

function superadmin_reset_attempts(string $type): void {
    unset($_SESSION["{$type}_attempts"], $_SESSION["{$type}_lock_until"]);
}

require_once __DIR__ . '/../templates/functions/communication.php'; // SMS fonksiyonları için

// IP Kontrolü
function checkAccessPermission() {
    global $config;
    $allowed_ips = $config['security']['allowed_ips'];
    
    if (empty($allowed_ips)) {
        return true;
    }

    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $forwarded_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    $real_ip = $_SERVER['HTTP_X_REAL_IP'] ?? '';
    
    $all_ips = array_filter([$client_ip, $forwarded_ip, $real_ip]);
    
    foreach ($all_ips as $ip) {
        if (in_array($ip, $allowed_ips)) {
            return true;
        }
    }
    return false;
}

if (!checkAccessPermission()) {
    $log_file = __DIR__ . '/../system/logs/security.log';
    if (!is_dir(dirname($log_file))) {
        @mkdir(dirname($log_file), 0755, true);
    }
    $log_entry = sprintf(
        "[%s] Unauthorized access attempt to SuperAdmin from IP: %s, UA: %s\n",
        date('Y-m-d H:i:s'),
        $_SERVER['REMOTE_ADDR'] ?? 'unknown',
        $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
    );
    @file_put_contents($log_file, $log_entry, FILE_APPEND);
    header('HTTP/1.0 403 Forbidden');
    echo 'Erişim reddedildi.';
    exit;
}

// PasswordManager sınıfı
if (!class_exists('PasswordManager')) {
    class PasswordManager {
        public static function hash($password) {
            return password_hash($password, PASSWORD_BCRYPT, ['cost' => 12]);
        }
        public static function verify($password, $hash) {
            return password_verify($password, $hash);
        }
    }
}

// İşlem Mantığı
$error = '';
$success = '';
$step = 'login';

if (isset($_SESSION['superadmin_logged_in']) && $_SESSION['superadmin_logged_in'] === true) {
            header('Location: index.php');
            exit;
        }

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası: Geçersiz form isteği (CSRF). Lütfen sayfayı yenileyip tekrar deneyin.';
    } else {
        $loginLock = superadmin_is_locked('login');
        if ($loginLock > 0) {
            $error = 'Çok fazla başarısız giriş denemesi. Lütfen ' . $loginLock . ' saniye sonra tekrar deneyin.';
        } else {
        $username = trim($_POST['username'] ?? '');
        $password = $_POST['password'] ?? '';
        
        if (empty($username) || empty($password)) {
            $error = 'Lütfen kullanıcı adı ve şifre giriniz.';
                superadmin_register_failure('login', SUPERADMIN_LOGIN_MAX_ATTEMPTS, SUPERADMIN_LOGIN_LOCK_SECONDS);
        } else {
            $db = new SQLite3(SUPERADMIN_DB_PATH);
                    ensure_superadmin_phone_column($db);
            $stmt = $db->prepare('SELECT * FROM superadmins WHERE username = :username');
            $stmt->bindValue(':username', $username, SQLITE3_TEXT);
                $result = $stmt->execute();
                $admin = $result->fetchArray(SQLITE3_ASSOC);
            
            if ($admin && PasswordManager::verify($password, $admin['password_hash'])) {
                    superadmin_reset_attempts('login');
                
                // TEST MODU: 2FA'yı atla ve direkt giriş yap
                $test_mode = false; // SMS aktif - 2FA çalışıyor
                
                // Şifre doğru, 2FA başlat
                            $phone = get_superadmin_phone($db, $admin);
                
                // Telefon numarası kontrolü
                if (empty($phone)) {
                    $error = 'Telefon numarası bulunamadı! Lütfen superadmin ayarlarından telefon numaranızı girin veya SUPERADMIN_PHONE environment variable\'ını ayarlayın.';
                } else {
                    // SMS Cooldown kontrolü
                    if (superadmin_sms_cooldown_remaining() > 0) {
                        $step = 'verify';
                        $error = 'Yeni kod için ' . superadmin_sms_cooldown_remaining() . ' saniye beklemelisiniz.';
                                } else {
                        $code = (string) rand(100000, 999999);
                        $smsResult = superadmin_send_verification_sms($phone, $code);
                        
                        if ($smsResult['success']) {
                            $_SESSION['superadmin_verification_username'] = $username;
                            $_SESSION['superadmin_verification_code'] = $code;
                            $_SESSION['superadmin_verification_expires'] = time() + SUPERADMIN_CODE_TTL;
                            $_SESSION['superadmin_verification_last_sent'] = time();
                            $step = 'verify';
                            $success = 'Doğrulama kodu gönderildi. Lütfen telefonunuza gelen SMS kodunu girin.';
                        } else {
                            $error = 'SMS gönderilemedi: ' . ($smsResult['error'] ?? 'Bilinmeyen hata') . '. Lütfen NetGSM ayarlarını kontrol edin.';
                        }
                    }
                }
            } else {
                $error = 'Kullanıcı adı veya şifre hatalı.';
                    superadmin_register_failure('login', SUPERADMIN_LOGIN_MAX_ATTEMPTS, SUPERADMIN_LOGIN_LOCK_SECONDS);
            }
            $db->close();
        }
        }
    }
} elseif ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['verify_code'])) {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = 'Güvenlik hatası: Geçersiz form isteği (CSRF).';
    } else {
        $verifyLock = superadmin_is_locked('verify');
        if ($verifyLock > 0) {
            $error = 'Çok fazla hatalı doğrulama kodu girildi. Lütfen ' . $verifyLock . ' saniye sonra tekrar deneyin.';
            $step = 'verify';
        } else {
            $code = $_POST['code'] ?? '';
            
            if (empty($_SESSION['superadmin_verification_code']) || 
                empty($_SESSION['superadmin_verification_expires']) || 
                time() > $_SESSION['superadmin_verification_expires']) {
                $error = 'Doğrulama kodu süresi dolmuş veya geçersiz. Lütfen tekrar giriş yapın.';
                $step = 'login';
            } elseif ($code === $_SESSION['superadmin_verification_code']) {
                // Başarılı giriş
                $_SESSION['superadmin_logged_in'] = true;
                $_SESSION['superadmin_username'] = $_SESSION['superadmin_verification_username'];
                $_SESSION['superadmin_login_time'] = time();
                $_SESSION['superadmin_ip'] = $_SERVER['REMOTE_ADDR'] ?? '';
                $_SESSION['superadmin_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? '';
                $_SESSION['superadmin_last_activity'] = time();
                superadmin_reset_attempts('verify');
                
                // Session Fixation önlemi
                regenerate_session_secure();
                
                // Temizlik
                unset($_SESSION['superadmin_verification_code']);
                unset($_SESSION['superadmin_verification_expires']);
                unset($_SESSION['superadmin_verification_username']);
                unset($_SESSION['superadmin_verification_last_sent']);
                
                superadmin_extend_session_cookie();
                
                header('Location: index.php');
                exit;
            } else {
                $error = 'Hatalı doğrulama kodu.';
                $step = 'verify';
                superadmin_register_failure('verify', SUPERADMIN_VERIFY_MAX_ATTEMPTS, SUPERADMIN_VERIFY_LOCK_SECONDS);
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SuperAdmin Girişi - UniPanel</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.5.1/css/all.min.css">
    <?php include __DIR__ . '/../templates/partials/tailwind_cdn_loader.php'; ?>
    <style>
        :root {
            --primary-color: #6366f1;
            --primary-dark: #4f46e5;
            --primary-light: #818cf8;
            --secondary-color: #8b5cf6;
            --text-primary: #0f172a;
            --text-secondary: #475569;
            --text-light: #94a3b8;
            --bg-primary: #ffffff;
            --bg-secondary: #f8fafc;
            --border-color: #e2e8f0;
            --shadow-sm: 0 1px 2px 0 rgba(15, 23, 42, 0.05);
            --shadow-md: 0 4px 6px -1px rgba(15, 23, 42, 0.1), 0 2px 4px -1px rgba(15, 23, 42, 0.06);
            --shadow-lg: 0 10px 15px -3px rgba(15, 23, 42, 0.1), 0 4px 6px -2px rgba(15, 23, 42, 0.05);
            --shadow-xl: 0 20px 25px -5px rgba(15, 23, 42, 0.1), 0 10px 10px -5px rgba(15, 23, 42, 0.04);
            --shadow-2xl: 0 25px 50px -12px rgba(15, 23, 42, 0.25);
            --gradient-primary: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            --transition-fast: 150ms cubic-bezier(0.4, 0, 0.2, 1);
            --transition-base: 300ms cubic-bezier(0.4, 0, 0.2, 1);
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, #eef2ff 0%, #f8fafc 40%, #ffffff 100%);
            min-height: 100vh;
            padding: clamp(2rem, 6vw, 5rem);
            position: relative;
            overflow-x: hidden;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }
        
        .input-wrapper {
            position: relative;
        }
        
        .input-icon {
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            color: var(--text-light);
            pointer-events: none;
            transition: color var(--transition-base);
            z-index: 1;
        }
        
        .input-wrapper input:focus ~ .input-icon,
        .input-wrapper input:not(:placeholder-shown) ~ .input-icon {
            color: #6366f1;
        }
        
        .input-wrapper input {
            padding-left: 44px;
            transition: all var(--transition-base);
        }
        
        .input-wrapper input:focus {
            padding-left: 44px;
        }
        
        .form-input {
            transition: all var(--transition-base);
            background: var(--bg-primary) !important;
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            width: 100% !important;
            height: auto !important;
        }
        
        .form-input:focus {
            border-color: #6366f1 !important;
            box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1) !important;
            outline: none !important;
        }
        
        .btn-primary { 
            background: linear-gradient(135deg, #4f46e5 0%, #6366f1 100%);
            border: none;
            box-shadow: 0 10px 25px -10px rgba(79, 70, 229, 0.65);
            transition: all var(--transition-base);
        }
        
        .btn-primary:hover { 
            background: linear-gradient(135deg, #4338ca 0%, #4f46e5 100%);
            transform: translateY(-1px);
        }
        
        @keyframes fadeInUp {
            from {
                opacity: 0;
                transform: translateY(20px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        .fade-in-up {
            animation: fadeInUp 0.6s ease-out;
        }

        .auth-page {
            position: relative;
            min-height: calc(100vh - clamp(2rem, 6vw, 5rem) * 2);
            display: flex;
            align-items: center;
            justify-content: center;
            width: 100%;
            max-width: 1200px;
            margin: 0 auto;
        }

        .auth-blur {
            position: absolute;
            inset: 0;
            background: radial-gradient(circle at top right, rgba(99, 102, 241, 0.12), transparent 55%),
                        radial-gradient(circle at bottom left, rgba(129, 140, 248, 0.18), transparent 60%);
            z-index: -2;
            filter: blur(0px);
            display: none;
        }

        .auth-card {
            position: relative;
            width: 100%;
            display: grid;
            grid-template-columns: 1fr;
            overflow: hidden;
            backdrop-filter: none;
            background: transparent;
            z-index: 1;
        }

        @media (min-width: 900px) {
            .auth-card {
                grid-template-columns: minmax(0, 0.9fr) minmax(0, 1.1fr);
            }
        }

        @media (min-width: 1024px) {
            body {
                padding: 0;
            }

            .auth-page {
                max-width: none;
                min-height: 100vh;
                align-items: stretch;
                justify-content: stretch;
            }

            .auth-card {
                min-height: 100vh;
                grid-template-columns: minmax(0, 0.75fr) minmax(0, 1fr);
            }

            .auth-card-media,
            .auth-card-form {
                height: 100%;
            }
        }

        .auth-card-media {
            position: relative;
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            color: white;
            padding: clamp(2.5rem, 5vw, 3.75rem);
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: clamp(1.5rem, 3vw, 2.5rem);
            overflow: hidden;
        }

        .auth-card-media::before,
        .auth-card-media::after {
            content: '';
            position: absolute;
            border-radius: 999px;
            filter: blur(0);
            opacity: 0.65;
            z-index: 0;
        }

        .auth-card-media::before {
            width: clamp(220px, 40vw, 320px);
            height: clamp(220px, 40vw, 320px);
            background: rgba(255, 255, 255, 0.12);
            top: clamp(-140px, -10vw, -80px);
            right: clamp(-120px, -8vw, -70px);
        }

        .auth-card-media::after {
            width: clamp(160px, 30vw, 280px);
            height: clamp(160px, 30vw, 260px);
            background: rgba(255, 255, 255, 0.08);
            bottom: clamp(-120px, -8vw, -70px);
            left: clamp(-120px, -8vw, -70px);
        }

        .auth-media-content {
            position: relative;
            z-index: 1;
            display: flex;
            flex-direction: column;
            gap: clamp(1.25rem, 2.5vw, 1.75rem);
        }

        .auth-brand {
            display: flex;
            align-items: center;
            gap: 1rem;
        }

        .auth-brand-icon {
            width: clamp(60px, 10vw, 72px);
            height: clamp(60px, 10vw, 72px);
            border-radius: 20px;
            display: grid;
            place-items: center;
            background: rgba(255, 255, 255, 0.16);
            box-shadow: inset 0 0 0 1px rgba(255, 255, 255, 0.2);
        }

        .auth-brand-icon i {
            font-size: clamp(1.8rem, 3vw, 2.2rem);
        }

        .auth-brand h1 {
            font-size: clamp(1.75rem, 3vw, 2.25rem);
            font-weight: 800;
            letter-spacing: -0.04em;
        }

        .auth-brand p {
            color: rgba(255, 255, 255, 0.75);
            font-weight: 500;
        }

        .auth-headline {
            font-size: clamp(2rem, 3.6vw, 2.75rem);
            line-height: 1.1;
            font-weight: 800;
            letter-spacing: -0.045em;
        }

        .auth-subheadline {
            font-size: clamp(1rem, 2vw, 1.125rem);
            color: rgba(255, 255, 255, 0.8);
            max-width: 32rem;
            line-height: 1.65;
        }

        .auth-benefits {
            list-style: none;
            display: grid;
            gap: 0.9rem;
            padding: 0;
            margin: 0;
        }

        .auth-benefits li {
            display: flex;
            align-items: center;
            gap: 0.75rem;
            font-size: 0.975rem;
            color: rgba(255, 255, 255, 0.88);
            font-weight: 500;
        }

        .auth-benefits i {
            width: 28px;
            height: 28px;
            border-radius: 999px;
            display: grid;
            place-items: center;
            background: rgba(255, 255, 255, 0.15);
        }

        .auth-card-form {
            position: relative;
            background: transparent;
            padding: clamp(2.5rem, 5vw, 4rem);
            display: flex;
            flex-direction: column;
            justify-content: center;
            gap: clamp(1.75rem, 3vw, 2.5rem);
        }

        .auth-form-header {
            display: flex;
            flex-direction: column;
            gap: 0.5rem;
        }

        .auth-form-header h2 {
            font-size: clamp(1.75rem, 2.8vw, 2.1rem);
            color: var(--text-primary);
            font-weight: 700;
            letter-spacing: -0.035em;
        }

        .auth-form-header p {
            color: var(--text-secondary);
            font-size: 0.975rem;
        }

        .auth-form {
            display: flex !important;
            flex-direction: column;
            gap: 1.4rem;
            visibility: visible !important;
            opacity: 1 !important;
        }
        
        .auth-form * {
            visibility: visible !important;
        }
        
        .auth-form input[type="text"],
        .auth-form input[type="password"] {
            display: block !important;
            visibility: visible !important;
            opacity: 1 !important;
            width: 100% !important;
            height: auto !important;
            min-height: 48px !important;
        }

        .input-wrapper input {
            padding-left: 48px;
        }

        .auth-actions {
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 1rem;
            flex-wrap: wrap;
        }

        @media (max-width: 899px) {
            body {
                padding: clamp(1.5rem, 6vw, 3rem);
            }

            .auth-card {
                transform: translateX(0);
            }

            .auth-card-media {
                min-height: 280px;
            }
        }
    </style>
</head>
<body>
    <div class="auth-page fade-in-up">
        <div class="auth-blur"></div>
        <div class="auth-card">
            <div class="auth-card-media">
                <div class="auth-media-content">
                    <div class="auth-brand">
                        <div class="auth-brand-icon">
                            <i class="fas fa-shield-alt"></i>
                        </div>
                        <div>
                            <h1>UniFour</h1>
                            <p>SuperAdmin Paneli</p>
                        </div>
                    </div>
                    <div>
                        <h2 class="auth-headline">Güvenli sistem yönetimi</h2>
                        <p class="auth-subheadline">Tüm toplulukları yönetin, sistem ayarlarını kontrol edin ve platform genelinde raporlara erişin. SuperAdmin paneli ile tam kontrol sizde.</p>
                    </div>
                    <ul class="auth-benefits">
                        <li><i class="fas fa-check"></i> Tüm toplulukları tek panelden yönetin</li>
                        <li><i class="fas fa-check"></i> Sistem genelinde raporlama ve analitik</li>
                        <li><i class="fas fa-check"></i> Güvenli ve merkezi yönetim</li>
                    </ul>
                </div>
            </div>
            <div class="auth-card-form">
                <div class="auth-form-header">
                    <h2>Hoş Geldiniz</h2>
                    <p>SuperAdmin hesabınıza giriş yapın ve sistem yönetim paneline erişin.</p>
                </div>

                <?php if ($error): ?>
                    <div class="mb-2 p-4 bg-red-50 border border-red-200 text-red-700 rounded-2xl text-sm flex items-start gap-3" style="animation: fadeInUp 0.4s ease-out;">
                        <i class="fas fa-exclamation-circle mt-0.5 flex-shrink-0"></i>
                        <span class="font-medium"><?= htmlspecialchars($error, ENT_QUOTES, 'UTF-8') ?></span>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="mb-2 p-4 bg-green-50 border border-green-200 text-green-700 rounded-2xl text-sm flex items-start gap-3" style="animation: fadeInUp 0.4s ease-out;">
                        <i class="fas fa-check-circle mt-0.5 flex-shrink-0"></i>
                        <span class="font-medium"><?= htmlspecialchars($success, ENT_QUOTES, 'UTF-8') ?></span>
                </div>
            <?php endif; ?>

                <?php if ($step === 'login'): ?>
                    <form method="POST" class="auth-form" id="loginForm" style="display: flex !important; flex-direction: column !important; gap: 1.4rem !important; visibility: visible !important; opacity: 1 !important;">
                        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                        <input type="hidden" name="login" value="1">
                        
                        <div style="display: block !important; visibility: visible !important; opacity: 1 !important; margin-bottom: 1.4rem !important; width: 100% !important;">
                            <label class="block text-sm font-semibold mb-2" style="color: #0f172a !important; letter-spacing: -0.01em; display: block !important; visibility: visible !important; opacity: 1 !important;">Kullanıcı Adı</label>
                            <div class="input-wrapper" style="display: block !important; visibility: visible !important; opacity: 1 !important; position: relative !important; width: 100% !important;">
                                <i class="fas fa-user input-icon" style="position: absolute !important; left: 16px !important; top: 50% !important; transform: translateY(-50%) !important; z-index: 1 !important; color: #94a3b8 !important; pointer-events: none !important;"></i>
                                <input type="text" 
                                       name="username" 
                                       required 
                                       class="form-input"
                                       style="display: block !important; visibility: visible !important; opacity: 1 !important; width: 100% !important; min-height: 48px !important; padding: 14px 16px 14px 48px !important; border: 2px solid #e2e8f0 !important; border-radius: 16px !important; outline: none !important; font-weight: 500 !important; color: #0f172a !important; background: #ffffff !important; box-sizing: border-box !important;"
                                       placeholder="Kullanıcı adınızı girin"
                                       value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                                       autocomplete="username">
                            </div>
                </div>

                        <div style="display: block !important; visibility: visible !important; opacity: 1 !important; margin-bottom: 1.4rem !important; width: 100% !important;">
                            <label class="block text-sm font-semibold mb-2" style="color: #0f172a !important; letter-spacing: -0.01em; display: block !important; visibility: visible !important; opacity: 1 !important;">Şifre</label>
                            <div class="input-wrapper" style="display: block !important; visibility: visible !important; opacity: 1 !important; position: relative !important; width: 100% !important;">
                                <i class="fas fa-lock input-icon" style="position: absolute !important; left: 16px !important; top: 50% !important; transform: translateY(-50%) !important; z-index: 1 !important; color: #94a3b8 !important; pointer-events: none !important;"></i>
                                <input type="password" 
                                       name="password" 
                                       required 
                                       class="form-input"
                                       style="display: block !important; visibility: visible !important; opacity: 1 !important; width: 100% !important; min-height: 48px !important; padding: 14px 16px 14px 48px !important; border: 2px solid #e2e8f0 !important; border-radius: 16px !important; outline: none !important; font-weight: 500 !important; color: #0f172a !important; background: #ffffff !important; box-sizing: border-box !important;"
                                       placeholder="••••••••"
                                       autocomplete="current-password">
                            </div>
                </div>

                        <button type="submit" class="btn-primary w-full py-3.5 text-white rounded-xl font-semibold text-base" style="letter-spacing: -0.01em; display: block !important; width: 100% !important; min-height: 48px !important;">
                    Giriş Yap
                </button>
            </form>
                <?php else: ?>
                    <form method="POST" class="auth-form" id="verifyCodeForm" style="display: block !important;">
                        <input type="hidden" name="csrf_token" value="<?php echo generate_csrf_token(); ?>">
                        <input type="hidden" name="verify_code" value="1">
                        <div style="display: block !important; margin-bottom: 1.4rem;">
                            <label class="block text-sm font-semibold mb-2" style="color: var(--text-primary); letter-spacing: -0.01em; display: block !important;">Doğrulama Kodu</label>
                            <div class="input-wrapper" style="display: block !important; visibility: visible !important; position: relative; width: 100%;">
                                <i class="fas fa-key input-icon" style="position: absolute; left: 16px; top: 50%; transform: translateY(-50%); z-index: 1; color: var(--text-light);"></i>
                                <input type="text" 
                                       name="code" 
                                       required 
                                       maxlength="6" 
                                       pattern="[0-9]{6}"
                                       class="form-input w-full px-4 py-3.5 pl-12 border-2 rounded-2xl outline-none font-medium text-center text-2xl tracking-widest"
                                       style="display: block !important; visibility: visible !important; opacity: 1 !important; width: 100% !important; border-color: var(--border-color); color: var(--text-primary);"
                                       placeholder="000000"
                                       autocomplete="off">
                            </div>
                            <p class="text-sm text-gray-500 mt-2">
                                Telefonunuza gönderilen 6 haneli kodu giriniz
                                <?php if (isset($_SESSION['superadmin_verification_expires'])): ?>
                                    <span id="codeExpiry" class="block mt-1 text-xs"></span>
                                <?php endif; ?>
                            </p>
                        </div>

                        <button type="submit" class="btn-primary w-full py-3.5 text-white rounded-xl font-semibold text-base" style="letter-spacing: -0.01em; display: block !important;" id="verifyBtn">
                            Doğrula ve Giriş Yap
                        </button>
                        
                        <div class="flex items-center justify-between mt-2" style="display: flex !important;">
                            <a href="login.php" class="text-gray-600 hover:text-indigo-600 text-sm font-medium">
                                <i class="fas fa-arrow-left"></i> Geri Dön
                            </a>
                            <?php if (superadmin_sms_cooldown_remaining() > 0): ?>
                                <span id="resendCooldown" class="text-xs text-gray-400"><?= superadmin_sms_cooldown_remaining() ?> saniye sonra tekrar gönderebilirsiniz</span>
                            <?php else: ?>
                                <button type="button" onclick="resendCode()" id="resendBtn" class="text-gray-600 hover:text-indigo-600 text-sm font-medium">
                                    <i class="fas fa-redo"></i> Kodu Tekrar Gönder
                                </button>
                            <?php endif; ?>
                    </div>
                    </form>
                <?php endif; ?>
                
                <div class="text-center mt-4">
                    <p class="text-gray-500 text-xs">© 2025 UniFour - Tüm hakları saklıdır</p>
                </div>
            </div>
        </div>
    </div>

    <script>
        // Kod tekrar gönderme fonksiyonu
        function resendCode() {
            const btn = document.getElementById('resendBtn');
            const cooldownEl = document.getElementById('resendCooldown');
            
            if (btn && btn.disabled) return;
            
            if (btn) {
                btn.disabled = true;
                btn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Gönderiliyor...';
            }
            
            // Sayfayı yenile (yeni kod için)
            setTimeout(() => {
                window.location.reload();
            }, 1000);
        }
        
        // Kod süresi dolduğunda otomatik kontrol
        <?php if (isset($_SESSION['superadmin_verification_expires'])): ?>
        (function() {
            const expiryTime = <?= $_SESSION['superadmin_verification_expires'] ?>;
            const expiryEl = document.getElementById('codeExpiry');
            
            function updateExpiry() {
                const now = Math.floor(Date.now() / 1000);
                const remaining = expiryTime - now;
                
                if (remaining <= 0) {
                    if (expiryEl) {
                        expiryEl.innerHTML = '<span class="text-red-600 font-semibold">Kod süresi doldu! Yeni kod isteyin.</span>';
                    }
                } else {
                    const minutes = Math.floor(remaining / 60);
                    const seconds = remaining % 60;
                    if (expiryEl) {
                        expiryEl.innerHTML = `<span class="text-gray-600">Kalan süre: ${minutes}:${String(seconds).padStart(2, '0')}</span>`;
                    }
                }
            }
            
            updateExpiry();
            setInterval(updateExpiry, 1000);
        })();
        <?php endif; ?>
        
        // Cooldown gösterimi
        <?php 
        $cooldown = superadmin_sms_cooldown_remaining();
        if ($cooldown > 0): 
        ?>
        (function() {
            let cooldown = <?= $cooldown ?>;
            const btn = document.getElementById('resendBtn');
            const cooldownEl = document.getElementById('resendCooldown');
            
            if (btn) btn.disabled = true;
            
            const interval = setInterval(() => {
                if (cooldown > 0) {
                    if (cooldownEl) cooldownEl.textContent = `${cooldown} saniye sonra tekrar gönderebilirsiniz`;
                    cooldown--;
                } else {
                    clearInterval(interval);
                    if (cooldownEl) cooldownEl.textContent = '';
                    if (btn) {
                        btn.disabled = false;
                    }
                }
            }, 1000);
        })();
        <?php endif; ?>
        
        // Form animasyonu
        document.addEventListener('DOMContentLoaded', function() {
            const form = document.querySelector('form');
            const inputs = document.querySelectorAll('input[type="text"], input[type="password"]');
            
            inputs.forEach(input => {
                input.addEventListener('focus', function() {
                    this.parentElement.classList.add('scale-105');
                });
                
                input.addEventListener('blur', function() {
                    this.parentElement.classList.remove('scale-105');
                });
            });
            
            // Doğrulama kodu input'u için otomatik odaklanma
            const verificationInput = document.querySelector('input[name="code"]');
            if (verificationInput) {
                verificationInput.focus();
                verificationInput.addEventListener('input', function() {
                    if (this.value.length === 6) {
                        this.form.submit();
                    }
                });
            }
            
            if (form) {
                form.addEventListener('submit', function() {
                    const button = this.querySelector('button[type="submit"]');
                    if (button) {
                        button.innerHTML = `
                            <div class="flex items-center justify-center">
                                <div class="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                                ${button.textContent.includes('Doğrula') ? 'Doğrulanıyor...' : 'Giriş yapılıyor...'}
                            </div>
                        `;
                        button.disabled = true;
                    }
                });
            }
        });
    </script>
</body>
</html>