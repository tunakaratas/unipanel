<?php
// =================================================================
// SUPERADMIN PANELİ - Tam Özellikli Topluluk Yönetim Sistemi
// =================================================================

$superadminConfig = require __DIR__ . '/config.php';

// SQLite3 sabitlerini tanımla (eğer tanımlı değilse)
if (!defined('SQLITE3_INTEGER')) define('SQLITE3_INTEGER', 1);
if (!defined('SQLITE3_TEXT')) define('SQLITE3_TEXT', 3);
if (!defined('SQLITE3_REAL')) define('SQLITE3_REAL', 2);
if (!defined('SQLITE3_BLOB')) define('SQLITE3_BLOB', 4);
if (!defined('SQLITE3_NULL')) define('SQLITE3_NULL', 5);

// SQLite3 bağlantısı oluştur (retry ile)
function getSQLite3Connection($dbPath, $retries = 3) {
    // Veritabanı dosyası izinlerini kontrol et ve düzelt
    if (file_exists($dbPath)) {
        if (!is_writable($dbPath)) {
            @chmod($dbPath, SUPERADMIN_FILE_PERMS);
        }
        // Klasörün de yazılabilir olduğundan emin ol
        $db_dir = dirname($dbPath);
        if (!is_writable($db_dir)) {
            @chmod($db_dir, SUPERADMIN_DIR_PERMS);
        }
    } else {
        // Dosya yoksa klasörün yazılabilir olduğundan emin ol
        $db_dir = dirname($dbPath);
        if (!is_dir($db_dir)) {
            @mkdir($db_dir, SUPERADMIN_DIR_PERMS, true);
        }
        if (!is_writable($db_dir)) {
            @chmod($db_dir, SUPERADMIN_DIR_PERMS);
        }
    }
    
    for ($i = 0; $i < $retries; $i++) {
        try {
            $db = new SQLite3($dbPath);
            $db->busyTimeout(10000); // 10 saniye timeout
            
            // Veritabanı yazılabilir mi kontrol et
            $is_writable = is_writable($dbPath);
            if (!$is_writable) {
                // İzinleri tekrar düzelt
                @chmod($dbPath, SUPERADMIN_FILE_PERMS);
                @chmod(dirname($dbPath), SUPERADMIN_DIR_PERMS);
            }
            
            // PRAGMA komutlarını çalıştır (sadece yazılabilirse)
            try {
                if ($is_writable || is_writable($dbPath)) {
                    @$db->exec('PRAGMA journal_mode = WAL');
                    @$db->exec('PRAGMA synchronous = NORMAL');
                } else {
                    // Readonly modda çalış
                    @$db->exec('PRAGMA query_only = 1');
                }
            } catch (\Exception $e) {
                // PRAGMA hatası kritik değil, devam et
                error_log("PRAGMA error (non-critical): " . $e->getMessage());
            }
            
            return $db;
        } catch (Exception $e) {
            // İzin sorunu varsa düzelt ve tekrar dene
            if (strpos($e->getMessage(), 'readonly') !== false || strpos($e->getMessage(), 'permission') !== false) {
                @chmod($dbPath, SUPERADMIN_FILE_PERMS);
                @chmod(dirname($dbPath), SUPERADMIN_DIR_PERMS);
            }
            
            if ($i < $retries - 1) {
                usleep(100000 * ($i + 1)); // 100ms, 200ms, 300ms...
                continue;
            }
            throw $e;
        }
    }
    return null;
}

// SQLite3 execute işlemi (retry ile)
function executeSQLite3Stmt($stmt, $retries = 3) {
    for ($i = 0; $i < $retries; $i++) {
        try {
            $result = $stmt->execute();
            if ($result !== false) {
                return $result;
            }
            if ($i < $retries - 1) {
                usleep(50000 * ($i + 1)); // 50ms, 100ms, 150ms...
            }
        } catch (Exception $e) {
            if (strpos($e->getMessage(), 'database is locked') !== false && $i < $retries - 1) {
                usleep(100000 * ($i + 1)); // Lock hatası için daha uzun bekle
                continue;
            }
            throw $e;
        }
    }
    return false;
}

if (!defined('SUPERADMIN_SESSION_LIFETIME')) {
    define('SUPERADMIN_SESSION_LIFETIME', (int)($superadminConfig['security']['session_lifetime'] ?? 1800));
}
if (!defined('SUPERADMIN_IDLE_TIMEOUT')) {
    define('SUPERADMIN_IDLE_TIMEOUT', (int) min(SUPERADMIN_SESSION_LIFETIME, $superadminConfig['security']['idle_timeout'] ?? SUPERADMIN_SESSION_LIFETIME));
}
const SUPERADMIN_FILE_PERMS = 0644; // Web sunucusu okuyabilmeli
const SUPERADMIN_DIR_PERMS = 0755; // Web sunucusu okuyabilmeli (755)
const SUPERADMIN_PUBLIC_DIR_PERMS = 0755;
$SUPERADMIN_ALLOWED_IPS = $superadminConfig['security']['allowed_ips'] ?? ['127.0.0.1', '::1'];

// Session kontrolü - sadece web ortamında
if (php_sapi_name() !== 'cli' && session_status() === PHP_SESSION_NONE) {
    session_start();
}

function superadmin_env_flag_enabled(string $key): bool
{
    $value = getenv($key);
    if ($value === false) {
        return false;
    }
    $normalized = strtolower(trim($value));
    return in_array($normalized, ['1', 'true', 'on', 'yes'], true);
}

function superadmin_expected_token(): ?string
{
    static $tokenLoaded = false;
    static $token = null;

    if ($tokenLoaded) {
        return $token;
    }

    $value = getenv('SUPERADMIN_LOGIN_TOKEN');
    if (is_string($value)) {
        $value = trim($value);
    }
    $token = $value !== '' ? $value : null;
    $tokenLoaded = true;
    return $token;
}

function superadmin_should_show_detailed_errors(): bool
{
    $env = strtolower(trim(getenv('APP_ENV') ?: ''));
    return in_array($env, ['local', 'development', 'dev'], true);
}

function superadmin_log_error_message(string $message): void
{
    error_log('[SuperAdmin] ' . $message);
}

function superadmin_refresh_session_cookie(): void {
    if (PHP_SAPI === 'cli' || session_status() !== PHP_SESSION_ACTIVE) {
        return;
    }
    $params = session_get_cookie_params();
    $options = [
        'expires' => time() + SUPERADMIN_SESSION_LIFETIME,
        'path' => $params['path'] ?? '/',
        'domain' => $params['domain'] ?? '',
        'secure' => $params['secure'] ?? (!empty($_SERVER['HTTPS']) && ($_SERVER['HTTPS'] === 'on')),
        'httponly' => true,
        'samesite' => $params['samesite'] ?? 'Strict'
    ];
    setcookie(session_name(), session_id(), $options);
}
// Security Helper'ı dahil et
require_once __DIR__ . '/security_helper.php';

function superadmin_force_logout(string $reasonQuery = ''): void
{
    if (session_status() === PHP_SESSION_ACTIVE) {
        $_SESSION = [];
        session_destroy();
    }
    $location = 'login.php';
    if ($reasonQuery !== '') {
        $location .= (strpos($reasonQuery, '?') === 0 ? $reasonQuery : ('?' . $reasonQuery));
    }
    header("Location: {$location}");
    exit;
}

function superadmin_session_guard(): void
{
    if (session_status() !== PHP_SESSION_ACTIVE || empty($_SESSION['superadmin_logged_in'])) {
        return;
    }

    $now = time();
    $last = $_SESSION['superadmin_last_activity'] ?? $now;
    if (($now - $last) > SUPERADMIN_IDLE_TIMEOUT) {
        superadmin_force_logout('timeout=1');
    }

    $currentIp = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!empty($_SESSION['superadmin_ip']) && $currentIp !== $_SESSION['superadmin_ip']) {
        superadmin_force_logout('rebind=1');
    }

    $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? '';
    if (!empty($_SESSION['superadmin_ua']) && $currentUa !== $_SESSION['superadmin_ua']) {
        superadmin_force_logout('rebind=1');
    }

    $_SESSION['superadmin_last_activity'] = $now;
}

// Hata raporlama
error_reporting(E_ALL);
ini_set('display_errors', 0); // Production'da 0 olmalı
ini_set('log_errors', 1);
ini_set('error_log', __DIR__ . '/../system/logs/superadmin_error.log');

require_once __DIR__ . '/../bootstrap/community_stubs.php';

use function UniPanel\Community\sync_community_stubs;

// Hata yakalama için exception handler
$SUPERADMIN_SHOW_ERRORS = superadmin_should_show_detailed_errors();

set_error_handler(function($errno, $errstr, $errfile, $errline) use ($SUPERADMIN_SHOW_ERRORS) {
    if (!(error_reporting() & $errno)) {
        return false;
    }
    
    $error_types = [
        E_ERROR => 'FATAL ERROR',
        E_WARNING => 'WARNING',
        E_PARSE => 'PARSE ERROR',
        E_NOTICE => 'NOTICE',
        E_CORE_ERROR => 'CORE ERROR',
        E_CORE_WARNING => 'CORE WARNING',
        E_COMPILE_ERROR => 'COMPILE ERROR',
        E_COMPILE_WARNING => 'COMPILE WARNING',
        E_USER_ERROR => 'USER ERROR',
        E_USER_WARNING => 'USER WARNING',
        E_USER_NOTICE => 'USER NOTICE',
        E_STRICT => 'STRICT',
        E_RECOVERABLE_ERROR => 'RECOVERABLE ERROR',
        E_DEPRECATED => 'DEPRECATED',
        E_USER_DEPRECATED => 'USER DEPRECATED'
    ];
    $error_type = $error_types[$errno] ?? 'UNKNOWN ERROR';
    $message = sprintf('[%s] %s in %s:%d', $error_type, $errstr, $errfile, $errline);
    superadmin_log_error_message($message);

    if ($SUPERADMIN_SHOW_ERRORS) {
        echo "<div style='background: #fee; border: 2px solid #f00; padding: 15px; margin: 10px; border-radius: 5px; font-family: monospace;'>";
        echo "<strong style='color: #c00;'>[$error_type]</strong><br>";
        echo "<strong>Dosya:</strong> " . htmlspecialchars($errfile) . "<br>";
        echo "<strong>Satır:</strong> $errline<br>";
        echo "<strong>Mesaj:</strong> " . htmlspecialchars($errstr) . "<br>";
        echo "</div>";
    } else {
        http_response_code(500);
        echo 'Beklenmeyen bir hata oluştu.';
    }

    return true;
});

// Exception handler
set_exception_handler(function($exception) use ($SUPERADMIN_SHOW_ERRORS) {
    $message = sprintf(
        '[UNCAUGHT EXCEPTION] %s in %s:%d' . PHP_EOL . '%s',
        $exception->getMessage(),
        $exception->getFile(),
        $exception->getLine(),
        $exception->getTraceAsString()
    );
    superadmin_log_error_message($message);

    if ($SUPERADMIN_SHOW_ERRORS) {
        echo "<div style='background: #fee; border: 2px solid #f00; padding: 15px; margin: 10px; border-radius: 5px; font-family: monospace;'>";
        echo "<strong style='color: #c00;'>[UNCAUGHT EXCEPTION]</strong><br>";
        echo "<strong>Mesaj:</strong> " . htmlspecialchars($exception->getMessage()) . "<br>";
        echo "<strong>Dosya:</strong> " . htmlspecialchars($exception->getFile()) . "<br>";
        echo "<strong>Satır:</strong> " . $exception->getLine() . "<br>";
        echo "<strong>Stack Trace:</strong><pre>" . htmlspecialchars($exception->getTraceAsString()) . "</pre>";
        echo "</div>";
    } else {
        http_response_code(500);
        echo 'Beklenmeyen bir hata oluştu.';
    }
});

// Güvenlik filtreleri (login.php ile aynı)
function checkAccessPermission() {
    global $SUPERADMIN_ALLOWED_IPS;
    $allowed_ips = $SUPERADMIN_ALLOWED_IPS ?: ['127.0.0.1', '::1'];
    
    // İzin verilen User Agent'lar (bilgisayarınızın özellikleri)
    $allowed_user_agents = [
        // Bilgisayarınızın User Agent'ını buraya ekleyin
        // 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/XXX.0.0.0 Safari/537.36',
    ];
    
    // IP kontrolü
    $client_ip = $_SERVER['REMOTE_ADDR'] ?? '';
    $forwarded_ip = $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '';
    $real_ip = $_SERVER['HTTP_X_REAL_IP'] ?? '';
    
    $all_ips = array_filter([$client_ip, $forwarded_ip, $real_ip]);
    $ip_allowed = false;
    
    foreach ($all_ips as $ip) {
        if (in_array($ip, $allowed_ips)) {
            $ip_allowed = true;
            break;
        }
    }
    
    // User Agent kontrolü
    $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? '';
    $ua_allowed = empty($allowed_user_agents) || in_array($user_agent, $allowed_user_agents);
    
    return $ip_allowed && $ua_allowed;
}

// IP kontrolü kaldırıldı - sadece şifre ile giriş

// Windows hosting için disk alanı fonksiyonları
function getDiskFreeSpace() {
    try {
        // Önce mevcut dizini dene
        $current_dir = __DIR__;
        $free_space = disk_free_space($current_dir);
        if ($free_space !== false) {
            return $free_space; // Sayısal değer döndür
        }
        
        // Windows hosting'de alternatif yollar dene
        $paths = [
            __DIR__ . '/../',
            __DIR__ . '/../communities/',
            __DIR__ . '/../system/',
            '.'
        ];
        
        foreach ($paths as $path) {
            if (file_exists($path)) {
                $free_space = disk_free_space($path);
                if ($free_space !== false) {
                    return $free_space; // Sayısal değer döndür
                }
            }
        }
        
        return 0; // Sayısal değer döndür
    } catch (Exception $e) {
        return 0; // Sayısal değer döndür
    }
}

function getDiskTotalSpace() {
    try {
        // Önce mevcut dizini dene
        $current_dir = __DIR__;
        $total_space = disk_total_space($current_dir);
        if ($total_space !== false) {
            return $total_space; // Sayısal değer döndür
        }
        
        // Windows hosting'de alternatif yollar dene
        $paths = [
            __DIR__ . '/../',
            __DIR__ . '/../communities/',
            __DIR__ . '/../system/',
            '.'
        ];
        
        foreach ($paths as $path) {
            if (file_exists($path)) {
                $total_space = disk_total_space($path);
                if ($total_space !== false) {
                    return $total_space; // Sayısal değer döndür
                }
            }
        }
        
        return 0; // Sayısal değer döndür
    } catch (Exception $e) {
        return 0; // Sayısal değer döndür
    }
}

function formatBytes($bytes, $precision = 2) {
    $units = array('B', 'KB', 'MB', 'GB', 'TB');
    
    for ($i = 0; $bytes > 1024 && $i < count($units) - 1; $i++) {
        $bytes /= 1024;
    }
    
    return round($bytes, $precision) . ' ' . $units[$i];
}

function getDiskUsagePercentage($total_space, $free_space) {
    // Eğer değerler sayısal değilse veya "Bilinmiyor" ise
    if (!is_numeric($total_space) || !is_numeric($free_space) || 
        $total_space === 'Bilinmiyor' || $free_space === 'Bilinmiyor' ||
        $total_space <= 0) {
        return 'Bilinmiyor';
    }
    
    $used_space = $total_space - $free_space;
    if ($used_space < 0) {
        return 'Bilinmiyor';
    }
    
    $percentage = ($used_space / $total_space) * 100;
    return round($percentage, 1) . '%';
}

// --- YAPILANDIRMA ---
const COMMUNITIES_DIR = __DIR__ . '/../communities/';
const SUPERADMIN_DB = __DIR__ . '/../unipanel.sqlite';

// --- LOG SİSTEMİ FONKSİYONLARI ---
function initLogDatabase() {
    try {
        if (!file_exists(SUPERADMIN_DB)) {
            $dir = dirname(SUPERADMIN_DB);
            if (!is_dir($dir)) {
                @mkdir($dir, 0755, true);
            }
            @touch(SUPERADMIN_DB);
            @chmod(SUPERADMIN_DB, SUPERADMIN_FILE_PERMS);
        }
        
        $db = new SQLite3(SUPERADMIN_DB);
        if (!$db) {
            error_log('[SuperAdmin] Veritabanı bağlantısı kurulamadı: ' . SUPERADMIN_DB);
            return;
        }
        $db->busyTimeout(30000); // 30 saniye timeout
        
        // PRAGMA komutlarını try-catch ile koru
        try {
            if (is_writable(SUPERADMIN_DB)) {
                @$db->exec('PRAGMA journal_mode = WAL');
                @$db->exec('PRAGMA synchronous = NORMAL'); // Performans için
            } else {
                @$db->exec('PRAGMA query_only = 1');
            }
        } catch (\Exception $e) {
            // PRAGMA hatası kritik değil, devam et
            error_log("PRAGMA error (non-critical): " . $e->getMessage());
        }
    
        // Activity Logs Tablosu (Admin işlemleri ve kullanıcı aktiviteleri)
        // Sadece yazılabilirse tablo oluştur
        if (is_writable(SUPERADMIN_DB)) {
            try {
                @$db->exec("CREATE TABLE IF NOT EXISTS activity_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            community_name TEXT,
            user_type TEXT NOT NULL,
            user_id INTEGER,
            username TEXT,
            action_type TEXT NOT NULL,
            action_description TEXT NOT NULL,
            ip_address TEXT,
            user_agent TEXT,
            additional_data TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // System Logs Tablosu (Sistem olayları)
                @$db->exec("CREATE TABLE IF NOT EXISTS system_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_level TEXT NOT NULL,
            log_category TEXT,
            message TEXT NOT NULL,
            context TEXT,
            community_name TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Error Logs Tablosu (Hata logları)
                @$db->exec("CREATE TABLE IF NOT EXISTS error_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            error_type TEXT NOT NULL,
            error_message TEXT NOT NULL,
            error_file TEXT,
            error_line INTEGER,
            error_trace TEXT,
            community_name TEXT,
            user_id INTEGER,
            request_url TEXT,
            ip_address TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // İndeksler
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_activity_community ON activity_logs(community_name)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_activity_user ON activity_logs(user_id, user_type)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_logs(created_at)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_system_level ON system_logs(log_level)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_system_created ON system_logs(created_at)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_error_type ON error_logs(error_type)");
                @$db->exec("CREATE INDEX IF NOT EXISTS idx_error_created ON error_logs(created_at)");
            } catch (\Exception $e) {
                // Tablo oluşturma hatası kritik değil, devam et
                error_log("SuperAdmin table creation error (non-critical): " . $e->getMessage());
            }
        }
        
        // Reklamlar Tablosu
        $db->exec("CREATE TABLE IF NOT EXISTS ads (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            image_url TEXT,
            logo_url TEXT,
            call_to_action TEXT DEFAULT 'Keşfet',
            advertiser TEXT NOT NULL,
            rating REAL,
            click_url TEXT,
            status TEXT DEFAULT 'active',
            priority INTEGER DEFAULT 0,
            start_date DATETIME,
            end_date DATETIME,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        $db->exec("CREATE INDEX IF NOT EXISTS idx_ads_status ON ads(status)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_ads_priority ON ads(priority DESC)");
        $db->exec("CREATE INDEX IF NOT EXISTS idx_ads_dates ON ads(start_date, end_date)");
        
        $db->close();
    } catch (Exception $e) {
        error_log('[SuperAdmin] initLogDatabase hatası: ' . $e->getMessage());
        // Hata durumunda sessizce devam et
    }
}

// Log kaydetme fonksiyonları
function logAdminAction($community_name, $user_id, $username, $action_type, $action_description, $additional_data = null) {
    try {
        initLogDatabase();
        $db = new SQLite3(SUPERADMIN_DB);
        $db->busyTimeout(5000); // 5 saniye timeout
        $db->exec('PRAGMA journal_mode = WAL');
        
        $stmt = $db->prepare("INSERT INTO activity_logs (community_name, user_type, user_id, username, action_type, action_description, ip_address, user_agent, additional_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $community_name, SQLITE3_TEXT);
        $stmt->bindValue(2, 'admin', SQLITE3_TEXT);
        $stmt->bindValue(3, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(4, $username, SQLITE3_TEXT);
        $stmt->bindValue(5, $action_type, SQLITE3_TEXT);
        $stmt->bindValue(6, $action_description, SQLITE3_TEXT);
        $stmt->bindValue(7, $_SERVER['REMOTE_ADDR'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(8, $_SERVER['HTTP_USER_AGENT'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(9, $additional_data ? json_encode($additional_data) : null, SQLITE3_TEXT);
        $stmt->execute();
        
        $db->close();
    } catch (Exception $e) {
        error_log("Log kaydetme hatası: " . $e->getMessage());
    }
}

function logUserActivity($community_name, $user_id, $username, $action_type, $action_description, $additional_data = null) {
    try {
        initLogDatabase();
        $db = new SQLite3(SUPERADMIN_DB);
        $db->exec('PRAGMA journal_mode = WAL');
        
        $stmt = $db->prepare("INSERT INTO activity_logs (community_name, user_type, user_id, username, action_type, action_description, ip_address, user_agent, additional_data) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $community_name, SQLITE3_TEXT);
        $stmt->bindValue(2, 'user', SQLITE3_TEXT);
        $stmt->bindValue(3, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(4, $username, SQLITE3_TEXT);
        $stmt->bindValue(5, $action_type, SQLITE3_TEXT);
        $stmt->bindValue(6, $action_description, SQLITE3_TEXT);
        $stmt->bindValue(7, $_SERVER['REMOTE_ADDR'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(8, $_SERVER['HTTP_USER_AGENT'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(9, $additional_data ? json_encode($additional_data) : null, SQLITE3_TEXT);
        $stmt->execute();
        
        $db->close();
    } catch (Exception $e) {
        error_log("Log kaydetme hatası: " . $e->getMessage());
    }
}

function logSystemEvent($log_level, $log_category, $message, $context = null, $community_name = null) {
    try {
        initLogDatabase();
        $db = new SQLite3(SUPERADMIN_DB);
        $db->exec('PRAGMA journal_mode = WAL');
        
        $stmt = $db->prepare("INSERT INTO system_logs (log_level, log_category, message, context, community_name) VALUES (?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $log_level, SQLITE3_TEXT);
        $stmt->bindValue(2, $log_category, SQLITE3_TEXT);
        $stmt->bindValue(3, $message, SQLITE3_TEXT);
        $stmt->bindValue(4, $context ? json_encode($context) : null, SQLITE3_TEXT);
        $stmt->bindValue(5, $community_name, SQLITE3_TEXT);
        $stmt->execute();
        
        $db->close();
    } catch (Exception $e) {
        error_log("System log kaydetme hatası: " . $e->getMessage());
    }
}

function logError($error_type, $error_message, $error_file = null, $error_line = null, $error_trace = null, $community_name = null, $user_id = null) {
    try {
        initLogDatabase();
        $db = new SQLite3(SUPERADMIN_DB);
        $db->busyTimeout(5000); // 5 saniye timeout
        $db->exec('PRAGMA journal_mode = WAL');
        
        $stmt = $db->prepare("INSERT INTO error_logs (error_type, error_message, error_file, error_line, error_trace, community_name, user_id, request_url, ip_address) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $error_type, SQLITE3_TEXT);
        $stmt->bindValue(2, $error_message, SQLITE3_TEXT);
        $stmt->bindValue(3, $error_file, SQLITE3_TEXT);
        $stmt->bindValue(4, $error_line, SQLITE3_INTEGER);
        $stmt->bindValue(5, $error_trace, SQLITE3_TEXT);
        $stmt->bindValue(6, $community_name, SQLITE3_TEXT);
        $stmt->bindValue(7, $user_id, SQLITE3_INTEGER);
        $stmt->bindValue(8, $_SERVER['REQUEST_URI'] ?? '', SQLITE3_TEXT);
        $stmt->bindValue(9, $_SERVER['REMOTE_ADDR'] ?? '', SQLITE3_TEXT);
        $stmt->execute();
        
        $db->close();
    } catch (Exception $e) {
        error_log("Error log kaydetme hatası: " . $e->getMessage());
    }
}

// Veritabanını başlat
initLogDatabase();

// --- GİRİŞ KONTROLÜ ---
if (!isset($_SESSION['superadmin_logged_in'])) {
    header("Location: login.php");
    exit;
}
superadmin_session_guard();
superadmin_refresh_session_cookie();

// --- TOPLULUK YÖNETİMİ ---
$action = $_GET['action'] ?? $_POST['action'] ?? 'list';
$error = $_GET['error'] ?? '';
$success = $_GET['success'] ?? '';

// Çıkış işlemi HTML çıktısından önce gerçekleştirilir
if ($action === 'logout') {
    session_destroy();
    header("Location: login.php");
    exit;
}

// Başkan oluşturma işlemi
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create_president') {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
    } else {
        $community_folder = trim($_POST['community_folder'] ?? '');
        $president_name = trim($_POST['president_name'] ?? '');
        $president_email = trim($_POST['president_email'] ?? '');
        $president_phone = trim($_POST['president_phone'] ?? '');
        $president_student_id = trim($_POST['president_student_id'] ?? '');
        $president_department = trim($_POST['president_department'] ?? '');
        
        if (empty($community_folder) || empty($president_name)) {
            $error = "Topluluk klasörü ve başkan adı zorunludur!";
        } else {
            $db_path = COMMUNITIES_DIR . $community_folder . '/unipanel.sqlite';
            if (!file_exists($db_path)) {
                $error = "Topluluk veritabanı bulunamadı!";
            } else {
                try {
                    $db = getSQLite3Connection($db_path);
                    if (!$db) {
                        throw new Exception("Veritabanı bağlantısı kurulamadı");
                    }
                    
                    // Settings tablosunu oluştur (eğer yoksa)
                    $db->exec("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, club_id INTEGER, setting_key TEXT, setting_value TEXT)");
                    
                    // Başkan bilgilerini kaydet
                    $settings = [
                        ['president_name', $president_name],
                        ['president_email', $president_email],
                        ['president_phone', $president_phone],
                        ['president_student_id', $president_student_id],
                        ['president_department', $president_department]
                    ];
                    
                    foreach ($settings as $setting) {
                        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, ?, ?)");
                        if ($stmt) {
                            $stmt->bindValue(1, $setting[0], SQLITE3_TEXT);
                            $stmt->bindValue(2, $setting[1], SQLITE3_TEXT);
                            try {
                                executeSQLite3Stmt($stmt);
                            } catch (Exception $e) {
                                error_log("Settings insert hatası: " . $e->getMessage());
                            }
                        }
                    }
                    
                    $db->close();
                    $success = "Başkan başarıyla oluşturuldu!";
                    
                    // Sayfayı yenile
                    header("Location: index.php?view=communities&success=" . urlencode($success));
                    exit;
                } catch (Exception $e) {
                    $error = "Başkan oluşturulurken hata oluştu: " . $e->getMessage();
                    error_log("Başkan oluşturma hatası: " . $e->getMessage());
                }
            }
        }
    }
}

// Bildirim gönderme işlemi
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'send_notification') {
    $notification_title = trim($_POST['notification_title'] ?? '');
    $notification_message = trim($_POST['notification_message'] ?? '');
    $notification_type = $_POST['notification_type'] ?? 'info';
    $target_communities = $_POST['target_communities'] ?? [];
    $is_urgent = isset($_POST['is_urgent']) ? 1 : 0; // Acil bildirim kontrolü
    
    if (empty($notification_title) || empty($notification_message)) {
        $error = "Bildirim başlığı ve mesajı gerekli!";
        } else {
        $sent_count = 0;
        $target_list = [];
        
        // Hedef toplulukları belirle
        if (in_array('all', $target_communities)) {
            $target_list = $communities;
        } else {
            $target_list = $target_communities;
        }
        
        // Her hedef topluluğa bildirim gönder
        foreach ($target_list as $community) {
            $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
            if (file_exists($db_path)) {
                try {
                    $db = new SQLite3($db_path);
                    
                    // Bildirim tablosunu oluştur (eğer yoksa) - Acil bildirim alanı ekle
                    $db->exec("CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        type TEXT DEFAULT 'info',
                        is_read INTEGER DEFAULT 0,
                        is_urgent INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        sender_type TEXT DEFAULT 'superadmin'
                    )");
                    
                    // Acil bildirim alanını ekle (eğer yoksa)
                    $db->exec("ALTER TABLE notifications ADD COLUMN is_urgent INTEGER DEFAULT 0");
                    
                    // Bildirimi ekle
                    $stmt = $db->prepare("INSERT INTO notifications (club_id, title, message, type, is_urgent, sender_type) VALUES (1, ?, ?, ?, ?, 'superadmin')");
                    $stmt->bindValue(1, $notification_title, SQLITE3_TEXT);
                    $stmt->bindValue(2, $notification_message, SQLITE3_TEXT);
                    $stmt->bindValue(3, $notification_type, SQLITE3_TEXT);
                    $stmt->bindValue(4, $is_urgent, SQLITE3_INTEGER);
                    $stmt->execute();
                    
                    $sent_count++;
                    $db->close();
                } catch (Exception $e) {
                    // Hata durumunda detaylı log
                    error_log("Bildirim gönderme hatası - Topluluk: $community, Hata: " . $e->getMessage());
                }
            } else {
                error_log("Veritabanı bulunamadı: $db_path");
            }
        }
        
        if ($sent_count > 0) {
            $success = "Bildirim {$sent_count} topluluğa başarıyla gönderildi!";
        } else {
            $error = "Bildirim gönderilemedi! Hedef topluluk sayısı: " . count($target_list) . ", Mevcut topluluklar: " . implode(', ', $communities) . ", Hedef listesi: " . implode(', ', $target_list);
        }
        
        // POST işlemi sonrası yönlendirme
        $redirect_url = "index.php?view=notifications";
        if (!empty($success)) {
            $redirect_url .= "&success=" . urlencode($success);
        }
        if (!empty($error)) {
            $redirect_url .= "&error=" . urlencode($error);
        }
        header("Location: $redirect_url");
    exit;
    }
}

// Üniversiteler ve bölümler listesi
// Not: Bu listeler admin-login.php ile aynı olmalı
$universities = [
    'Bandırma 17 Eylül Üniversitesi', 'İstanbul Üniversitesi', 'Ankara Üniversitesi', 'Hacettepe Üniversitesi', 'Boğaziçi Üniversitesi',
    'Orta Doğu Teknik Üniversitesi', 'İstanbul Teknik Üniversitesi', 'Gazi Üniversitesi', 'Ege Üniversitesi',
    'Dokuz Eylül Üniversitesi', 'Marmara Üniversitesi', 'Yıldız Teknik Üniversitesi', 'Anadolu Üniversitesi',
    'Selçuk Üniversitesi', 'Akdeniz Üniversitesi', 'Çukurova Üniversitesi', 'Erciyes Üniversitesi',
    'Uludağ Üniversitesi', 'Atatürk Üniversitesi', 'Ondokuz Mayıs Üniversitesi', 'Karadeniz Teknik Üniversitesi',
    'Pamukkale Üniversitesi', 'Süleyman Demirel Üniversitesi', 'Kocaeli Üniversitesi', 'Sakarya Üniversitesi',
    'Trakya Üniversitesi', 'Çanakkale Onsekiz Mart Üniversitesi', 'Balıkesir Üniversitesi', 'Adnan Menderes Üniversitesi',
    'Muğla Sıtkı Koçman Üniversitesi', 'Bursa Teknik Üniversitesi', 'İzmir Yüksek Teknoloji Enstitüsü', 'Gebze Teknik Üniversitesi',
    'Sabancı Üniversitesi', 'Koç Üniversitesi', 'Bilkent Üniversitesi', 'Özyeğin Üniversitesi',
    'Bahçeşehir Üniversitesi', 'İstanbul Bilgi Üniversitesi', 'İstanbul Kültür Üniversitesi', 'Yeditepe Üniversitesi',
    'Maltepe Üniversitesi', 'Kadir Has Üniversitesi', 'İstanbul Aydın Üniversitesi', 'Altınbaş Üniversitesi',
    'İstanbul Medipol Üniversitesi', 'Acıbadem Üniversitesi', 'Bezmialem Vakıf Üniversitesi', 'Diğer'
];

$departments = [
    'Bilgisayar Mühendisliği', 'Yazılım Mühendisliği', 'Elektrik-Elektronik Mühendisliği', 'Endüstri Mühendisliği',
    'Makine Mühendisliği', 'İnşaat Mühendisliği', 'Kimya Mühendisliği', 'Gıda Mühendisliği',
    'Biyomedikal Mühendisliği', 'Mekatronik Mühendisliği', 'Otomotiv Mühendisliği', 'Enerji Sistemleri Mühendisliği',
    'Çevre Mühendisliği', 'Harita Mühendisliği', 'Jeoloji Mühendisliği', 'Maden Mühendisliği',
    'Petrol ve Doğalgaz Mühendisliği', 'Metalurji ve Malzeme Mühendisliği', 'Tekstil Mühendisliği', 'Uçak Mühendisliği',
    'Uzay Mühendisliği', 'Gemi İnşaatı ve Gemi Makineleri Mühendisliği', 'Denizcilik İşletmeleri Yönetimi', 'İşletme',
    'İktisat', 'Siyaset Bilimi ve Kamu Yönetimi', 'Uluslararası İlişkiler', 'Hukuk',
    'Tıp', 'Diş Hekimliği', 'Eczacılık', 'Veteriner Hekimliği',
    'Hemşirelik', 'Sağlık Yönetimi', 'Beslenme ve Diyetetik', 'Fizyoterapi ve Rehabilitasyon',
    'Ebelik', 'Odyoloji', 'Dil ve Konuşma Terapisi', 'Ergoterapi',
    'Çocuk Gelişimi', 'Sosyal Hizmet', 'Psikoloji', 'Sosyoloji',
    'Felsefe', 'Tarih', 'Coğrafya', 'Türk Dili ve Edebiyatı',
    'İngiliz Dili ve Edebiyatı', 'Alman Dili ve Edebiyatı', 'Fransız Dili ve Edebiyatı', 'Mütercim-Tercümanlık',
    'Güzel Sanatlar', 'Resim', 'Heykel', 'Müzik',
    'Tiyatro', 'Sinema ve Televizyon', 'Radyo, Televizyon ve Sinema', 'Grafik Tasarım',
    'Endüstriyel Tasarım', 'İç Mimarlık', 'Mimarlık', 'Şehir ve Bölge Planlama',
    'Peyzaj Mimarlığı', 'Eğitim Bilimleri', 'Sınıf Öğretmenliği', 'Okul Öncesi Öğretmenliği',
    'Rehberlik ve Psikolojik Danışmanlık', 'Türkçe Öğretmenliği', 'Matematik Öğretmenliği', 'Fen Bilgisi Öğretmenliği',
    'Sosyal Bilgiler Öğretmenliği', 'İngilizce Öğretmenliği', 'Almanca Öğretmenliği', 'Fransızca Öğretmenliği',
    'Beden Eğitimi ve Spor Öğretmenliği', 'Müzik Öğretmenliği', 'Resim-İş Öğretmenliği', 'Bilgisayar ve Öğretim Teknolojileri Öğretmenliği',
    'Gazetecilik', 'Halkla İlişkiler ve Tanıtım', 'Reklamcılık', 'Medya ve İletişim',
    'Yeni Medya', 'İletişim Tasarımı', 'Görsel İletişim Tasarımı', 'Dijital Medya',
    'Moleküler Biyoloji ve Genetik', 'Biyoloji', 'Kimya', 'Fizik',
    'Matematik', 'İstatistik', 'Astronomi ve Uzay Bilimleri', 'Meteoroloji Mühendisliği',
    'Ziraat Mühendisliği', 'Bahçe Bitkileri', 'Bitki Koruma', 'Tarımsal Biyoteknoloji',
    'Tarım Ekonomisi', 'Tarım Makineleri ve Teknolojileri Mühendisliği', 'Toprak Bilimi ve Bitki Besleme', 'Tarla Bitkileri',
    'Hayvansal Üretim', 'Su Ürünleri Mühendisliği', 'Orman Mühendisliği', 'Orman Endüstrisi Mühendisliği',
    'Yaban Hayatı Ekolojisi ve Yönetimi', 'Turizm İşletmeciliği', 'Turizm ve Otel İşletmeciliği', 'Gastronomi ve Mutfak Sanatları',
    'Rekreasyon Yönetimi', 'Seyahat İşletmeciliği', 'Aşçılık', 'Otel Yöneticiliği',
    'Turizm Rehberliği', 'Spor Yöneticiliği', 'Antrenörlük Eğitimi', 'Beden Eğitimi ve Spor',
    'Egzersiz ve Spor Bilimleri', 'Spor Bilimleri', 'Spor Yönetimi', 'Spor Bilimleri Fakültesi',
    'Diğer'
];

// Topluluk adından "Topluluğu" kelimesini kaldır
function cleanCommunityName($name) {
    $name = trim($name);
    // "Topluluğu" kelimesini kaldır (başta, sonda veya ortada)
    $name = preg_replace('/\s*topluluğu\s*/i', ' ', $name);
    $name = preg_replace('/\s*topluluk\s*/i', ' ', $name);
    $name = trim($name);
    return $name;
}

// Klasör adını otomatik formatla (Türkçe karakterleri çevir, küçük harf, boşlukları alt çizgi)
function formatFolderName($name) {
    // Önce "Topluluğu" kelimesini kaldır
    $name = cleanCommunityName($name);
    
    // Türkçe karakterleri İngilizce karşılıklarına çevir
    $turkish_chars = ['Ç', 'Ğ', 'İ', 'Ö', 'Ş', 'Ü', 'ç', 'ğ', 'ı', 'ö', 'ş', 'ü'];
    $english_chars = ['C', 'G', 'I', 'O', 'S', 'U', 'c', 'g', 'i', 'o', 's', 'u'];
    $name = str_replace($turkish_chars, $english_chars, $name);
    
    // Tüm harfleri küçük harfe çevir
    $name = strtolower($name);
    
    // Boşlukları ve özel karakterleri alt çizgiye çevir
    $name = preg_replace('/[^a-z0-9_]+/', '_', $name);
    
    // Birden fazla alt çizgiyi tek alt çizgiye çevir
    $name = preg_replace('/_+/', '_', $name);
    
    // Başta ve sonda alt çizgi varsa kaldır
    $name = trim($name, '_');
    
    return $name;
}

// Topluluk kodu oluşturma fonksiyonu (bölüm adından veya topluluk adından türetilmiş)
// Format: İlk 3 harf (bölüm/topluluk adından) + 1 rastgele rakam (0-9)
function generateCommunityCode($source_name, $is_department = false) {
    // Önce "Topluluğu" kelimesini kaldır
    $source_name = cleanCommunityName($source_name);
    
    // Türkçe karakterleri İngilizce karşılıklarına çevir
    $turkish_chars = ['Ç', 'Ğ', 'İ', 'Ö', 'Ş', 'Ü', 'ç', 'ğ', 'ı', 'ö', 'ş', 'ü'];
    $english_chars = ['C', 'G', 'I', 'O', 'S', 'U', 'c', 'g', 'i', 'o', 's', 'u'];
    $name = str_replace($turkish_chars, $english_chars, $source_name);
    
    // Sadece harfleri al, boşlukları kaldır
    $name = preg_replace('/[^A-Za-z]/', '', $name);
    $name = strtoupper($name);
    
    // İlk 3 karakteri al
    $code = substr($name, 0, 3);
    
    // Eğer 3 karakterden azsa, rastgele harfler ekle
    if (strlen($code) < 3) {
        $characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        while (strlen($code) < 3) {
            $code .= $characters[rand(0, strlen($characters) - 1)];
        }
    }
    
    // Son karakteri rastgele rakam ekle (0-9)
    $code .= rand(0, 9);
    
    return $code;
}

// Topluluk oluşturma
if ($_SERVER['REQUEST_METHOD'] === 'POST' && (($action ?? '') === 'create' || ($_POST['action'] ?? '') === 'create')) {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
    } else {
        $community_name = trim($_POST['community_name'] ?? '');
        $folder_name = trim($_POST['folder_name'] ?? '');
        $admin_username = trim($_POST['admin_username'] ?? '');
        $admin_password = trim($_POST['admin_password'] ?? '');
        $selected_university = trim($_POST['university'] ?? '');
        
        // Topluluk adından "Topluluğu" kelimesini kaldır
        $community_name = cleanCommunityName($community_name);
        
        // Eğer klasör adı boşsa veya sadece boşluk varsa, topluluk adından otomatik oluştur
        if (empty($folder_name) || trim($folder_name) === '') {
            $folder_name = formatFolderName($community_name);
        } else {
            // Klasör adını formatla
            $folder_name = formatFolderName($folder_name);
        }
        
        // Topluluk kodu oluştur (topluluk adından: ilk 3 harf + rastgele rakam)
        // Aynı üniversitede benzersiz olana kadar dene
        $community_code = generateCommunityCode($community_name);
        $max_attempts = 20; // Daha fazla deneme şansı
        $attempt = 0;
        while ($attempt < $max_attempts) {
            // Kodu kontrol et - aynı üniversitedeki mevcut topluluklarda aynı kod var mı?
            $code_exists = false;
            if (is_dir(COMMUNITIES_DIR)) {
                $dirs = scandir(COMMUNITIES_DIR);
                foreach ($dirs as $dir) {
                    if ($dir === '.' || $dir === '..') continue;
                    $db_path = COMMUNITIES_DIR . $dir . '/unipanel.sqlite';
                    if (file_exists($db_path)) {
                        try {
                            $check_db = new SQLite3($db_path);
                            // Aynı üniversitede mi kontrol et
                            $existing_university = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'university'");
                            $existing_code = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'");
                            $check_db->close();
                            
                            // Sadece aynı üniversitede aynı kod varsa çakışma var
                            if ($existing_university === $selected_university && $existing_code === $community_code) {
                                $code_exists = true;
                                break;
                            }
                        } catch (Exception $e) {
                            // Hata durumunda devam et
                        }
                    }
                }
            }
            if (!$code_exists) {
                break;
            }
            // Yeni kod oluştur (topluluk adından, rastgele rakam değişecek)
            $community_code = generateCommunityCode($community_name);
            $attempt++;
        }
        
        if (empty($community_name) || empty($folder_name) || empty($admin_username) || empty($admin_password) || empty($selected_university)) {
            $error = "Tüm alanlar doldurulmalıdır!";
        } elseif ($attempt >= $max_attempts) {
            $error = "Benzersiz topluluk kodu oluşturulamadı. Lütfen tekrar deneyin.";
        } else {
            // Klasör adı zaten formatlanmış durumda (yukarıda formatFolderName ile)
            $community_path = COMMUNITIES_DIR . $folder_name;
            
            if (is_dir($community_path)) {
                $error = "Bu topluluk zaten mevcut!";
            } else {
                // COMMUNITIES_DIR klasörünün varlığını kontrol et ve oluştur
                if (!is_dir(COMMUNITIES_DIR)) {
                    // COMMUNITIES_DIR yoksa oluştur - recursive olarak tüm parent'ları da oluştur
                    if (!@mkdir(COMMUNITIES_DIR, SUPERADMIN_DIR_PERMS, true)) {
                        $error = "Communities klasörü oluşturulamadı: " . COMMUNITIES_DIR . " - İzin sorunu olabilir.";
                    } else {
                        @chmod(COMMUNITIES_DIR, SUPERADMIN_DIR_PERMS);
                    }
                } else {
                    // Klasör varsa izinleri kontrol et ve düzelt
                    if (!is_writable(COMMUNITIES_DIR)) {
                        @chmod(COMMUNITIES_DIR, SUPERADMIN_DIR_PERMS);
                    }
                }
                
                // Klasör oluştur
                $full_path = COMMUNITIES_DIR . $folder_name;
                
                // Klasörün zaten oluşup oluşmadığını tekrar kontrol et
                if (is_dir($full_path)) {
                    $error = "Bu topluluk zaten mevcut!";
                } elseif (!empty($error)) {
                    // Önceki hata varsa devam etme
                } else {
                    // Klasör oluşturmayı dene
                    if (@mkdir($full_path, SUPERADMIN_DIR_PERMS, true)) {
                        @chmod($full_path, SUPERADMIN_DIR_PERMS);
                        
                        if (!is_dir($full_path)) {
                            $error = "Klasör oluşturuldu ancak erişilemiyor: " . $full_path;
                        } elseif (!is_writable($full_path)) {
                            $error = "Klasör oluşturuldu ancak yazılabilir değil: " . $full_path;
                        } else {
                            $template_index = __DIR__ . '/../templates/template_index.php';
                            $template_login = __DIR__ . '/../templates/template_login.php';
                            $template_loading = __DIR__ . '/../templates/template_loading.php';
                            $template_public_index = __DIR__ . '/../templates/template_public_index.php';
                            $input_validator = __DIR__ . '/../lib/general/input_validator.php';
                            $session_security = __DIR__ . '/../lib/general/session_security.php';
                            
                            if (!file_exists($template_index)) {
                                $error = "Template index dosyası bulunamadı: " . $template_index;
                            } elseif (!file_exists($template_login)) {
                                $error = "Template login dosyası bulunamadı: " . $template_login;
                            } elseif (!file_exists($template_loading)) {
                                $error = "Template loading dosyası bulunamadı: " . $template_loading;
                            } elseif (!file_exists($template_public_index)) {
                                $error = "Template public index dosyası bulunamadı: " . $template_public_index;
                            } elseif (!file_exists($input_validator)) {
                                $error = "Input validator dosyası bulunamadı: " . $input_validator;
                            } elseif (!file_exists($session_security)) {
                                $error = "Session security dosyası bulunamadı: " . $session_security;
                            } else {
                                $stubResult = sync_community_stubs($full_path);
                                
                                if (!$stubResult['success']) {
                                    $relativeErrors = array_map(function ($path) use ($full_path) {
                                        return ltrim(str_replace($full_path . '/', '', $path), '/');
                                    }, $stubResult['errors']);
                                    $error = "Şablon stub dosyaları oluşturulamadı: " . implode(', ', $relativeErrors);
                                } elseif (!copy($input_validator, $full_path . '/input_validator.php')) {
                                    $error = "input_validator.php dosyası kopyalanamadı!";
                                } elseif (!copy($session_security, $full_path . '/session_security.php')) {
                                    $error = "session_security.php dosyası kopyalanamadı!";
                                } else {
                                    $public_dir = $full_path . '/public';
                                    if (!is_dir($public_dir)) {
                                        @mkdir($public_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                    }
                                    @chmod($public_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                    
                                    $logo_source = __DIR__ . '/../assets/images/logo_tr.png';
                                    $logo_target_dir = $full_path . '/assets/images/';
                                    $logo_target = $logo_target_dir . 'logo_tr.png';
                                    
                                    if (!is_dir($logo_target_dir)) {
                                        mkdir($logo_target_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @chmod($logo_target_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                    }
                                    
                                    $partner_logos_dir = $full_path . '/assets/images/partner-logos/';
                                    if (!is_dir($partner_logos_dir)) {
                                        mkdir($partner_logos_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @chmod($partner_logos_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                    }
                                    
                                    $events_images_dir = $full_path . '/assets/images/events/';
                                    $events_videos_dir = $full_path . '/assets/videos/events/';
                                    if (!is_dir($events_images_dir)) {
                                        mkdir($events_images_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @chmod($events_images_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                    }
                                    if (!is_dir($events_videos_dir)) {
                                        mkdir($events_videos_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @chmod($events_videos_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                    }
                                    
                                    if (file_exists($logo_source)) {
                                        copy($logo_source, $logo_target);
                                    }
                                    
                                    @chmod($full_path . '/index.php', 0644);
                                    @chmod($full_path . '/login.php', 0644);
                                    @chmod($full_path . '/loading.php', 0644);
                                    @chmod($full_path, SUPERADMIN_DIR_PERMS);
                                    @chmod($full_path . '/assets', SUPERADMIN_PUBLIC_DIR_PERMS);
                                    @chmod($full_path . '/assets/images', SUPERADMIN_PUBLIC_DIR_PERMS);
                                    @chmod($full_path . '/assets/videos', SUPERADMIN_PUBLIC_DIR_PERMS);
                                    
                                    $db_path = $full_path . '/unipanel.sqlite';
                                    $db = new SQLite3($db_path);
                                    
                                    $db->exec("CREATE TABLE IF NOT EXISTS admins (
                        id INTEGER PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        password_hash TEXT NOT NULL,
                        club_id INTEGER,
                        is_banned INTEGER DEFAULT 0,
                        created_at TEXT DEFAULT CURRENT_TIMESTAMP
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS members (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        full_name TEXT,
                        email TEXT,
                        student_id TEXT,
                        phone_number TEXT,
                        registration_date TEXT,
                        is_banned INTEGER DEFAULT 0,
                        ban_reason TEXT
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS events (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        title TEXT NOT NULL,
                        description TEXT,
                        date TEXT NOT NULL,
                        time TEXT,
                        location TEXT,
                        image_path TEXT,
                        video_path TEXT,
                        category TEXT DEFAULT 'Genel',
                        status TEXT DEFAULT 'planlanıyor',
                        priority TEXT DEFAULT 'normal',
                        capacity INTEGER,
                        registration_required INTEGER DEFAULT 0,
                        is_active INTEGER DEFAULT 1
                    )");
                    
                    // Event RSVP Tablosu (Etkinlik katılım takibi) - events tablosundan sonra oluşturulmalı
                    $db->exec("CREATE TABLE IF NOT EXISTS event_rsvp (
                        id INTEGER PRIMARY KEY,
                        event_id INTEGER NOT NULL,
                        club_id INTEGER NOT NULL,
                        member_name TEXT NOT NULL,
                        member_email TEXT NOT NULL,
                        member_phone TEXT,
                        rsvp_status TEXT DEFAULT 'attending',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE
                    )");
                    
                    // Email Campaigns Tablosu (Toplu mail kampanyaları)
                    $db->exec("CREATE TABLE IF NOT EXISTS email_campaigns (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER NOT NULL,
                        subject TEXT NOT NULL,
                        message TEXT NOT NULL,
                        from_name TEXT,
                        from_email TEXT,
                        total_recipients INTEGER DEFAULT 0,
                        sent_count INTEGER DEFAULT 0,
                        failed_count INTEGER DEFAULT 0,
                        status TEXT DEFAULT 'pending',
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        started_at DATETIME,
                        completed_at DATETIME
                    )");
                    
                    // Email Queue Tablosu (Mail gönderim kuyruğu)
                    $db->exec("CREATE TABLE IF NOT EXISTS email_queue (
                        id INTEGER PRIMARY KEY,
                        campaign_id INTEGER NOT NULL,
                        club_id INTEGER NOT NULL,
                        recipient_email TEXT NOT NULL,
                        recipient_name TEXT,
                        subject TEXT NOT NULL,
                        message TEXT NOT NULL,
                        from_name TEXT,
                        from_email TEXT,
                        status TEXT DEFAULT 'pending',
                        attempts INTEGER DEFAULT 0,
                        error_message TEXT,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        sent_at DATETIME,
                        FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS board_members (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        full_name TEXT NOT NULL,
                        role TEXT NOT NULL,
                        contact_email TEXT,
                        is_active INTEGER DEFAULT 1
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS settings (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        setting_key TEXT NOT NULL,
                        setting_value TEXT NOT NULL
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS admin_logs (
                        id INTEGER PRIMARY KEY,
                        community_name TEXT,
                        action TEXT,
                        details TEXT,
                        timestamp TEXT DEFAULT CURRENT_TIMESTAMP
                    )");
                    
                    $db->exec("CREATE TABLE IF NOT EXISTS notifications (
                        id INTEGER PRIMARY KEY,
                        club_id INTEGER,
                        title TEXT NOT NULL,
                        message TEXT NOT NULL,
                        type TEXT DEFAULT 'info',
                        is_read INTEGER DEFAULT 0,
                        is_urgent INTEGER DEFAULT 0,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                        sender_type TEXT DEFAULT 'superadmin'
                    )");
                    
                    // Admin kullanıcısı oluştur
                    $hashed_password = password_hash($admin_password, PASSWORD_DEFAULT);
                    $stmt = $db->prepare("INSERT INTO admins (username, password_hash, club_id) VALUES (?, ?, ?)");
                    $stmt->bindValue(1, $admin_username, SQLITE3_TEXT);
                    $stmt->bindValue(2, $hashed_password, SQLITE3_TEXT);
                    $stmt->bindValue(3, 1, SQLITE3_INTEGER);
                    $stmt->execute();
                    
                    // Topluluk ayarları
                    $stmt = $db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                    $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                    $stmt->bindValue(2, 'club_name', SQLITE3_TEXT);
                    $stmt->bindValue(3, $community_name, SQLITE3_TEXT);
                    $stmt->execute();
                                    
                                    // Topluluk durumu ayarla (aktif)
                                    $stmt = $db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                    $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                    $stmt->bindValue(2, 'status', SQLITE3_TEXT);
                                    $stmt->bindValue(3, 'active', SQLITE3_TEXT);
                                    $stmt->execute();
                                    
                                    // Deneme süresi başlangıç tarihi (365 gün)
                                    $trial_start_date = date('Y-m-d');
                                    $stmt = $db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                    $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                    $stmt->bindValue(2, 'trial_start_date', SQLITE3_TEXT);
                                    $stmt->bindValue(3, $trial_start_date, SQLITE3_TEXT);
                                    $stmt->execute();
                                    
                                    // Başkan bilgileri otomatik olarak topluluk panelinden çekilecek
                                    // Yönetim kurulu bilgileri topluluk panelinden otomatik çekilecek
                                    
                                    try {
                                        $stmt = $db->prepare("INSERT INTO notifications (club_id, title, message, type, sender_type) VALUES (?, ?, ?, ?, ?)");
                                        if ($stmt) {
                                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                            $stmt->bindValue(2, 'Hoş Geldiniz!', SQLITE3_TEXT);
                                            $stmt->bindValue(3, $community_name . ' topluluğuna hoş geldiniz! Sistemi kullanmaya başlamak için sol menüden panoyu kontrol edebilirsiniz.', SQLITE3_TEXT);
                                            $stmt->bindValue(4, 'success', SQLITE3_TEXT);
                                            $stmt->bindValue(5, 'system', SQLITE3_TEXT);
                                            $stmt->execute();
                                        }
                                    } catch (Exception $e) {
                                        error_log("Hoş geldiniz bildirimi eklenemedi: " . $e->getMessage());
                                    }
                                    
                                    try {
                                        $stmt = $db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                        if ($stmt) {
                                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                            $stmt->bindValue(2, 'university', SQLITE3_TEXT);
                                            $stmt->bindValue(3, $selected_university, SQLITE3_TEXT);
                                            $stmt->execute();
                                        }
                                    } catch (Exception $e) {
                                        error_log("Üniversite bilgisi kaydedilemedi: " . $e->getMessage());
                                    }
                                    
                                    try {
                                        $stmt = $db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                        if ($stmt) {
                                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                            $stmt->bindValue(2, 'community_code', SQLITE3_TEXT);
                                            $stmt->bindValue(3, $community_code, SQLITE3_TEXT);
                                            $stmt->execute();
                                        }
                                    } catch (Exception $e) {
                                        error_log("Topluluk kodu kaydedilemedi: " . $e->getMessage());
                                    }
                                    
                                    // SMTP ayarlarını config/credentials.php'den çek ve kaydet
                                    try {
                                        $credentials_path = __DIR__ . '/../config/credentials.php';
                                        if (file_exists($credentials_path)) {
                                            $credentials = require $credentials_path;
                                            if (isset($credentials['smtp']) && is_array($credentials['smtp'])) {
                                                $smtp_config = $credentials['smtp'];
                                                
                                                // SMTP ayarlarını veritabanına kaydet
                                                $smtp_settings = [
                                                    'smtp_username' => $smtp_config['username'] ?? '',
                                                    'smtp_password' => $smtp_config['password'] ?? '',
                                                    'smtp_host' => $smtp_config['host'] ?? 'ms7.guzel.net.tr',
                                                    'smtp_port' => (string)($smtp_config['port'] ?? 587),
                                                    'smtp_secure' => $smtp_config['encryption'] ?? 'tls',
                                                    'smtp_from_email' => $smtp_config['from_email'] ?? ($smtp_config['username'] ?? 'admin@foursoftware.com.tr'),
                                                    'smtp_from_name' => $smtp_config['from_name'] ?? 'UniFour'
                                                ];
                                                
                                                foreach ($smtp_settings as $key => $value) {
                                                    if (!empty($value)) {
                                                        try {
                                                            $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                                            if ($stmt) {
                                                                $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                                                $stmt->bindValue(2, $key, SQLITE3_TEXT);
                                                                $stmt->bindValue(3, $value, SQLITE3_TEXT);
                                                                $stmt->execute();
                                                            }
                                                        } catch (Exception $e) {
                                                            error_log("SMTP ayarı kaydedilemedi ($key): " . $e->getMessage());
                                                        }
                                                    }
                                                }
                                                
                                                error_log("SMTP ayarları başarıyla yüklendi: " . $community_name);
                                            } else {
                                                error_log("SMTP ayarları config/credentials.php'de bulunamadı");
                                            }
                                        } else {
                                            error_log("config/credentials.php dosyası bulunamadı");
                                        }
                                    } catch (Exception $e) {
                                        error_log("SMTP ayarları yüklenirken hata: " . $e->getMessage());
                                    }
                                    
                                    $db->close();
                                    
                                    // İzin kontrolü ve düzeltme - veritabanı dosyası ve tüm klasörler
                                    try {
                                        // Veritabanı dosyası izinlerini kontrol et ve düzelt
                                        if (file_exists($db_path)) {
                                            if (!is_writable($db_path)) {
                                                @chmod($db_path, SUPERADMIN_FILE_PERMS);
                                            }
                                        }
                                        
                                        // Ana klasör izinlerini kontrol et
                                        if (is_dir($full_path) && !is_writable($full_path)) {
                                            @chmod($full_path, SUPERADMIN_DIR_PERMS);
                                        }
                                        
                                        // Alt klasörlerin izinlerini kontrol et ve düzelt
                                        $dirs_to_check = [
                                            $full_path . '/public',
                                            $full_path . '/assets',
                                            $full_path . '/assets/images',
                                            $full_path . '/assets/images/partner-logos',
                                            $full_path . '/assets/videos',
                                            $full_path . '/assets/videos/events'
                                        ];
                                        
                                        foreach ($dirs_to_check as $dir) {
                                            if (is_dir($dir) && !is_writable($dir)) {
                                                @chmod($dir, SUPERADMIN_PUBLIC_DIR_PERMS);
                                            }
                                        }
                                        
                                        // .htaccess dosyası varsa izinlerini kontrol et
                                        $htaccess_path = $full_path . '/.htaccess';
                                        if (file_exists($htaccess_path) && !is_readable($htaccess_path)) {
                                            @chmod($htaccess_path, SUPERADMIN_FILE_PERMS);
                                        }
                                        
                                        // PHP dosyalarının izinlerini kontrol et
                                        $php_files = [
                                            $full_path . '/index.php',
                                            $full_path . '/login.php',
                                            $full_path . '/loading.php',
                                            $full_path . '/input_validator.php',
                                            $full_path . '/session_security.php'
                                        ];
                                        
                                        foreach ($php_files as $file) {
                                            if (file_exists($file) && !is_readable($file)) {
                                                @chmod($file, SUPERADMIN_FILE_PERMS);
                                            }
                                        }
                                    } catch (Exception $e) {
                                        error_log("İzin kontrolü hatası: " . $e->getMessage());
                                    }
                                    
                                    // Cache'i temizle (yeni topluluk eklendi)
                                    clearCommunitiesCache();
                                    
                                    $success = "Topluluk başarıyla oluşturuldu: " . $community_name . " | Topluluk Kodu: <strong>" . $community_code . "</strong>";
                                    // Sayfayı yenile ki yeni topluluk listede görünsün
                                    header("Refresh: 2; url=" . $_SERVER['PHP_SELF'] . "?view=communities");
                                }
                            }
                        }
                    } else {
                        // mkdir başarısız oldu - izin sorunu olabilir
                        $last_error = error_get_last();
                        $is_local = (strpos(__DIR__, '/Applications/XAMPP') !== false || strpos(__DIR__, 'xampp') !== false);
                        
                        if ($is_local) {
                            // Local ortamda daha detaylı hata mesajı ve çözüm önerisi
                            $error_details = [];
                            $error_details[] = "<strong>Klasör yolu:</strong> " . $full_path;
                            $error_details[] = "<strong>Communities klasörü yazılabilir mi:</strong> " . (is_writable(COMMUNITIES_DIR) ? "Evet ✓" : "Hayır ✗");
                            if (is_dir(COMMUNITIES_DIR)) {
                                $error_details[] = "<strong>Communities klasörü izinleri:</strong> " . substr(sprintf('%o', fileperms(COMMUNITIES_DIR)), -4);
                            }
                            
                            if ($last_error) {
                                $error_details[] = "<strong>PHP Hatası:</strong> " . htmlspecialchars($last_error['message']);
                            }
                            
                            $error = "<div style='background: #fef2f2; border: 1 solid #fecaca; border-radius: 8px; padding: 16px; margin: 16px 0;'>";
                            $error .= "<h3 style='color: #dc2626; margin-bottom: 12px;'>❌ Topluluk klasörü oluşturulamadı!</h3>";
                            $error .= "<div style='margin-bottom: 16px;'>" . implode("<br>", $error_details) . "</div>";
                            $error .= "<div style='background: #f3f4f6; padding: 12px; border-radius: 6px; margin-top: 12px;'>";
                            $error .= "<strong style='color: #1f2937;'>🔧 Local Ortam Çözümü:</strong><br>";
                            $error .= "Terminal'de şu komutu çalıştırın:<br>";
                            $error .= "<code style='background: #1f2937; color: #10b981; padding: 8px 12px; border-radius: 4px; display: inline-block; margin-top: 8px; font-family: monospace;'>chmod -R 777 " . htmlspecialchars(COMMUNITIES_DIR) . "</code>";
                            $error .= "</div></div>";
                            
                            error_log("Failed to create community folder (local): " . $full_path);
                        } else {
                            // Hosting ortamında daha kısa mesaj
                            $error = "Topluluk klasörü oluşturulamadı. Lütfen sunucu yöneticisi ile iletişime geçin.";
                            error_log("Failed to create community folder (hosting): " . $full_path);
                        }
                    }
                }
            }
        }
    }
}

// Topluluk talebi onaylama
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'approve_request') {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
    } else {
        $request_id = intval($_POST['request_id'] ?? 0);
        
        if ($request_id <= 0) {
            $error = "Geçersiz talep ID!";
        } else {
            initLogDatabase();
            $db = new SQLite3(SUPERADMIN_DB);
            $db->exec('PRAGMA journal_mode = WAL');
            
            // Talebi al
            $stmt = $db->prepare("SELECT * FROM community_requests WHERE id = ? AND status = 'pending'");
            $stmt->bindValue(1, $request_id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            $request = $result->fetchArray(SQLITE3_ASSOC);
            
            if (!$request) {
                $error = "Talep bulunamadı veya zaten işlenmiş!";
                $db->close();
            } else {
                // Topluluk oluşturma işlemini başlat
                $community_name = $request['community_name'];
                $folder_name = $request['folder_name'];
                $admin_username = $request['admin_username'];
                $admin_password_hash = $request['admin_password_hash'];
                $admin_email = $request['admin_email'];
                $selected_university = $request['university'];
                
                // Topluluk kodu oluştur
                $community_code = generateCommunityCode($community_name);
                $max_attempts = 20;
                $attempt = 0;
                
                while ($attempt < $max_attempts) {
                    $code_exists = false;
                    if (is_dir(COMMUNITIES_DIR)) {
                        $dirs = scandir(COMMUNITIES_DIR);
                        foreach ($dirs as $dir) {
                            if ($dir === '.' || $dir === '..') continue;
                            $check_db_path = COMMUNITIES_DIR . $dir . '/unipanel.sqlite';
                            if (file_exists($check_db_path)) {
                                try {
                                    $check_db = new SQLite3($check_db_path);
                                    $settings_table_exists = (bool) @$check_db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
                                    $existing_university = '';
                                    $existing_code = '';
                                    if ($settings_table_exists) {
                                        $existing_university = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'university'") ?: '';
                                        $existing_code = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'") ?: '';
                                    }
                                    $check_db->close();
                                    
                                    if ($existing_university === $selected_university && $existing_code === $community_code) {
                                        $code_exists = true;
                                        break;
                                    }
                                } catch (Exception $e) {
                                    // Devam et
                                }
                            }
                        }
                    }
                    if (!$code_exists) {
                        break;
                    }
                    $community_code = generateCommunityCode($community_name);
                    $attempt++;
                }
                
                if ($attempt >= $max_attempts) {
                    $error = "Benzersiz topluluk kodu oluşturulamadı!";
                    $db->close();
                } else {
                    $community_path = COMMUNITIES_DIR . $folder_name;
                    $db_path = $community_path . '/unipanel.sqlite';
                    
                    // Klasör varsa ama veritabanı yoksa (kayıt sırasında oluşturulmuş), sadece veritabanını oluştur
                    if (is_dir($community_path) && !file_exists($db_path)) {
                        // Klasör zaten var, sadece veritabanı ve admin kullanıcısını oluştur
                        $db->close();
                        
                        // Veritabanı oluştur
                        $community_db = new SQLite3($db_path);
                        $community_db->exec('PRAGMA journal_mode = WAL');
                        
                        // Tabloları oluştur
                        $community_db->exec("CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, club_id INTEGER, is_banned INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, club_id INTEGER, full_name TEXT, email TEXT, student_id TEXT, phone_number TEXT, registration_date TEXT, is_banned INTEGER DEFAULT 0, ban_reason TEXT)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, club_id INTEGER, title TEXT NOT NULL, description TEXT, date TEXT NOT NULL, time TEXT, location TEXT, image_path TEXT, video_path TEXT, category TEXT DEFAULT 'Genel', status TEXT DEFAULT 'planlanıyor', priority TEXT DEFAULT 'normal', capacity INTEGER, registration_required INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS event_rsvp (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, club_id INTEGER NOT NULL, member_name TEXT NOT NULL, member_email TEXT NOT NULL, member_phone TEXT, rsvp_status TEXT DEFAULT 'attending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS email_campaigns (id INTEGER PRIMARY KEY, club_id INTEGER NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, from_name TEXT, from_email TEXT, total_recipients INTEGER DEFAULT 0, sent_count INTEGER DEFAULT 0, failed_count INTEGER DEFAULT 0, status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, started_at DATETIME, completed_at DATETIME)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS email_queue (id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL, club_id INTEGER NOT NULL, recipient_email TEXT NOT NULL, recipient_name TEXT, subject TEXT NOT NULL, message TEXT NOT NULL, from_name TEXT, from_email TEXT, status TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0, error_message TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, sent_at DATETIME, FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS board_members (id INTEGER PRIMARY KEY, club_id INTEGER, full_name TEXT NOT NULL, role TEXT NOT NULL, contact_email TEXT, is_active INTEGER DEFAULT 1)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, club_id INTEGER, setting_key TEXT NOT NULL, setting_value TEXT NOT NULL)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS admin_logs (id INTEGER PRIMARY KEY, community_name TEXT, action TEXT, details TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)");
                        $community_db->exec("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, club_id INTEGER, title TEXT NOT NULL, message TEXT NOT NULL, type TEXT DEFAULT 'info', is_read INTEGER DEFAULT 0, is_urgent INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, sender_type TEXT DEFAULT 'superadmin')");
                        
                        // Admin kullanıcısı oluştur
                        $stmt = $community_db->prepare("INSERT INTO admins (username, password_hash, club_id) VALUES (?, ?, ?)");
                        $stmt->bindValue(1, $admin_username, SQLITE3_TEXT);
                        $stmt->bindValue(2, $admin_password_hash, SQLITE3_TEXT);
                        $stmt->bindValue(3, 1, SQLITE3_INTEGER);
                        $stmt->execute();
                        
                        // Topluluk ayarları
                        $settings = [
                            ['club_name', $community_name],
                            ['status', 'active'],
                            ['trial_start_date', date('Y-m-d')],
                            ['university', $selected_university],
                            ['community_code', $community_code]
                        ];
                        
                        if (!empty($admin_email)) {
                            $settings[] = ['admin_email', $admin_email];
                        }
                        
                        // SMTP ayarlarını config/credentials.php'den çek ve ekle
                        try {
                            $credentials_path = __DIR__ . '/../config/credentials.php';
                            if (file_exists($credentials_path)) {
                                $credentials = require $credentials_path;
                                if (isset($credentials['smtp']) && is_array($credentials['smtp'])) {
                                    $smtp_config = $credentials['smtp'];
                                    
                                    if (!empty($smtp_config['username'])) {
                                        $settings[] = ['smtp_username', $smtp_config['username']];
                                    }
                                    if (!empty($smtp_config['password'])) {
                                        $settings[] = ['smtp_password', $smtp_config['password']];
                                    }
                                    if (!empty($smtp_config['host'])) {
                                        $settings[] = ['smtp_host', $smtp_config['host']];
                                    }
                                    if (!empty($smtp_config['port'])) {
                                        $settings[] = ['smtp_port', (string)$smtp_config['port']];
                                    }
                                    if (!empty($smtp_config['encryption'])) {
                                        $settings[] = ['smtp_secure', $smtp_config['encryption']];
                                    }
                                    if (!empty($smtp_config['from_email'])) {
                                        $settings[] = ['smtp_from_email', $smtp_config['from_email']];
                                    }
                                    if (!empty($smtp_config['from_name'])) {
                                        $settings[] = ['smtp_from_name', $smtp_config['from_name']];
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            error_log("SMTP ayarları yüklenirken hata: " . $e->getMessage());
                        }
                        
                        foreach ($settings as $setting) {
                            $stmt = $community_db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                            $stmt->bindValue(2, $setting[0], SQLITE3_TEXT);
                            $stmt->bindValue(3, $setting[1], SQLITE3_TEXT);
                            $stmt->execute();
                        }
                        
                        // Hoş geldiniz bildirimi
                        try {
                            $stmt = $community_db->prepare("INSERT INTO notifications (club_id, title, message, type, sender_type) VALUES (?, ?, ?, ?, ?)");
                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                            $stmt->bindValue(2, 'Hoş Geldiniz!', SQLITE3_TEXT);
                            $stmt->bindValue(3, $community_name . ' topluluğuna hoş geldiniz! Sistemi kullanmaya başlamak için sol menüden panoyu kontrol edebilirsiniz.', SQLITE3_TEXT);
                            $stmt->bindValue(4, 'success', SQLITE3_TEXT);
                            $stmt->bindValue(5, 'system', SQLITE3_TEXT);
                            $stmt->execute();
                        } catch (Exception $e) {
                            // Hata olsa da devam et
                        }
                        
                        $community_db->close();
                        
                        // Talebi approved olarak işaretle
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                        $update_stmt = $db->prepare("UPDATE community_requests SET status = 'approved', processed_at = CURRENT_TIMESTAMP, processed_by = ? WHERE id = ?");
                        $update_stmt->bindValue(1, 'superadmin', SQLITE3_TEXT);
                        $update_stmt->bindValue(2, $request_id, SQLITE3_INTEGER);
                        $update_stmt->execute();
                        $db->close();
                        
                        // Cache'i temizle
                        clearCommunitiesCache();
                        
                        $success = "Topluluk talebi onaylandı ve topluluk başarıyla aktifleştirildi!";
                        // Sayfayı yenile ki yeni topluluk listede görünsün
                        header("Refresh: 2; url=" . $_SERVER['PHP_SELF'] . "?view=communities");
                    } elseif (is_dir($community_path) && file_exists($db_path)) {
                        // Hem klasör hem veritabanı varsa, zaten oluşturulmuş
                        $db->close();
                        $error = "Bu topluluk zaten mevcut!";
                    } else {
                        // Topluluk oluşturma işlemini superadmin'deki mevcut koddan kopyala
                        // (superadmin/index.php'deki topluluk oluşturma kodunu kullan)
                        // Burada sadece talep onaylama mantığını ekliyoruz
                        // Gerçek topluluk oluşturma işlemi superadmin'deki mevcut fonksiyonla yapılacak
                        
                        $db->close();
                        
                        // Topluluk oluşturma işlemini yap (superadmin'deki mevcut kodu kullan)
                        // Klasör oluştur
                        if (!is_dir(COMMUNITIES_DIR)) {
                            @mkdir(COMMUNITIES_DIR, SUPERADMIN_DIR_PERMS, true);
                            @chmod(COMMUNITIES_DIR, SUPERADMIN_DIR_PERMS);
                        }
                        
                        $full_path = COMMUNITIES_DIR . $folder_name;
                        if (!is_dir($full_path)) {
                            if (@mkdir($full_path, SUPERADMIN_DIR_PERMS, true)) {
                                @chmod($full_path, SUPERADMIN_DIR_PERMS);
                                
                                // Template dosyalarını kopyala (superadmin'deki mevcut kod)
                                $template_index = __DIR__ . '/../templates/template_index.php';
                                $template_login = __DIR__ . '/../templates/template_login.php';
                                $template_loading = __DIR__ . '/../templates/template_loading.php';
                                $input_validator = __DIR__ . '/../lib/general/input_validator.php';
                                $session_security = __DIR__ . '/../lib/general/session_security.php';
                                
                                if (file_exists($template_index) && file_exists($template_login) && file_exists($template_loading) && 
                                    file_exists($input_validator) && file_exists($session_security)) {
                                    
                                    $stubResult = sync_community_stubs($full_path);
                                    
                                    if ($stubResult['success']) {
                                        copy($input_validator, $full_path . '/input_validator.php');
                                        copy($session_security, $full_path . '/session_security.php');
                                        
                                        // Public ve assets dizinlerini oluştur
                                        @mkdir($full_path . '/public', SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @mkdir($full_path . '/assets/images', SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @mkdir($full_path . '/assets/images/partner-logos', SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @mkdir($full_path . '/assets/images/events', SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        @mkdir($full_path . '/assets/videos/events', SUPERADMIN_PUBLIC_DIR_PERMS, true);
                                        
                                        // Logo kopyala
                                        $logo_source = __DIR__ . '/../assets/images/logo_tr.png';
                                        if (file_exists($logo_source)) {
                                            copy($logo_source, $full_path . '/assets/images/logo_tr.png');
                                        }
                                        
                                        // Veritabanı oluştur
                                        $db_path = $full_path . '/unipanel.sqlite';
                                        $community_db = new SQLite3($db_path);
                                        $community_db->exec('PRAGMA journal_mode = WAL');
                                        
                                        // Tabloları oluştur (superadmin'deki mevcut kod)
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, club_id INTEGER, is_banned INTEGER DEFAULT 0, created_at TEXT DEFAULT CURRENT_TIMESTAMP)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS members (id INTEGER PRIMARY KEY, club_id INTEGER, full_name TEXT, email TEXT, student_id TEXT, phone_number TEXT, registration_date TEXT, is_banned INTEGER DEFAULT 0, ban_reason TEXT)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS events (id INTEGER PRIMARY KEY, club_id INTEGER, title TEXT NOT NULL, description TEXT, date TEXT NOT NULL, time TEXT, location TEXT, image_path TEXT, video_path TEXT, category TEXT DEFAULT 'Genel', status TEXT DEFAULT 'planlanıyor', priority TEXT DEFAULT 'normal', capacity INTEGER, registration_required INTEGER DEFAULT 0, is_active INTEGER DEFAULT 1)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS event_rsvp (id INTEGER PRIMARY KEY, event_id INTEGER NOT NULL, club_id INTEGER NOT NULL, member_name TEXT NOT NULL, member_email TEXT NOT NULL, member_phone TEXT, rsvp_status TEXT DEFAULT 'attending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, FOREIGN KEY (event_id) REFERENCES events(id) ON DELETE CASCADE)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS email_campaigns (id INTEGER PRIMARY KEY, club_id INTEGER NOT NULL, subject TEXT NOT NULL, message TEXT NOT NULL, from_name TEXT, from_email TEXT, total_recipients INTEGER DEFAULT 0, sent_count INTEGER DEFAULT 0, failed_count INTEGER DEFAULT 0, status TEXT DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP, started_at DATETIME, completed_at DATETIME)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS email_queue (id INTEGER PRIMARY KEY, campaign_id INTEGER NOT NULL, club_id INTEGER NOT NULL, recipient_email TEXT NOT NULL, recipient_name TEXT, subject TEXT NOT NULL, message TEXT NOT NULL, from_name TEXT, from_email TEXT, status TEXT DEFAULT 'pending', attempts INTEGER DEFAULT 0, error_message TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, sent_at DATETIME, FOREIGN KEY (campaign_id) REFERENCES email_campaigns(id) ON DELETE CASCADE)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS board_members (id INTEGER PRIMARY KEY, club_id INTEGER, full_name TEXT NOT NULL, role TEXT NOT NULL, contact_email TEXT, is_active INTEGER DEFAULT 1)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS settings (id INTEGER PRIMARY KEY, club_id INTEGER, setting_key TEXT NOT NULL, setting_value TEXT NOT NULL)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS admin_logs (id INTEGER PRIMARY KEY, community_name TEXT, action TEXT, details TEXT, timestamp TEXT DEFAULT CURRENT_TIMESTAMP)");
                                        $community_db->exec("CREATE TABLE IF NOT EXISTS notifications (id INTEGER PRIMARY KEY, club_id INTEGER, title TEXT NOT NULL, message TEXT NOT NULL, type TEXT DEFAULT 'info', is_read INTEGER DEFAULT 0, is_urgent INTEGER DEFAULT 0, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, sender_type TEXT DEFAULT 'superadmin')");
                                        
                                        // Admin kullanıcısı oluştur (hash'lenmiş şifre ile)
                                        $stmt = $community_db->prepare("INSERT INTO admins (username, password_hash, club_id) VALUES (?, ?, ?)");
                                        $stmt->bindValue(1, $admin_username, SQLITE3_TEXT);
                                        $stmt->bindValue(2, $admin_password_hash, SQLITE3_TEXT);
                                        $stmt->bindValue(3, 1, SQLITE3_INTEGER);
                                        $stmt->execute();
                                        
                                        // Topluluk ayarları
                                        $settings = [
                                            ['club_name', $community_name],
                                            ['status', 'active'],
                                            ['trial_start_date', date('Y-m-d')],
                                            ['university', $selected_university],
                                            ['community_code', $community_code]
                                        ];
                                        
                                        if (!empty($admin_email)) {
                                            $settings[] = ['admin_email', $admin_email];
                                        }
                                        
                                        foreach ($settings as $setting) {
                                            $stmt = $community_db->prepare("INSERT INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                            $stmt->bindValue(2, $setting[0], SQLITE3_TEXT);
                                            $stmt->bindValue(3, $setting[1], SQLITE3_TEXT);
                                            $stmt->execute();
                                        }
                                        
                                        // Hoş geldiniz bildirimi
                                        try {
                                            $stmt = $community_db->prepare("INSERT INTO notifications (club_id, title, message, type, sender_type) VALUES (?, ?, ?, ?, ?)");
                                            $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                                            $stmt->bindValue(2, 'Hoş Geldiniz!', SQLITE3_TEXT);
                                            $stmt->bindValue(3, $community_name . ' topluluğuna hoş geldiniz! Sistemi kullanmaya başlamak için sol menüden panoyu kontrol edebilirsiniz.', SQLITE3_TEXT);
                                            $stmt->bindValue(4, 'success', SQLITE3_TEXT);
                                            $stmt->bindValue(5, 'system', SQLITE3_TEXT);
                                            $stmt->execute();
                                        } catch (Exception $e) {
                                            // Hata olsa da devam et
                                        }
                                        
                                        $community_db->close();
                                        
                                        // Talebi approved olarak işaretle
                                        $db = new SQLite3(SUPERADMIN_DB);
                                        $db->exec('PRAGMA journal_mode = WAL');
                                        $update_stmt = $db->prepare("UPDATE community_requests SET status = 'approved', processed_at = CURRENT_TIMESTAMP, processed_by = ? WHERE id = ?");
                                        $update_stmt->bindValue(1, 'superadmin', SQLITE3_TEXT);
                                        $update_stmt->bindValue(2, $request_id, SQLITE3_INTEGER);
                                        $update_stmt->execute();
                                        $db->close();
                                        
                                        // Cache'i temizle
                                        clearCommunitiesCache();
                                        
                                        $success = "Topluluk talebi onaylandı ve topluluk başarıyla oluşturuldu!";
                                        // Sayfayı yenile ki yeni topluluk listede görünsün
                                        header("Refresh: 2; url=" . $_SERVER['PHP_SELF'] . "?view=communities");
                                    } else {
                                        @rmdir($full_path);
                                        $error = "Şablon dosyaları oluşturulamadı!";
                                    }
                                } else {
                                    @rmdir($full_path);
                                    $error = "Gerekli template dosyaları bulunamadı!";
                                }
                            } else {
                                $error = "Topluluk klasörü oluşturulamadı!";
                            }
                        } else {
                            $error = "Bu topluluk zaten mevcut!";
                        }
                    }
                }
            }
        }
    }
}

// Topluluk talebi reddetme
// Reklam yönetimi POST işlemleri - EN ÜSTTE İŞLENMELİ
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_ad') {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
        header("Location: ?view=ads&error=" . urlencode($error));
        exit;
    }

    // Hemen işle, output'tan önce
    initLogDatabase();
    $db = new SQLite3(SUPERADMIN_DB);
    $db->exec('PRAGMA journal_mode = WAL');
    
    // Reklamlar tablosunu oluştur (eğer yoksa)
    $db->exec("CREATE TABLE IF NOT EXISTS ads (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        image_url TEXT,
        logo_url TEXT,
        call_to_action TEXT DEFAULT 'Keşfet',
        advertiser TEXT NOT NULL,
        rating REAL,
        click_url TEXT,
        status TEXT DEFAULT 'active',
        priority INTEGER DEFAULT 0,
        start_date DATETIME,
        end_date DATETIME,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )");
    
    try {
        $title = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $image_url = ''; // Başlangıçta boş - dosya yükleme veya URL alanından doldurulacak
        $logo_url = ''; // Başlangıçta boş - dosya yükleme veya URL alanından doldurulacak
        $call_to_action = trim($_POST['call_to_action'] ?? 'Keşfet');
        $advertiser = trim($_POST['advertiser'] ?? '');
        $rating = !empty($_POST['rating']) ? floatval($_POST['rating']) : null;
        $click_url = trim($_POST['click_url'] ?? '');
        $status = $_POST['status'] ?? 'active';
        $priority = intval($_POST['priority'] ?? 0);
        $start_date = !empty($_POST['start_date']) ? $_POST['start_date'] : null;
        $end_date = !empty($_POST['end_date']) ? $_POST['end_date'] : null;
        
        // Fotoğraf yükleme işlemi
        $upload_dir = __DIR__ . '/../assets/images/ads/';
        if (!is_dir($upload_dir)) {
            @mkdir($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
            @chmod($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
        } else {
            // Klasör varsa izinleri kontrol et ve düzelt
            if (!is_writable($upload_dir)) {
                @chmod($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
            }
        }
        
        // Reklam görseli yükleme (ÖNCELİKLİ - eğer dosya yüklenirse URL alanını görmezden gel)
        if (!empty($_FILES['ad_image']['name']) && $_FILES['ad_image']['error'] === UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
            $max_size = 5 * 1024 * 1024; // 5MB
            
            $file_type = $_FILES['ad_image']['type'];
            $file_size = $_FILES['ad_image']['size'];
            
            if (!in_array($file_type, $allowed_types)) {
                $error = "Geçersiz dosya formatı! Sadece JPG, PNG, GIF ve WebP formatları desteklenir.";
            } elseif ($file_size > $max_size) {
                $error = "Dosya boyutu çok büyük! Maksimum 5MB olmalıdır.";
            } else {
                // Ekstra MIME type kontrolü (finfo)
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $real_mime = $finfo->file($_FILES['ad_image']['tmp_name']);
                if (!in_array($real_mime, $allowed_types)) {
                    $error = "Geçersiz dosya içeriği! Lütfen geçerli bir resim dosyası yükleyin.";
                } else {
                    $file_ext = pathinfo($_FILES['ad_image']['name'], PATHINFO_EXTENSION);
                    // Uzantıyı sanitize et
                    $file_ext = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $file_ext));
                    $file_name = 'ad_' . time() . '_' . uniqid() . '.' . $file_ext;
                    $file_path = $upload_dir . $file_name;
                    
                    if (move_uploaded_file($_FILES['ad_image']['tmp_name'], $file_path)) {
                        @chmod($file_path, 0644); // Dosya izinlerini ayarla
                        $image_url = '/assets/images/ads/' . $file_name;
                    } else {
                        $last_error = error_get_last();
                        $error = "Fotoğraf yüklenirken bir hata oluştu! Hata: " . ($last_error['message'] ?? 'Bilinmeyen hata');
                    }
                }
            }
        }
        
        // Logo yükleme işlemi
        if (!empty($_FILES['ad_logo']['name']) && $_FILES['ad_logo']['error'] === UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
            $max_size = 2 * 1024 * 1024; // 2MB
            
            $file_type = $_FILES['ad_logo']['type'];
            $file_size = $_FILES['ad_logo']['size'];
            
            if (!in_array($file_type, $allowed_types)) {
                $error = "Geçersiz logo formatı! Sadece JPG, PNG, GIF ve WebP formatları desteklenir.";
            } elseif ($file_size > $max_size) {
                $error = "Logo boyutu çok büyük! Maksimum 2MB olmalıdır.";
            } else {
                // Ekstra MIME type kontrolü (finfo)
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $real_mime = $finfo->file($_FILES['ad_logo']['tmp_name']);
                if (!in_array($real_mime, $allowed_types)) {
                    $error = "Geçersiz logo içeriği! Lütfen geçerli bir resim dosyası yükleyin.";
                } else {
                    $file_ext = pathinfo($_FILES['ad_logo']['name'], PATHINFO_EXTENSION);
                    // Uzantıyı sanitize et
                    $file_ext = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $file_ext));
                    $file_name = 'logo_' . time() . '_' . uniqid() . '.' . $file_ext;
                    $file_path = $upload_dir . $file_name;
                    
                    if (move_uploaded_file($_FILES['ad_logo']['tmp_name'], $file_path)) {
                        @chmod($file_path, 0644); // Dosya izinlerini ayarla
                        $logo_url = '/assets/images/ads/' . $file_name;
                    } else {
                        $last_error = error_get_last();
                        $error = "Logo yüklenirken bir hata oluştu! Hata: " . ($last_error['message'] ?? 'Bilinmeyen hata');
                    }
                }
            }
        } elseif (!empty(trim($_POST['logo_url'] ?? ''))) {
            // Logo dosyası yüklenmediyse ve URL alanı doluysa, URL'i kullan
            $logo_url = trim($_POST['logo_url']);
        }
        
        // Görsel için de aynı mantık (eğer dosya yüklenmediyse)
        if (empty($image_url) && !empty(trim($_POST['image_url'] ?? ''))) {
            // Dosya yüklenmediyse ve URL alanı doluysa, URL'i kullan
            $image_url = trim($_POST['image_url']);
        }
        
        // Validasyon
        if (empty($title)) {
            $error = "Başlık gereklidir!";
        } elseif (empty($description)) {
            $error = "Açıklama gereklidir!";
        } elseif (empty($advertiser)) {
            $error = "Reklamveren adı gereklidir!";
        }
        
        // Eğer hata yoksa veritabanına kaydet
        if (!$error) {
            $stmt = $db->prepare("INSERT INTO ads (title, description, image_url, logo_url, call_to_action, advertiser, rating, click_url, status, priority, start_date, end_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            
            if (!$stmt) {
                $error = "SQL hazırlama hatası: " . $db->lastErrorMsg();
            } else {
                $stmt->bindValue(1, $title, SQLITE3_TEXT);
                $stmt->bindValue(2, $description, SQLITE3_TEXT);
                $stmt->bindValue(3, $image_url ?: null, SQLITE3_TEXT);
                $stmt->bindValue(4, $logo_url ?: null, SQLITE3_TEXT);
                $stmt->bindValue(5, $call_to_action, SQLITE3_TEXT);
                $stmt->bindValue(6, $advertiser, SQLITE3_TEXT);
                if ($rating !== null) {
                    $stmt->bindValue(7, $rating, SQLITE3_REAL);
                } else {
                    $stmt->bindValue(7, null, SQLITE3_NULL);
                }
                $stmt->bindValue(8, $click_url ?: null, SQLITE3_TEXT);
                $stmt->bindValue(9, $status, SQLITE3_TEXT);
                $stmt->bindValue(10, $priority, SQLITE3_INTEGER);
                $stmt->bindValue(11, $start_date ?: null, SQLITE3_TEXT);
                $stmt->bindValue(12, $end_date ?: null, SQLITE3_TEXT);
                
                $result = $stmt->execute();
                if ($result) {
                    logAdminAction('system', 0, 'superadmin', 'ad_created', "Yeni reklam eklendi: $title");
                    $db->close();
                    header("Location: ?view=ads&success=" . urlencode("Reklam başarıyla eklendi!"));
                    exit;
                } else {
                    $error = "Reklam eklenirken bir hata oluştu: " . $db->lastErrorMsg();
                }
            }
        }
        
        // Hata varsa göster
        if ($error) {
            $db->close();
            header("Location: ?view=ads&error=" . urlencode($error));
            exit;
        }
    } catch (Exception $e) {
        $db->close();
        header("Location: ?view=ads&error=" . urlencode("Hata: " . $e->getMessage()));
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && ($_POST['action'] ?? '') === 'verification_admin_update') {
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        header("Location: ?view=verification_admin&error=" . urlencode('Güvenlik hatası: CSRF doğrulanamadı.'));
        exit;
    }

    $communityFolder = preg_replace('/[^a-zA-Z0-9_-]/', '', $_POST['community_folder'] ?? '');
    $requestId = (int)($_POST['request_id'] ?? 0);
    $newStatus = $_POST['new_status'] ?? '';
    $adminNotes = trim($_POST['admin_notes'] ?? '');
    $allowedStatuses = ['pending', 'approved', 'rejected'];

    if ($communityFolder === '' || $requestId <= 0 || !in_array($newStatus, $allowedStatuses, true)) {
        header("Location: ?view=verification_admin&error=" . urlencode('Eksik veya geçersiz veri gönderildi.'));
        exit;
    }

    $dbPath = COMMUNITIES_DIR . $communityFolder . '/unipanel.sqlite';
    if (!file_exists($dbPath)) {
        header("Location: ?view=verification_admin&error=" . urlencode('Topluluk veritabanı bulunamadı.'));
        exit;
    }

    try {
        $db = new SQLite3($dbPath);
        @$db->exec('PRAGMA journal_mode = WAL');
        $tableExists = @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='community_verifications'");
        if (!$tableExists) {
            throw new RuntimeException('Toplulukta doğrulama tablosu bulunamadı.');
        }

        $stmt = $db->prepare("UPDATE community_verifications 
            SET status = :status,
                admin_notes = :notes,
                reviewer_name = :reviewer,
                reviewed_by = 0,
                reviewed_at = CURRENT_TIMESTAMP
            WHERE id = :id");
        $stmt->bindValue(':status', $newStatus, SQLITE3_TEXT);
        $stmt->bindValue(':notes', $adminNotes, SQLITE3_TEXT);
        $stmt->bindValue(':reviewer', 'SuperAdmin', SQLITE3_TEXT);
        $stmt->bindValue(':id', $requestId, SQLITE3_INTEGER);
        $result = $stmt->execute();
        if (!$result) {
            throw new RuntimeException('Durum güncellenemedi.');
        }
        $db->close();

        logAdminAction($communityFolder, 0, 'superadmin', 'verification_update', 'Doğrulama talebi güncellendi', [
            'request_id' => $requestId,
            'status' => $newStatus
        ]);

        $redirectStatus = $newStatus !== '' ? '&status=' . urlencode($newStatus) : '';
        header("Location: ?view=verification_admin{$redirectStatus}&success=" . urlencode('Doğrulama talebi güncellendi.'));
        exit;
    } catch (Exception $e) {
        if (isset($db) && $db instanceof SQLite3) {
            $db->close();
        }
        header("Location: ?view=verification_admin&error=" . urlencode('Hata: ' . $e->getMessage()));
        exit;
    }
}

// Diğer POST işlemleri
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // CSRF Kontrolü
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
        // Hata varsa yönlendir
        header("Location: ?view=ads&error=" . urlencode($error));
        exit;
    }

    initLogDatabase();
    $db = new SQLite3(SUPERADMIN_DB);
    $db->exec('PRAGMA journal_mode = WAL');
    
    if ($_POST['action'] === 'update_ad') {
        $ad_id = intval($_POST['ad_id'] ?? 0);
        $title = trim($_POST['title'] ?? '');
        $description = trim($_POST['description'] ?? '');
        $image_url = ''; // Başlangıçta boş - dosya yükleme veya URL alanından doldurulacak
        $logo_url = ''; // Başlangıçta boş - dosya yükleme veya URL alanından doldurulacak
        $call_to_action = trim($_POST['call_to_action'] ?? 'Keşfet');
        $advertiser = trim($_POST['advertiser'] ?? '');
        $rating = !empty($_POST['rating']) ? floatval($_POST['rating']) : null;
        $click_url = trim($_POST['click_url'] ?? '');
        $status = $_POST['status'] ?? 'active';
        $priority = intval($_POST['priority'] ?? 0);
        $start_date = !empty($_POST['start_date']) ? $_POST['start_date'] : null;
        $end_date = !empty($_POST['end_date']) ? $_POST['end_date'] : null;
        
        // Eski görselleri al (silme için ve mevcut URL'leri korumak için)
        $old_image_url = '';
        $old_logo_url = '';
        $old_stmt = $db->prepare("SELECT image_url, logo_url FROM ads WHERE id = ?");
        $old_stmt->bindValue(1, $ad_id, SQLITE3_INTEGER);
        $old_result = $old_stmt->execute();
        if ($old_row = $old_result->fetchArray(SQLITE3_ASSOC)) {
            $old_image_url = $old_row['image_url'] ?? '';
            $old_logo_url = $old_row['logo_url'] ?? '';
            // Mevcut URL'leri varsayılan olarak kullan (eğer yeni dosya veya URL girilmezse)
            $image_url = $old_image_url;
            $logo_url = $old_logo_url;
        }
        
        // Fotoğraf yükleme işlemi
        $upload_dir = __DIR__ . '/../assets/images/ads/';
        if (!is_dir($upload_dir)) {
            @mkdir($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS, true);
            @chmod($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
        } else {
            // Klasör varsa izinleri kontrol et ve düzelt
            if (!is_writable($upload_dir)) {
                @chmod($upload_dir, SUPERADMIN_PUBLIC_DIR_PERMS);
            }
        }
        
        // Reklam görseli yükleme
        if (!empty($_FILES['ad_image']['name']) && $_FILES['ad_image']['error'] === UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
            $max_size = 5 * 1024 * 1024; // 5MB
            
            $file_type = $_FILES['ad_image']['type'];
            $file_size = $_FILES['ad_image']['size'];
            
            if (!in_array($file_type, $allowed_types)) {
                $error = "Geçersiz dosya formatı! Sadece JPG, PNG, GIF ve WebP formatları desteklenir.";
            } elseif ($file_size > $max_size) {
                $error = "Dosya boyutu çok büyük! Maksimum 5MB olmalıdır.";
            } else {
                // Ekstra MIME type kontrolü (finfo)
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $real_mime = $finfo->file($_FILES['ad_image']['tmp_name']);
                if (!in_array($real_mime, $allowed_types)) {
                    $error = "Geçersiz dosya içeriği! Lütfen geçerli bir resim dosyası yükleyin.";
                } else {
                    $file_ext = pathinfo($_FILES['ad_image']['name'], PATHINFO_EXTENSION);
                    // Uzantıyı sanitize et
                    $file_ext = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $file_ext));
                    $file_name = 'ad_' . time() . '_' . uniqid() . '.' . $file_ext;
                    $file_path = $upload_dir . $file_name;
                    
                    if (move_uploaded_file($_FILES['ad_image']['tmp_name'], $file_path)) {
                        @chmod($file_path, 0644); // Dosya izinlerini ayarla
                        // Eski görseli sil
                        if (!empty($old_image_url) && strpos($old_image_url, '/assets/images/ads/') === 0) {
                            $old_file_path = __DIR__ . '/..' . $old_image_url;
                            if (file_exists($old_file_path)) {
                                @unlink($old_file_path);
                            }
                        }
                        $image_url = '/assets/images/ads/' . $file_name;
                    } else {
                        $last_error = error_get_last();
                        $error = "Fotoğraf yüklenirken bir hata oluştu! Hata: " . ($last_error['message'] ?? 'Bilinmeyen hata');
                    }
                }
            }
        }
        
        // Logo yükleme işlemi
        if (!empty($_FILES['ad_logo']['name']) && $_FILES['ad_logo']['error'] === UPLOAD_ERR_OK) {
            $allowed_types = ['image/jpeg', 'image/jpg', 'image/png', 'image/gif', 'image/webp'];
            $max_size = 2 * 1024 * 1024; // 2MB
            
            $file_type = $_FILES['ad_logo']['type'];
            $file_size = $_FILES['ad_logo']['size'];
            
            if (!in_array($file_type, $allowed_types)) {
                $error = "Geçersiz logo formatı! Sadece JPG, PNG, GIF ve WebP formatları desteklenir.";
            } elseif ($file_size > $max_size) {
                $error = "Logo boyutu çok büyük! Maksimum 2MB olmalıdır.";
            } else {
                // Ekstra MIME type kontrolü (finfo)
                $finfo = new finfo(FILEINFO_MIME_TYPE);
                $real_mime = $finfo->file($_FILES['ad_logo']['tmp_name']);
                if (!in_array($real_mime, $allowed_types)) {
                    $error = "Geçersiz logo içeriği! Lütfen geçerli bir resim dosyası yükleyin.";
                } else {
                    $file_ext = pathinfo($_FILES['ad_logo']['name'], PATHINFO_EXTENSION);
                    // Uzantıyı sanitize et
                    $file_ext = strtolower(preg_replace('/[^a-zA-Z0-9]/', '', $file_ext));
                    $file_name = 'logo_' . time() . '_' . uniqid() . '.' . $file_ext;
                    $file_path = $upload_dir . $file_name;
                    
                    if (move_uploaded_file($_FILES['ad_logo']['tmp_name'], $file_path)) {
                        @chmod($file_path, 0644); // Dosya izinlerini ayarla
                        // Eski logoyu sil
                        if (!empty($old_logo_url) && strpos($old_logo_url, '/assets/images/ads/') === 0) {
                            $old_file_path = __DIR__ . '/..' . $old_logo_url;
                            if (file_exists($old_file_path)) {
                                @unlink($old_file_path);
                            }
                        }
                        $logo_url = '/assets/images/ads/' . $file_name;
                    } else {
                        $error = "Logo yüklenirken bir hata oluştu! Hata: " . (error_get_last()['message'] ?? 'Bilinmeyen hata');
                    }
                }
            }
        } elseif (!empty(trim($_POST['logo_url'] ?? ''))) {
            // Logo dosyası yüklenmediyse ve URL alanı doluysa, URL'i kullan
            $logo_url = trim($_POST['logo_url']);
        }
        
        // Görsel için de aynı mantık (eğer dosya yüklenmediyse)
        if (empty($image_url) || (!empty($_FILES['ad_image']['name']) && $_FILES['ad_image']['error'] === UPLOAD_ERR_OK)) {
            // Görsel zaten yüklendi veya yükleniyor, değiştirme
        } elseif (!empty(trim($_POST['image_url'] ?? ''))) {
            // Dosya yüklenmediyse ve URL alanı doluysa, URL'i kullan
            $image_url = trim($_POST['image_url']);
        }
        
        if (empty($title) || empty($description) || empty($advertiser)) {
            $error = "Başlık, açıklama ve reklamveren adı gereklidir!";
        } elseif (!isset($error)) {
            $stmt = $db->prepare("UPDATE ads SET title = ?, description = ?, image_url = ?, logo_url = ?, call_to_action = ?, advertiser = ?, rating = ?, click_url = ?, status = ?, priority = ?, start_date = ?, end_date = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?");
            $stmt->bindValue(1, $title, SQLITE3_TEXT);
            $stmt->bindValue(2, $description, SQLITE3_TEXT);
            $stmt->bindValue(3, $image_url ?: null, SQLITE3_TEXT);
            $stmt->bindValue(4, $logo_url ?: null, SQLITE3_TEXT);
            $stmt->bindValue(5, $call_to_action, SQLITE3_TEXT);
            $stmt->bindValue(6, $advertiser, SQLITE3_TEXT);
            $stmt->bindValue(7, $rating, SQLITE3_REAL);
            $stmt->bindValue(8, $click_url ?: null, SQLITE3_TEXT);
            $stmt->bindValue(9, $status, SQLITE3_TEXT);
            $stmt->bindValue(10, $priority, SQLITE3_INTEGER);
            $stmt->bindValue(11, $start_date ?: null, SQLITE3_TEXT);
            $stmt->bindValue(12, $end_date ?: null, SQLITE3_TEXT);
            $stmt->bindValue(13, $ad_id, SQLITE3_INTEGER);
            $stmt->execute();
            
            logAdminAction('system', 0, 'superadmin', 'ad_updated', "Reklam güncellendi: $title");
            $success = "Reklam başarıyla güncellendi!";
            header("Location: ?view=ads&success=" . urlencode($success));
            exit;
        }
    } elseif ($_POST['action'] === 'delete_ad') {
        $ad_id = intval($_POST['ad_id'] ?? 0);
        if ($ad_id > 0) {
            $stmt = $db->prepare("SELECT title FROM ads WHERE id = ?");
            $stmt->bindValue(1, $ad_id, SQLITE3_INTEGER);
            $result = $stmt->execute();
            $ad = $result->fetchArray(SQLITE3_ASSOC);
            
            $stmt = $db->prepare("DELETE FROM ads WHERE id = ?");
            $stmt->bindValue(1, $ad_id, SQLITE3_INTEGER);
            $stmt->execute();
            
            logAdminAction('system', 0, 'superadmin', 'ad_deleted', "Reklam silindi: " . ($ad['title'] ?? 'ID: ' . $ad_id));
            $success = "Reklam başarıyla silindi!";
            header("Location: ?view=ads&success=" . urlencode($success));
            exit;
        }
    }
    $db->close();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'reject_request') {
    $request_id = intval($_POST['request_id'] ?? 0);
    $reject_reason = trim($_POST['reject_reason'] ?? '');
    
    if ($request_id <= 0) {
        $error = "Geçersiz talep ID!";
    } else {
        initLogDatabase();
        $db = new SQLite3(SUPERADMIN_DB);
        $db->exec('PRAGMA journal_mode = WAL');
        
        // Önce folder_name'i al
        $get_stmt = $db->prepare("SELECT folder_name FROM community_requests WHERE id = ?");
        $get_stmt->bindValue(1, $request_id, SQLITE3_INTEGER);
        $result = $get_stmt->execute();
        $request_data = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($request_data) {
            $folder_name = $request_data['folder_name'];
            
            // Topluluk klasörünü sil
            $community_path = COMMUNITIES_DIR . $folder_name;
            if (is_dir($community_path)) {
                // Klasörü ve içindeki tüm dosyaları sil (recursive)
                $deleteDir = function($dir) use (&$deleteDir) {
                    if (!is_dir($dir)) {
                        return false;
                    }
                    $files = array_diff(scandir($dir), array('.', '..'));
                    foreach ($files as $file) {
                        $path = $dir . '/' . $file;
                        if (is_dir($path)) {
                            $deleteDir($path);
                        } else {
                            @unlink($path);
                        }
                    }
                    return @rmdir($dir);
                };
                
                $deleteDir($community_path);
            }
        }
        
        // Veritabanında durumu güncelle
        $stmt = $db->prepare("UPDATE community_requests SET status = 'rejected', admin_notes = ?, processed_at = CURRENT_TIMESTAMP, processed_by = ? WHERE id = ?");
        $stmt->bindValue(1, $reject_reason, SQLITE3_TEXT);
        $stmt->bindValue(2, 'superadmin', SQLITE3_TEXT);
        $stmt->bindValue(3, $request_id, SQLITE3_INTEGER);
        $stmt->execute();
        
        $db->close();
        $success = "Topluluk talebi reddedildi ve klasör silindi!";
    }
}

// Plan atama işlemi
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'assign_plan') {
    require_once __DIR__ . '/../lib/payment/SubscriptionManager.php';
    
    $community_folder = trim($_POST['community_folder'] ?? '');
    $plan_tier = trim($_POST['plan_tier'] ?? 'standard');
    $months = intval($_POST['months'] ?? 12);
    
    if (empty($community_folder)) {
        $error = "Topluluk klasörü belirtilmedi!";
    } elseif (!in_array($plan_tier, ['standard', 'professional', 'business'])) {
        $error = "Geçersiz plan seçimi!";
    } elseif ($months < 1 || $months > 120) {
        $error = "Geçersiz ay sayısı! (1-120 arası olmalı)";
    } else {
        $community_path = COMMUNITIES_DIR . $community_folder;
        $db_path = $community_path . '/unipanel.sqlite';
        
        if (!is_dir($community_path)) {
            $error = "Topluluk klasörü bulunamadı!";
        } elseif (!file_exists($db_path)) {
            $error = "Topluluk veritabanı bulunamadı!";
        } else {
            try {
                $db = new SQLite3($db_path);
                $db->exec('PRAGMA journal_mode = WAL');
                
                // SubscriptionManager'ı başlat
                $subscriptionManager = new \UniPanel\Payment\SubscriptionManager($db, $community_folder);
                $subscriptionManager->createSubscriptionTable(); // Tabloyu oluştur/güncelle
                
                // Mevcut aboneliği kontrol et
                $current_subscription = $subscriptionManager->getSubscription();
                
                // Plan fiyatlarını hesapla
                $amount = 0;
                if ($plan_tier === 'professional') {
                    $amount = 250.00 * $months; // 250 TL/ay
                } elseif ($plan_tier === 'business') {
                    $amount = 500.00 * $months; // 500 TL/ay
                }
                
                // Abonelik oluştur veya güncelle (superadmin tarafından atandığı için payment_id özel)
                $payment_id = 'SUPERADMIN-ASSIGN-' . $community_folder . '-' . time();
                
                if ($current_subscription && isset($current_subscription['id'])) {
                    // Mevcut aboneliği güncelle
                    $subscription_id = $subscriptionManager->updateSubscriptionPlan(
                        $current_subscription['id'],
                        $plan_tier,
                        $months,
                        $amount
                    );
                } else {
                    // Yeni abonelik oluştur
                    $subscription_id = $subscriptionManager->createSubscription(
                        $payment_id,
                        'success', // Direkt aktif
                        $months,
                        $amount,
                        $plan_tier
                    );
                }
                
                $db->close();
                
                logAdminAction('system', 0, 'superadmin', 'plan_assigned', "Plan atandı: {$plan_tier} ({$months} ay) - Topluluk: {$community_folder}");
                $success = "Plan başarıyla atandı! ({$plan_tier} - {$months} ay)";
                
            } catch (Exception $e) {
                $error = "Plan atama hatası: " . $e->getMessage();
                error_log("Plan assignment error: " . $e->getMessage());
            }
        }
    }
}

// SMS Paketi tahsis işlemi
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'assign_sms_package') {
    require_once __DIR__ . '/../lib/payment/SubscriptionManager.php';
    
    $community_folder = trim($_POST['community_folder'] ?? '');
    $sms_credits = intval($_POST['sms_package'] ?? 0);
    $notes = trim($_POST['notes'] ?? '');
    
    if (empty($community_folder)) {
        $error = "Topluluk klasörü belirtilmedi!";
    } elseif ($sms_credits <= 0) {
        $error = "Geçersiz SMS paketi seçimi!";
    } else {
        $community_path = COMMUNITIES_DIR . $community_folder;
        $db_path = $community_path . '/unipanel.sqlite';
        
        if (!is_dir($community_path)) {
            $error = "Topluluk klasörü bulunamadı!";
        } elseif (!file_exists($db_path)) {
            $error = "Topluluk veritabanı bulunamadı!";
        } else {
            try {
                $db = getSQLite3Connection($db_path);
                
                // SubscriptionManager'ı başlat
                $subscriptionManager = new \UniPanel\Payment\SubscriptionManager($db, $community_folder);
                $subscriptionManager->createSubscriptionTable(); // Tabloyu oluştur/güncelle
                
                // Paket adını belirle
                $packageName = number_format($sms_credits, 0, ',', '.') . ' SMS Paketi';
                
                // SMS kredilerini ekle
                $result = $subscriptionManager->addSmsCredits(
                    $sms_credits,
                    $packageName,
                    'superadmin',
                    $notes
                );
                
                if ($result) {
                    logAdminAction('system', 0, 'superadmin', 'sms_package_assigned', "SMS paketi tahsis edildi: {$sms_credits} SMS - Topluluk: {$community_folder}");
                    $success = "SMS paketi başarıyla tahsis edildi! ({$packageName})";
                } else {
                    $error = "SMS paketi tahsis edilirken bir hata oluştu!";
                }
                
                $db->close();
                
            } catch (Exception $e) {
                $error = "SMS paketi tahsis hatası: " . $e->getMessage();
                error_log("SMS package assignment error: " . $e->getMessage());
            }
        }
    }
}

// Topluluk düzenleme (AJAX için JSON response)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'edit' && isset($_POST['ajax'])) {
    header('Content-Type: application/json');
    
    $folder = $_POST['folder'] ?? '';
    $new_name = trim($_POST['new_name'] ?? '');
    $new_admin = trim($_POST['new_admin'] ?? '');
    $new_password = trim($_POST['new_password'] ?? '');
    $new_code = trim(strtoupper($_POST['new_code'] ?? ''));
    $new_university = trim($_POST['new_university'] ?? '');
    $new_folder = trim($_POST['new_folder'] ?? '');
    
    $response = ['success' => false, 'message' => ''];
    
    // Debug log (sadece development için)
    error_log("Edit request - folder: $folder, name: $new_name, code: $new_code, university: $new_university");
    
    if (empty($new_name)) {
        $response['message'] = "Topluluk adı boş olamaz!";
        echo json_encode($response);
        exit;
    } elseif (empty($new_code)) {
        $response['message'] = "Topluluk kodu boş olamaz!";
        echo json_encode($response);
        exit;
    } elseif (empty($new_university)) {
        $response['message'] = "Üniversite seçilmelidir!";
        echo json_encode($response);
        exit;
    } elseif (empty($folder)) {
        $response['message'] = "Topluluk klasörü belirtilmedi!";
        echo json_encode($response);
        exit;
    } else {
        $community_path = COMMUNITIES_DIR . $folder;
        if (is_dir($community_path)) {
            $db_path = $community_path . '/unipanel.sqlite';
            if (file_exists($db_path)) {
                try {
                    $db = new SQLite3($db_path);
                    
                    // Topluluk adını güncelle
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'club_name', ?)");
                    $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                    $stmt->execute();
                    
                    // Mevcut kodu kontrol et
                    $current_code = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'");
                    
                    // Topluluk kodunu güncelle (aynı üniversitede benzersizlik kontrolü ile)
                    // Eğer kod değişmemişse, çakışma kontrolü yapma
                    $code_changed = ($current_code !== $new_code);
                    $code_exists = false;
                    
                    if ($code_changed) {
                        // Kod değişmişse, çakışma kontrolü yap
                        if (is_dir(COMMUNITIES_DIR)) {
                            $dirs = scandir(COMMUNITIES_DIR);
                            foreach ($dirs as $dir) {
                                if ($dir === '.' || $dir === '..' || $dir === $folder) continue; // Kendi klasörünü atla
                                $check_db_path = COMMUNITIES_DIR . $dir . '/unipanel.sqlite';
                                if (file_exists($check_db_path)) {
                                    try {
                                        $check_db = new SQLite3($check_db_path);
                                        $existing_university = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'university'");
                                        $existing_code = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'");
                                        $check_db->close();
                                        
                                        // Sadece aynı üniversitede aynı kod varsa çakışma var
                                        if ($existing_university === $new_university && $existing_code === $new_code) {
                                            $code_exists = true;
                                            break;
                                        }
                                    } catch (Exception $e) {
                                        // Hata durumunda devam et
                                    }
                                }
                            }
                        }
                    }
                    
                    if ($code_exists) {
                        $response['message'] = "Bu kod aynı üniversitede zaten kullanılıyor!";
                        $db->close();
                        echo json_encode($response);
                        exit;
                    }
                    
                    // Kod güncelle
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'community_code', ?)");
                    $stmt->bindValue(1, $new_code, SQLITE3_TEXT);
                    $stmt->execute();
                    
                    // Üniversite güncelle
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'university', ?)");
                    $stmt->bindValue(1, $new_university, SQLITE3_TEXT);
                    $stmt->execute();
                    
                    // Admin bilgilerini güncelle (sadece doldurulmuşsa)
                    if (!empty($new_admin) || !empty($new_password)) {
                        // Mevcut admin bilgilerini al
                        $current_admin = $db->querySingle("SELECT username FROM admins WHERE club_id = 1", true);
                        $current_username = $current_admin['username'] ?? '';
                        
                        // Kullanıcı adı değiştirilmişse veya şifre değiştirilmişse güncelle
                        $update_username = !empty($new_admin) ? $new_admin : $current_username;
                        
                        if (!empty($new_password)) {
                            // Hem kullanıcı adı hem şifre güncelleniyor
                            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                            $stmt = $db->prepare("UPDATE admins SET username = ?, password_hash = ? WHERE club_id = 1");
                            $stmt->bindValue(1, $update_username, SQLITE3_TEXT);
                            $stmt->bindValue(2, $hashed_password, SQLITE3_TEXT);
                            $stmt->execute();
                        } elseif (!empty($new_admin)) {
                            // Sadece kullanıcı adı güncelleniyor
                            $stmt = $db->prepare("UPDATE admins SET username = ? WHERE club_id = 1");
                            $stmt->bindValue(1, $update_username, SQLITE3_TEXT);
                            $stmt->execute();
                        }
                    }
                    
                    // Klasör adını değiştir (eğer değiştirilmişse)
                    if (!empty($new_folder) && $new_folder !== $folder) {
                        $new_folder = strtolower(preg_replace('/[^a-zA-Z0-9_]/', '_', $new_folder));
                        $new_community_path = COMMUNITIES_DIR . $new_folder;
                        
                        if (!is_dir($new_community_path)) {
                            if (@rename($community_path, $new_community_path)) {
                                $folder = $new_folder; // Başarılı olursa yeni klasör adını kullan
                            } else {
                                $response['message'] = "Klasör adı değiştirilemedi. İzin sorunu olabilir.";
                                $db->close();
                                echo json_encode($response);
                                exit;
                            }
                        } else {
                            $response['message'] = "Bu klasör adı zaten kullanılıyor!";
                            $db->close();
                            echo json_encode($response);
                            exit;
                        }
                    }
                    
                    $db->close();
                    $response['success'] = true;
                    $response['message'] = "Topluluk başarıyla güncellendi!";
                    error_log("Edit success - folder: $folder");
                    echo json_encode($response);
                    exit;
                } catch (Exception $e) {
                    $response['message'] = "Veritabanı hatası: " . $e->getMessage();
                    error_log("Edit DB error: " . $e->getMessage());
                    echo json_encode($response);
                    exit;
                }
            } else {
                $response['message'] = "Topluluk veritabanı bulunamadı!";
                error_log("Edit error - DB not found: $db_path");
                echo json_encode($response);
                exit;
            }
        } else {
            $response['message'] = "Topluluk klasörü bulunamadı! Klasör: " . htmlspecialchars($folder);
            error_log("Edit error - Folder not found: $community_path");
            echo json_encode($response);
            exit;
        }
    }
}

// Topluluk düzenleme (Normal form submit - eski kod, geriye dönük uyumluluk için)
if ($_SERVER['REQUEST_METHOD'] === 'POST' && $action === 'edit' && !isset($_POST['ajax'])) {
    $folder = $_POST['folder'] ?? '';
    $new_name = trim($_POST['new_name'] ?? '');
    $new_admin = trim($_POST['new_admin'] ?? '');
    $new_password = trim($_POST['new_password'] ?? '');
    $new_code = trim(strtoupper($_POST['new_code'] ?? ''));
    $new_university = trim($_POST['new_university'] ?? '');
    $new_folder = trim($_POST['new_folder'] ?? '');
    
    if (empty($new_name)) {
        $error = "Topluluk adı boş olamaz!";
    } elseif (empty($new_code)) {
        $error = "Topluluk kodu boş olamaz!";
    } elseif (empty($new_university)) {
        $error = "Üniversite seçilmelidir!";
    } else {
        $community_path = COMMUNITIES_DIR . $folder;
        if (is_dir($community_path)) {
            $db_path = $community_path . '/unipanel.sqlite';
            if (file_exists($db_path)) {
                $db = new SQLite3($db_path);
                
                // Topluluk adını güncelle
                $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'club_name', ?)");
                $stmt->bindValue(1, $new_name, SQLITE3_TEXT);
                $stmt->execute();
                
                // Mevcut kodu kontrol et
                $current_code = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'");
                
                // Topluluk kodunu güncelle (aynı üniversitede benzersizlik kontrolü ile)
                // Eğer kod değişmemişse, çakışma kontrolü yapma
                $code_changed = ($current_code !== $new_code);
                $code_exists = false;
                
                if ($code_changed) {
                    // Kod değişmişse, çakışma kontrolü yap
                    if (is_dir(COMMUNITIES_DIR)) {
                        $dirs = scandir(COMMUNITIES_DIR);
                        foreach ($dirs as $dir) {
                            if ($dir === '.' || $dir === '..' || $dir === $folder) continue;
                            $check_db_path = COMMUNITIES_DIR . $dir . '/unipanel.sqlite';
                            if (file_exists($check_db_path)) {
                                try {
                                    $check_db = new SQLite3($check_db_path);
                                    $existing_university = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'university'");
                                    $existing_code = $check_db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'");
                                    $check_db->close();
                                    
                                    if ($existing_university === $new_university && $existing_code === $new_code) {
                                        $code_exists = true;
                                        break;
                                    }
                                } catch (Exception $e) {
                                    continue;
                                }
                            }
                        }
                    }
                }
                
                if ($code_exists) {
                    $error = "Bu kod aynı üniversitede zaten kullanılıyor!";
                } else {
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'community_code', ?)");
                    $stmt->bindValue(1, $new_code, SQLITE3_TEXT);
                    $stmt->execute();
                    
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'university', ?)");
                    $stmt->bindValue(1, $new_university, SQLITE3_TEXT);
                    $stmt->execute();
                    
                    if (!empty($new_admin) || !empty($new_password)) {
                        $current_admin = $db->querySingle("SELECT username FROM admins WHERE club_id = 1", true);
                        $current_username = $current_admin['username'] ?? '';
                        $update_username = !empty($new_admin) ? $new_admin : $current_username;
                        
                        if (!empty($new_password)) {
                            $hashed_password = password_hash($new_password, PASSWORD_DEFAULT);
                            $stmt = $db->prepare("UPDATE admins SET username = ?, password_hash = ? WHERE club_id = 1");
                            $stmt->bindValue(1, $update_username, SQLITE3_TEXT);
                            $stmt->bindValue(2, $hashed_password, SQLITE3_TEXT);
                            $stmt->execute();
                        } elseif (!empty($new_admin)) {
                            $stmt = $db->prepare("UPDATE admins SET username = ? WHERE club_id = 1");
                            $stmt->bindValue(1, $update_username, SQLITE3_TEXT);
                            $stmt->execute();
                        }
                    }
                    
                    if (!empty($new_folder) && $new_folder !== $folder) {
                        $new_folder = strtolower(preg_replace('/[^a-zA-Z0-9_]/', '_', $new_folder));
                        $new_community_path = COMMUNITIES_DIR . $new_folder;
                        
                        if (!is_dir($new_community_path)) {
                            if (@rename($community_path, $new_community_path)) {
                                $folder = $new_folder;
                            } else {
                                $error = "Klasör adı değiştirilemedi. İzin sorunu olabilir.";
                            }
                        } else {
                            $error = "Bu klasör adı zaten kullanılıyor!";
                        }
                    }
                    
                    $db->close();
                    if (empty($error)) {
                        $success = "Topluluk başarıyla güncellendi!";
                    }
                }
            }
        }
    }
}

// Hassas işlemler için POST Handler
// Topluluk adı doğrulama (Path Traversal Koruması)
function isValidCommunityName($name) {
    if (empty($name) || !is_string($name)) {
        return false;
    }
    // Sadece harf, rakam, alt çizgi ve tireye izin ver
    // Nokta (.), slash (/) ve ters slash (\) karakterlerini kesinlikle yasakla
    return preg_match('/^[a-zA-Z0-9_-]+$/', $name);
}

if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    // CSRF Kontrolü (Eğer önceki bloklarda yapılmadıysa)
    if (!verify_csrf_token($_POST['csrf_token'] ?? '')) {
        // AJAX isteği ise JSON dön
        if (!empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) == 'xmlhttprequest') {
            header('Content-Type: application/json');
            echo json_encode(['success' => false, 'message' => 'Güvenlik hatası: CSRF token geçersiz!']);
            exit;
        }
        $error = "Güvenlik hatası: Geçersiz form isteği (CSRF).";
    } else {
        // Kullanıcı banlama
        if ($_POST['action'] === 'ban_user') {
            $community = $_POST['community'] ?? '';
            $user_id = $_POST['user_id'] ?? '';
            $reason = $_POST['reason'] ?? 'Yönetim kararı';
            
            if ($community && $user_id) {
                if (!isValidCommunityName($community)) {
                    $error = "Geçersiz topluluk adı!";
                } else {
                    $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                    if (file_exists($db_path)) {
                        $db = new SQLite3($db_path);
                        $stmt = $db->prepare("UPDATE members SET is_banned = 1, ban_reason = ? WHERE id = ?");
                        $stmt->bindValue(1, $reason, SQLITE3_TEXT);
                        $stmt->bindValue(2, $user_id, SQLITE3_INTEGER);
                        $stmt->execute();
                        $db->close();
                        $success = "Kullanıcı başarıyla banlandı!";
                    }
                }
            }
        }

        // Kullanıcı ban kaldırma
        elseif ($_POST['action'] === 'unban_user') {
            $community = $_POST['community'] ?? '';
            $user_id = $_POST['user_id'] ?? '';
            
            if ($community && $user_id) {
                if (!isValidCommunityName($community)) {
                    $error = "Geçersiz topluluk adı!";
                } else {
                    $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                    if (file_exists($db_path)) {
                        $db = new SQLite3($db_path);
                        $stmt = $db->prepare("UPDATE members SET is_banned = 0, ban_reason = NULL WHERE id = ?");
                        $stmt->bindValue(1, $user_id, SQLITE3_INTEGER);
                        $stmt->execute();
                        $db->close();
                        $success = "Kullanıcının banı kaldırıldı!";
                    }
                }
            }
        }

        // Topluluk kapatma
        elseif ($_POST['action'] === 'disable_community') {
            $community = $_POST['community'] ?? '';
            
            if (!isValidCommunityName($community)) {
                $error = "Geçersiz topluluk adı!";
            } else {
                $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                
                if (file_exists($db_path)) {
                    try {
                        $db = new SQLite3($db_path);
                        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'status', 'disabled')");
                        $stmt->execute();
                        $db->close();
                        $success = "Topluluk başarıyla kapatıldı!";
                    } catch (Exception $e) {
                        $error = "Topluluk kapatma işlemi başarısız: " . $e->getMessage();
                    }
                }
            }
        }

        // Topluluk açma
        elseif ($_POST['action'] === 'enable_community') {
            $community = $_POST['community'] ?? '';
            
            if (!isValidCommunityName($community)) {
                $error = "Geçersiz topluluk adı!";
            } else {
                $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                
                if (file_exists($db_path)) {
                    try {
                        $db = new SQLite3($db_path);
                        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'status', 'active')");
                        $stmt->execute();
                        $db->close();
                        $success = "Topluluk başarıyla açıldı!";
                    } catch (Exception $e) {
                        $error = "Topluluk açma işlemi başarısız: " . $e->getMessage();
                    }
                }
            }
        }

        // Topluluk silme
        elseif ($_POST['action'] === 'delete') {
            $folder = $_POST['folder'] ?? '';
            if ($folder) {
                if (!isValidCommunityName($folder)) {
                    $error = "Geçersiz klasör adı! (Path Traversal girişimi engellendi)";
                } else {
                    $community_path = COMMUNITIES_DIR . $folder;
                    
                    if (is_dir($community_path)) {
                        try {
                            if (safeDeleteDirectory($community_path)) {
                                $success = "Topluluk ve klasörü başarıyla silindi!";
                            } else {
                                $error = "Topluluk klasörü silinemedi. İzin hatası!";
                            }
                        } catch (Exception $e) {
                            $error = "Topluluk silinirken hata: " . $e->getMessage();
                        }
                    } else {
                        $error = "Topluluk klasörü bulunamadı!";
                    }
                }
            }
        }
    }
}

// Otomatik login
if ($action === 'auto_login' && isset($_GET['community'])) {
    if (!superadmin_env_flag_enabled('ENABLE_SUPERADMIN_AUTO_LOGIN')) {
        http_response_code(403);
        $error = "Otomatik giriş özelliği devre dışı.";
    } else {
        $token = $_GET['token'] ?? '';
        $expectedToken = superadmin_expected_token();
        if (!$expectedToken || !hash_equals($expectedToken, (string)$token)) {
            http_response_code(403);
            $error = "Geçersiz veya eksik güvenlik belirteci.";
        } else {
            $community = $_GET['community'];
            
            if (!isValidCommunityName($community)) {
                $error = "Geçersiz topluluk adı!";
            } else {
                $community_path = COMMUNITIES_DIR . $community;
                
                if (is_dir($community_path)) {
                    // Template dosyasını güncelle
                    $template_path = realpath('../templates/template_index.php');
                    $target_path = $community_path . '/index.php';
                    
                    if (file_exists($template_path)) {
                        // İzinleri düzelt
                        if (file_exists($target_path)) {
                            chmod($target_path, SUPERADMIN_FILE_PERMS);
                        }
                        copy($template_path, $target_path);
                    }
                    
                    header("Location: ../communities/{$community}/index.php?superadmin_login=" . urlencode($expectedToken));
                    exit;
                }
            }
        }
    }
}

// Şifresiz otomatik erişim
if ($action === 'auto_access' && isset($_GET['community'])) {
    if (!superadmin_env_flag_enabled('ENABLE_SUPERADMIN_AUTO_ACCESS')) {
        http_response_code(403);
        $error = "Şifresiz erişim devre dışı.";
    } else {
        $token = $_GET['token'] ?? '';
        $expectedToken = superadmin_expected_token();
        if (!$expectedToken || !hash_equals($expectedToken, (string)$token)) {
            http_response_code(403);
            $error = "Geçersiz veya eksik güvenlik belirteci.";
        } else {
            $community = $_GET['community'];
            
            if (!isValidCommunityName($community)) {
                $error = "Geçersiz topluluk adı!";
            } else {
                $community_path = COMMUNITIES_DIR . $community;
                
                if (is_dir($community_path)) {
                    // Topluluk login sayfasına şifresiz erişim ile yönlendir
                    header("Location: ../communities/{$community}/login.php?auto_access=true&superadmin_login=" . urlencode($expectedToken));
                    exit;
                } else {
                    $error = "Topluluk bulunamadı!";
                }
            }
        }
    }
}

// Güvenli klasör silme fonksiyonu
function safeDeleteDirectory($dir) {
    if (!is_dir($dir)) {
        return false;
    }

    $iterator = new RecursiveIteratorIterator(
        new RecursiveDirectoryIterator($dir, RecursiveDirectoryIterator::SKIP_DOTS),
        RecursiveIteratorIterator::CHILD_FIRST
    );

    foreach ($iterator as $file) {
        $path = $file->getRealPath();
        if ($file->isDir()) {
            @chmod($path, SUPERADMIN_DIR_PERMS);
            if (!@rmdir($path)) {
                return false;
            }
        } else {
            @chmod($path, SUPERADMIN_FILE_PERMS);
            if (!@unlink($path)) {
                return false;
            }
        }
    }

    @chmod($dir, SUPERADMIN_DIR_PERMS);
    return @rmdir($dir);
}

// PERFORMANS: Cache mekanizması
$cache_file = __DIR__ . '/../system/cache/communities_list.cache';
$cache_duration = 300; // 5 dakika cache
$use_cache = true;

// Cache temizleme fonksiyonu
function clearCommunitiesCache() {
    $cache_file = __DIR__ . '/../system/cache/communities_list.cache';
    
    try {
        // communities_list.cache dosyasını temizle
        if (file_exists($cache_file)) {
            @unlink($cache_file);
        }
        
        // Public index cache'lerini temizle
        require_once __DIR__ . '/../lib/core/Cache.php';
        $cache = \UniPanel\Core\Cache::getInstance(__DIR__ . '/../system/cache');
        $cache->delete('all_communities_list_v2');
        $cache->delete('all_communities_list_v3');
        
        // Pattern ile tüm ilgili cache'leri temizle
        $cacheFiles = glob(__DIR__ . '/../system/cache/all_communities_list_*.cache');
        foreach ($cacheFiles as $cacheFile) {
            @unlink($cacheFile);
        }
        
        return true;
    } catch (Exception $e) {
        error_log("Cache temizleme hatası: " . $e->getMessage());
        return false;
    }
}

// Cache kontrolü
$communities = [];
$community_details = [];

if ($use_cache && file_exists($cache_file) && (time() - filemtime($cache_file)) < $cache_duration) {
    // Cache'den oku
    $cached_data = @json_decode(file_get_contents($cache_file), true);
    if ($cached_data && isset($cached_data['communities']) && isset($cached_data['details'])) {
        $communities = $cached_data['communities'];
        $community_details = $cached_data['details'];
    }
}

// Cache yoksa veya süresi dolmuşsa veritabanından çek
if (empty($communities) && is_dir(COMMUNITIES_DIR)) {
    $dirs = scandir(COMMUNITIES_DIR);
    $processed = 0;
    $max_per_request = 100; // Her istekte max 100 topluluk işle
    
    foreach ($dirs as $dir) {
        if ($processed >= $max_per_request) {
            break; // Limit aşıldı, dur
        }
        // Sistem klasörlerini ve geçersiz klasörleri filtrele
        $excluded_dirs = ['.', '..', 'assets', 'templates', 'system', 'docs'];
        if (!in_array($dir, $excluded_dirs) && is_dir(COMMUNITIES_DIR . $dir)) {
            $communities[] = $dir;
            
            // Topluluk detaylarını al
            $db_path = COMMUNITIES_DIR . $dir . '/unipanel.sqlite';
            if (file_exists($db_path)) {
                try {
                    // Veritabanı dosyasının yazma izinlerini kontrol et ve düzelt
                    if (!is_writable($db_path)) {
                        @chmod($db_path, SUPERADMIN_FILE_PERMS);
                    }
                    // Klasörün de yazılabilir olduğundan emin ol
                    $db_dir = dirname($db_path);
                    if (!is_writable($db_dir)) {
                        @chmod($db_dir, SUPERADMIN_DIR_PERMS);
                    }
                    
                    $db = getSQLite3Connection($db_path);
                    if (!$db) {
                        // Bağlantı kurulamazsa bu topluluğu atla
                        continue;
                    }
                    $db_is_writable = is_writable($db_path);
                    if (!$db_is_writable) {
                        @$db->exec('PRAGMA query_only = 1');
                    }
                    
                    // Eksik sütunları ekle - önce tablo varlığını kontrol et
                    $members_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='members'");
                    if ($members_table_exists) {
                        $members_columns = $db->query("PRAGMA table_info(members)");
                        $existing_columns = [];
                        while ($row = $members_columns->fetchArray(SQLITE3_ASSOC)) {
                            $existing_columns[] = $row['name'];
                        }
                        
                        if ($db_is_writable && !in_array('is_banned', $existing_columns)) {
                            @$db->exec("ALTER TABLE members ADD COLUMN is_banned INTEGER DEFAULT 0");
                        }
                        
                        if ($db_is_writable && !in_array('ban_reason', $existing_columns)) {
                            @$db->exec("ALTER TABLE members ADD COLUMN ban_reason TEXT");
                        }
                    }
                    
                    // Admins tablosu varsa sütunları ekle
                    $admin_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='admins'");
                    if ($admin_table_exists) {
                        $admins_columns = $db->query("PRAGMA table_info(admins)");
                        $existing_admin_columns = [];
                        while ($row = $admins_columns->fetchArray(SQLITE3_ASSOC)) {
                            $existing_admin_columns[] = $row['name'];
                        }
                        
                        if (!in_array('is_banned', $existing_admin_columns)) {
                        $db->exec("ALTER TABLE admins ADD COLUMN is_banned INTEGER DEFAULT 0");
                        }
                        
                        if (!in_array('created_at', $existing_admin_columns)) {
                            $db->exec("ALTER TABLE admins ADD COLUMN created_at TEXT DEFAULT CURRENT_TIMESTAMP");
                        }
                    }
                    
                    // Tablo varlık kontrolleri ile veri çek
                    $club_name = '';
                    $status = 'active';
                    $member_count = 0;
                    $event_count = 0;
                    $banned_count = 0;
                    
                    $settings_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
                    if ($settings_table_exists) {
                        $club_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'club_name'") ?: '';
                        $status = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'status'") ?: 'active';
                        $community_code = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'community_code'") ?: '';
                        $university = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'university'") ?: '';
                    }
                    
                    $members_table_exists = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='members'");
                    if ($members_table_exists) {
                        $member_count = $db->querySingle("SELECT COUNT(*) FROM members") ?: 0;
                        $banned_count = $db->querySingle("SELECT COUNT(*) FROM members WHERE is_banned = 1") ?: 0;
                    }
                    
                    $events_table_exists = $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='events'");
                    if ($events_table_exists) {
                        $event_count = $db->querySingle("SELECT COUNT(*) FROM events") ?: 0;
                    }
                    
                    // Yönetici bilgilerini al
                    $admin_username = 'admin';
                    $admin_created = date('Y-m-d H:i:s');
                    if ($admin_table_exists) {
                        try {
                            $admin_info = $db->querySingle("SELECT username, created_at FROM admins WHERE club_id = 1", true);
                            if ($admin_info) {
                                $admin_username = $admin_info['username'] ?? 'admin';
                                $admin_created = $admin_info['created_at'] ?? date('Y-m-d H:i:s');
                            }
                    } catch (Exception $e) {
                            // Hata durumunda varsayılan değerler
                        }
                    }
                    
                    // İletişim bilgileri
                    $contact_email = '';
                    $contact_phone = '';
                    $admin_name = 'Yönetici';
                    
                    // Topluluk başkanı bilgileri
                    $president_name = '';
                    $president_email = '';
                    $president_phone = '';
                    $president_student_id = '';
                    $president_department = '';
                    
                    if ($settings_table_exists) {
                        $contact_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'contact_email'") ?: '';
                        $contact_phone = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'contact_phone'") ?: '';
                        $admin_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'admin_name'") ?: 'Yönetici';
                        
                        $president_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'president_name'") ?: '';
                        $president_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'president_email'") ?: '';
                        $president_phone = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'president_phone'") ?: '';
                        $president_student_id = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'president_student_id'") ?: '';
                        $president_department = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'president_department'") ?: '';
                    }
                    
                    // Yönetim kurulu üyeleri bilgileri - otomatik çek
                    $board_members = [];
                    $board_members_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='board_members'");
                    if ($board_members_table_exists) {
                        try {
                            $query = $db->query("SELECT * FROM board_members");
                            if ($query) {
                                while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
                                    $board_members[] = $row;
                                }
                            }
                    } catch (Exception $e) {
                            // Hata durumunda boş array kullan
                        }
                    }
                    
                    // PERFORMANS: Board members verilerini settings'e kaydetme işlemi kaldırıldı
                    // Bu işlem her sayfa yüklendiğinde çalıştığı için çok yavaşlatıyordu
                    // Manuel güncelleme için: ?update_board_members=1 parametresi kullanılabilir
                    
                    // Settings'den güncel bilgileri al
                    if ($settings_table_exists) {
                        $vice_president_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'vice_president_name'") ?: '';
                        $vice_president_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'vice_president_email'") ?: '';
                        $secretary_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'secretary_name'") ?: '';
                        $secretary_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'secretary_email'") ?: '';
                        $treasurer_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'treasurer_name'") ?: '';
                        $treasurer_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'treasurer_email'") ?: '';
                        $board_member_name = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'board_member_name'") ?: '';
                        $board_member_email = $db->querySingle("SELECT setting_value FROM settings WHERE setting_key = 'board_member_email'") ?: '';
                    }
                    
                    // Abonelik bilgilerini al (db kapatılmadan önce)
                    $subscription_tier = 'standard';
                    $subscription_end_date = null;
                    $subscription_days_remaining = null;
                    $subscription_is_active = false;
                    
                    try {
                        // Veritabanı yazılabilir mi kontrol et
                        if (!is_writable($db_path)) {
                            @chmod($db_path, SUPERADMIN_FILE_PERMS);
                            @chmod(dirname($db_path), SUPERADMIN_DIR_PERMS);
                        }
                        
                        require_once __DIR__ . '/../lib/payment/SubscriptionManager.php';
                        $subscriptionManager = new \UniPanel\Payment\SubscriptionManager($db, $dir);
                        $subscription = $subscriptionManager->getSubscription();
                        
                        if ($subscription) {
                            $subscription_tier = $subscription['tier'] ?? 'standard';
                            $subscription_end_date = $subscription['end_date'] ?? null;
                            $subscription_is_active = $subscription['is_active'] ?? false;
                            
                            if ($subscription_end_date) {
                                $end_timestamp = strtotime($subscription_end_date);
                                $now = time();
                                $subscription_days_remaining = max(0, floor(($end_timestamp - $now) / 86400));
                            }
                        }
                    } catch (Exception $e) {
                        // Hata durumunda varsayılan değerler kullanılacak
                    }
                    
                    $db->close();
                    $processed++;
                    
                    $community_details[$dir] = [
                        'name' => $club_name ?: ucwords(str_replace('_', ' ', $dir)),
                        'status' => $status ?: 'active',
                        'members' => $member_count ?: 0,
                        'events' => $event_count ?: 0,
                        'banned' => $banned_count ?: 0,
                        'community_code' => $community_code ?: '',
                        'university' => $university ?: '',
                        'folder' => $dir,
                        'subscription' => [
                            'tier' => $subscription_tier,
                            'end_date' => $subscription_end_date,
                            'days_remaining' => $subscription_days_remaining,
                            'is_active' => $subscription_is_active
                        ],
                        'admin' => [
                            'username' => $admin_username,
                            'name' => $admin_name,
                            'email' => $contact_email,
                            'phone' => $contact_phone,
                            'created_at' => $admin_created
                        ],
                        'president' => [
                            'name' => $president_name,
                            'email' => $president_email,
                            'phone' => $president_phone,
                            'student_id' => $president_student_id,
                            'department' => $president_department
                        ],
                        'board_members' => [
                            'vice_president' => [
                                'name' => $vice_president_name,
                                'email' => $vice_president_email
                            ],
                            'secretary' => [
                                'name' => $secretary_name,
                                'email' => $secretary_email
                            ],
                            'treasurer' => [
                                'name' => $treasurer_name,
                                'email' => $treasurer_email
                            ],
                            'board_member' => [
                                'name' => $board_member_name,
                                'email' => $board_member_email
                            ]
                        ]
                    ];
                } catch (Exception $e) {
                    $community_details[$dir] = [
                        'name' => ucwords(str_replace('_', ' ', $dir)),
                        'status' => 'active',
                        'members' => 0,
                        'events' => 0,
                        'banned' => 0,
                        'admin' => [
                            'username' => 'admin',
                            'name' => 'Yönetici',
                            'email' => '',
                            'phone' => '',
                            'created_at' => date('Y-m-d H:i:s')
                        ],
                        'president' => [
                            'name' => '',
                            'email' => '',
                            'phone' => '',
                            'student_id' => '',
                            'department' => ''
                        ],
                        'board_members' => [
                            'vice_president' => [
                                'name' => '',
                                'email' => ''
                            ],
                            'secretary' => [
                                'name' => '',
                                'email' => ''
                            ],
                            'treasurer' => [
                                'name' => '',
                                'email' => ''
                            ],
                            'board_member' => [
                                'name' => '',
                                'email' => ''
                            ]
                        ]
                    ];
                }
            }
        }
    }
    
    // Toplulukları oluşturulma tarihine göre sırala (yeni olanlar en üstte)
    if (!empty($communities)) {
        usort($communities, function($a, $b) use ($community_details) {
            // Klasör oluşturma tarihini al
            $path_a = COMMUNITIES_DIR . $a;
            $path_b = COMMUNITIES_DIR . $b;
            
            $time_a = file_exists($path_a) ? filemtime($path_a) : 0;
            $time_b = file_exists($path_b) ? filemtime($path_b) : 0;
            
            // Veritabanından created_at bilgisini kontrol et (varsa)
            if (isset($community_details[$a]['admin']['created_at'])) {
                $db_time_a = strtotime($community_details[$a]['admin']['created_at']);
                if ($db_time_a > 0) {
                    $time_a = max($time_a, $db_time_a);
                }
            }
            if (isset($community_details[$b]['admin']['created_at'])) {
                $db_time_b = strtotime($community_details[$b]['admin']['created_at']);
                if ($db_time_b > 0) {
                    $time_b = max($time_b, $db_time_b);
                }
            }
            
            // Yeni olanlar en üstte (büyükten küçüğe)
            return $time_b <=> $time_a;
        });
    }
    
    // Cache'i kaydet
    if ($use_cache && !empty($communities)) {
        $cache_dir = dirname($cache_file);
        if (!is_dir($cache_dir)) {
            @mkdir($cache_dir, 0755, true);
        }
        @file_put_contents($cache_file, json_encode([
            'communities' => $communities,
            'details' => $community_details,
            'timestamp' => time()
        ]), LOCK_EX);
    }
}

// İstatistikler
$total_communities = count($communities);
$total_members = 0;
$total_events = 0;
$total_banned = 0;

foreach ($community_details as $details) {
    $total_members += $details['members'];
    $total_events += $details['events'];
    $total_banned += $details['banned'];
}
?>

<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SuperAdmin | Tam Özellikli Admin Paneli</title>
    <?php include __DIR__ . '/../templates/partials/tailwind_cdn_loader.php'; ?>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700&display=swap');
        body { font-family: 'Inter', sans-serif; }
        
        /* Toast Progress Bar Animation */
        @keyframes toastProgress {
            from { width: 100%; }
            to { width: 0%; }
        }
        
        .toast-progress-bar {
            transition: width 0.1s linear;
        }
        
        /* Yeni Minimalist ve Resmi Palet */
        .bg-sidebar { background-color: #ffffff; } /* Sidebar beyaz */
        .text-sidebar { color: #475569; } /* Slate-600 */
        .active-link { background-color: #e0f2f7; color: #0ea5e9; border-left: 4px solid #0ea5e9; } /* Mavi-100/500 ile vurgu */
        .card-shadow { box-shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06); }
        .input-focus:focus { border-color: #0ea5e9; box-shadow: 0 0 0 1px #0ea5e9; } /* Mavi odak */
        
        /* Sabit Renk Paleti (Buton ve Vurgu renkleri artık tek tip) */
        .color-primary { background-color: #0ea5e9; } /* Mavi-500: Birincil eylem */
        .hover-primary:hover { background-color: #0284c7; } /* Mavi-600 */
        .color-secondary { background-color: #10b981; } /* Yeşil-500: İkincil eylem */
        .hover-secondary:hover { background-color: #059669; } /* Yeşil-600 */
        .color-danger { background-color: #ef4444; } /* Kırmızı-500: Tehlikeli eylem */
        .hover-danger:hover { background-color: #dc2626; } /* Kırmızı-600 */
        
        /* Responsive ve Modern Gölgeler */
        .section-card { 
            background: linear-gradient(135deg, #ffffff 0%, #f8fafc 100%);
            border: 1px solid #e2e8f0;
        }
        
        /* Hover Efektleri */
        .hover-lift:hover { transform: translateY(-2px); }
        .transition-smooth { transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1); }
        
        /* Responsive Design Fixes */
        @media (max-width: 640px) {
            .grid { display: grid; }
            .grid-cols-1 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .grid-cols-2 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .grid-cols-3 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .grid-cols-4 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .sm\\:grid-cols-2 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .md\\:grid-cols-2 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .md\\:grid-cols-3 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .lg\\:grid-cols-2 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .lg\\:grid-cols-3 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
            .lg\\:grid-cols-4 { grid-template-columns: repeat(1, minmax(0, 1fr)); }
        }
        
        @media (min-width: 641px) and (max-width: 768px) {
            .sm\\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .md\\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .md\\:grid-cols-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        
        @media (min-width: 769px) and (max-width: 1024px) {
            .md\\:grid-cols-2 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .md\\:grid-cols-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .lg\\:grid-cols-3 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
            .lg\\:grid-cols-4 { grid-template-columns: repeat(2, minmax(0, 1fr)); }
        }
        
        @media (min-width: 1025px) {
            .lg\\:grid-cols-3 { grid-template-columns: repeat(3, minmax(0, 1fr)); }
            .lg\\:grid-cols-4 { grid-template-columns: repeat(4, minmax(0, 1fr)); }
        }
        
        /* Mobile Navigation Fix */
        @media (max-width: 1024px) {
            .lg\\:ml-64 { margin-left: 0; }
            .lg\\:translate-x-0 { transform: translateX(0); }
        }
    </style>
</head>
<body class="min-h-screen bg-gray-50">
    <div class="flex">
        <!-- Sidebar -->
        <aside class="fixed inset-y-0 left-0 z-30 w-64 bg-sidebar transform -translate-x-full lg:translate-x-0 transition duration-200 ease-in-out shadow-xl border-r border-gray-200">
            <div class="h-full flex flex-col p-4">
                <div class="flex flex-col items-center justify-center p-4 mb-4 border-b border-gray-200">
                    <img src="https://www.caddedoner.com/foursoftware-light.png" alt="Four Community Logo" class="w-16 h-16 mb-2">
                    <h2 class="text-xl font-bold text-gray-800">SuperAdmin</h2>
                </div>
                <nav class="flex-1 space-y-2">
                    <a href="?view=dashboard" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>
                        <span class="font-normal">Pano</span>
                    </a>
                    <a href="?view=communities" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path></svg>
                        <span class="font-normal">Topluluklar</span>
                    </a>
                    <a href="?view=users" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                        <span class="font-normal">Kullanıcılar</span>
                    </a>
                    <a href="?view=events" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path></svg>
                        <span class="font-normal">Etkinlikler</span>
                    </a>
                    <a href="?view=reports" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                        <span class="font-normal">Raporlar</span>
                    </a>
                    <a href="?view=logs" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        <span class="font-normal">Loglar</span>
                    </a>
                    <a href="?view=requests" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150 <?= ($current_view ?? '') === 'requests' ? 'bg-gray-100 text-blue-600' : '' ?>">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path></svg>
                        <span class="font-normal">Topluluk Talepleri</span>
                        <?php
                        initLogDatabase();
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                        $db->exec("CREATE TABLE IF NOT EXISTS community_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, community_name TEXT NOT NULL, folder_name TEXT NOT NULL, university TEXT NOT NULL, admin_username TEXT NOT NULL, admin_password_hash TEXT NOT NULL, admin_email TEXT, status TEXT DEFAULT 'pending', admin_notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, processed_at DATETIME, processed_by TEXT)");
                        $pending_count = $db->querySingle("SELECT COUNT(*) FROM community_requests WHERE status = 'pending'");
                        $db->close();
                        if ($pending_count > 0):
                        ?>
                        <span class="ml-auto bg-red-500 text-white text-xs font-bold px-2 py-1 rounded-full"><?= $pending_count ?></span>
                        <?php endif; ?>
                    </a>
                    <a href="?view=ads" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150 <?= ($current_view ?? '') === 'ads' ? 'bg-gray-100 text-blue-600' : '' ?>">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"></path></svg>
                        <span class="font-normal">Reklamlar</span>
                    </a>
                    <a href="?view=notifications" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150 <?= ($current_view ?? '') === 'notifications' ? 'bg-gray-100 text-blue-600' : '' ?>">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-5 5v-5zM4.828 7l2.586-2.586A2 2 0 018.828 4h6.344a2 2 0 011.414.586L19.172 7H4.828zM4 7v10a2 2 0 002 2h12a2 2 0 002-2V7H4z"></path></svg>
                        <span class="font-normal">Bildirimler</span>
                    </a>
                    <a href="?view=contact_forms" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150 <?= ($current_view ?? '') === 'contact_forms' ? 'bg-gray-100 text-blue-600' : '' ?>">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path></svg>
                        <span class="font-normal">İletişim Formları</span>
                        <?php
                        initLogDatabase();
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                        $db->exec("CREATE TABLE IF NOT EXISTS contact_submissions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            name TEXT NOT NULL,
                            email TEXT NOT NULL,
                            phone TEXT,
                            community TEXT,
                            message TEXT NOT NULL,
                            ip_address TEXT,
                            user_agent TEXT,
                            status TEXT DEFAULT 'new',
                            read_at DATETIME,
                            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                        )");
                        $new_count = $db->querySingle("SELECT COUNT(*) FROM contact_submissions WHERE status = 'new'");
                        $db->close();
                        if ($new_count > 0):
                        ?>
                        <span class="ml-auto bg-blue-500 text-white text-xs font-bold px-2 py-1 rounded-full"><?= $new_count ?></span>
                        <?php endif; ?>
                    </a>
                    <a href="?view=verification_admin" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150 <?= ($current_view ?? '') === 'verification_admin' ? 'bg-gray-100 text-blue-600' : '' ?>">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg">
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5l7 3V12c0 4.5-3 8.5-7 9-4-.5-7-4.5-7-9V7.5l7-3z"></path>
                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.5 12.5l2 2 3-3.5"></path>
                        </svg>
                        <span class="font-normal">Topluluk Onayı</span>
                    </a>
                    <a href="?view=settings" class="flex items-center p-3 rounded-lg text-sidebar hover:bg-gray-100 hover:text-blue-600 transition duration-150">
                        <svg class="w-6 h-6 mr-3" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37a1.724 1.724 0 002.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                        <span class="font-normal">Sistem Ayarları</span>
                    </a>
                </nav>
                <div class="mt-auto p-4 border-t border-gray-200">
                    <a href="?action=logout" class="w-full flex items-center justify-center p-3 rounded-lg text-red-500 bg-red-50 hover:bg-red-100 transition duration-150 font-semibold border border-red-200">
                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg>
                        Çıkış Yap
                    </a>
                </div>
            </div>
        </aside>

        <!-- Main Content -->
        <div class="flex-1 lg:ml-64">
            <!-- Header -->
            <header class="bg-white shadow-sm border-b border-gray-200">
                <div class="p-4 sm:p-6 lg:p-4 flex items-center justify-between">
                    <div class="flex items-center">
                        <div class="hidden lg:flex items-center mr-4">
                            <svg class="w-6 h-6 mr-3 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"></path></svg>
                        </div>
                        <div>
                            <h1 class="text-lg font-semibold text-gray-800 leading-tight">SuperAdmin Paneli</h1>
                            <p class="text-xs text-gray-500">Tam Özellikli Yönetim Sistemi</p>
                        </div>
                    </div>
                </div>
            </header>

            <!-- Content -->
            <main class="p-4 sm:p-6 lg:p-8">
                <?php if ($error): ?>
                    <div class="mb-6 p-4 text-red-700 bg-red-100 rounded-lg border border-red-300 relative overflow-hidden">
                        <?= htmlspecialchars($error) ?>
                        <div class="absolute bottom-0 left-0 h-1 bg-red-500 toast-progress-bar" style="width: 100%; animation: toastProgress 5s linear forwards;"></div>
                    </div>
                <?php endif; ?>

                <?php if ($success): ?>
                    <div class="mb-6 p-4 text-green-700 bg-green-100 rounded-lg border border-green-300 relative overflow-hidden">
                        <?= htmlspecialchars($success) ?>
                        <div class="absolute bottom-0 left-0 h-1 bg-green-500 toast-progress-bar" style="width: 100%; animation: toastProgress 5s linear forwards;"></div>
                    </div>
                <?php endif; ?>

                <?php
                $current_view = $_GET['view'] ?? 'dashboard';
                if ($current_view === 'dashboard'):
                ?>
                    <!-- Dashboard -->
                    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
                        <div class="bg-white p-6 rounded-xl card-shadow border-l-4 border-blue-500 bg-blue-50">
                            <div class="flex items-center justify-between">
                                <p class="text-md font-medium text-gray-500">Toplam Topluluk</p>
                                <div class="p-2 rounded-full text-blue-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path></svg>
                                </div>
                            </div>
                            <p class="mt-2 text-4xl font-extrabold text-gray-900"><?= $total_communities ?></p>
                        </div>

                        <div class="bg-white p-6 rounded-xl card-shadow border-l-4 border-green-500 bg-green-50">
                            <div class="flex items-center justify-between">
                                <p class="text-md font-medium text-gray-500">Toplam Üye</p>
                                <div class="p-2 rounded-full text-green-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                                </div>
                            </div>
                            <p class="mt-2 text-4xl font-extrabold text-gray-900"><?= $total_members ?></p>
                        </div>

                        <div class="bg-white p-6 rounded-xl card-shadow border-l-4 border-cyan-500 bg-cyan-50">
                            <div class="flex items-center justify-between">
                                <p class="text-md font-medium text-gray-500">Toplam Etkinlik</p>
                                <div class="p-2 rounded-full text-cyan-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path></svg>
                                </div>
                            </div>
                            <p class="mt-2 text-4xl font-extrabold text-gray-900"><?= $total_events ?></p>
                        </div>

                        <div class="bg-white p-6 rounded-xl card-shadow border-l-4 border-red-500 bg-red-50">
                            <div class="flex items-center justify-between">
                                <p class="text-md font-medium text-gray-500">Banlı Kullanıcı</p>
                                <div class="p-2 rounded-full text-red-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728L5.636 5.636m12.728 12.728L18.364 5.636M5.636 18.364l12.728-12.728"></path></svg>
                                </div>
                            </div>
                            <p class="mt-2 text-4xl font-extrabold text-gray-900"><?= $total_banned ?></p>
                        </div>
                    </div>

                    <!-- Son Aktiviteler -->
                    <div class="bg-white rounded-xl card-shadow">
                        <div class="p-6 border-b border-gray-200">
                            <h2 class="text-xl font-semibold text-gray-800">Son Aktiviteler</h2>
                        </div>
                        <div class="p-6">
                            <div class="space-y-4">
                                <div class="flex items-center p-4 bg-gray-50 rounded-lg">
                                    <div class="w-10 h-10 bg-blue-100 rounded-full flex items-center justify-center mr-4">
                                        <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v3m0 0v3m0-3h3m-3 0H9m12 0a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <p class="font-medium text-gray-800">Sistem Başlatıldı</p>
                                        <p class="text-sm text-gray-500">SuperAdmin paneli aktif</p>
                                    </div>
                                </div>
                                <div class="flex items-center p-4 bg-gray-50 rounded-lg">
                                    <div class="w-10 h-10 bg-green-100 rounded-full flex items-center justify-center mr-4">
                                        <svg class="w-5 h-5 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                    <div>
                                        <p class="font-medium text-gray-800">Tüm Sistemler Aktif</p>
                                        <p class="text-sm text-gray-500"><?= $total_communities ?> topluluk çalışıyor</p>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($current_view === 'communities'): ?>
                    <!-- Topluluk Yönetimi - TAMAMEN YENİDEN YAZILDI -->
                    <div class="space-y-6">
                        <!-- Başlık ve Oluştur Butonu -->
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <div class="flex items-center justify-between">
                                <div>
                                    <h1 class="text-3xl font-bold text-gray-900 mb-2">Topluluklar</h1>
                                    <p class="text-gray-600">Toplam <span class="font-bold text-purple-600"><?= count($communities) ?></span> topluluk</p>
                                </div>
                                <button onclick="openCreateModal()" class="px-6 py-3 bg-purple-600 text-white rounded-lg font-semibold hover:bg-purple-700 transition flex items-center gap-2">
                                    <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                                    </svg>
                                    Yeni Topluluk
                                </button>
                            </div>
                        </div>

                        <!-- Arama ve Filtreler - BASİT VE ÇALIŞIR -->
                        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                                <!-- Arama -->
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Ara</label>
                                    <div class="relative">
                                        <input type="text" id="communitySearch" placeholder="Topluluk adı, klasör veya üniversite..." 
                                               onkeyup="if(event.key==='Enter') window.doSearch();"
                                               class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                                        <svg class="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                                
                                <!-- Üniversite -->
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Üniversite</label>
                                    <div class="relative">
                                        <input type="text" id="filterUniversity" placeholder="Üniversite adı..." 
                                               onkeyup="if(event.key==='Enter') window.doSearch();"
                                               class="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                                        <svg class="w-5 h-5 absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
                                <!-- Durum -->
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Durum</label>
                                    <select id="filterStatus" onchange="window.doSearch();" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                                        <option value="all">Tümü</option>
                                        <option value="active">Aktif</option>
                                        <option value="inactive">Kapalı</option>
                                    </select>
                                </div>
                                
                                <!-- Plan -->
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Plan</label>
                                    <select id="filterTier" onchange="window.doSearch();" class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-purple-500">
                                        <option value="all">Tümü</option>
                                        <option value="standard">Standart</option>
                                        <option value="professional">Profesyonel</option>
                                        <option value="business">Business</option>
                                    </select>
                                </div>
                                
                                <!-- Butonlar -->
                                <div class="flex items-end gap-2">
                                    <button onclick="window.doSearch();" class="flex-1 px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition font-medium">
                                        Ara
                                    </button>
                                    <button onclick="window.clearSearch();" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 transition font-medium">
                                        Temizle
                                    </button>
                                </div>
                            </div>
                            
                            <!-- Sonuç -->
                            <div id="searchResult" class="text-sm text-gray-600 hidden"></div>
                        </div>
                            
                            <?php if (empty($communities)): ?>
                                <div class="p-8 text-center text-gray-500">
                                    <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                                    </svg>
                                    <p class="text-lg">Henüz topluluk oluşturulmamış</p>
                                    <p class="text-sm">Yukarıdaki formu kullanarak ilk topluluğunuzu oluşturun</p>
                                </div>
                            <?php else: ?>
                                <?php 
                                // PERFORMANS: Lazy loading için ilk yüklemede sadece ilk 30 topluluk
                                $displayed_communities = array_slice($communities, 0, 30);
                                $has_more_communities = count($communities) > 30;
                                ?>
                                <div class="p-6">
                                    <div class="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-6" id="communitiesList">
                                    <?php foreach ($displayed_communities as $community): 
                                        $is_active = isset($community_details[$community]['status']) ? $community_details[$community]['status'] : 'active';
                                        $subscription = $community_details[$community]['subscription'] ?? null;
                                        $tier = $subscription ? ($subscription['tier'] ?? 'standard') : 'none';
                                    ?>
                                        <div class="community-item group bg-white rounded-xl border-2 border-gray-200 hover:border-purple-400 hover:shadow-xl transition-all duration-300 overflow-hidden" 
                                             data-name="<?= strtolower(htmlspecialchars($community_details[$community]['name'] ?? $community)) ?>" 
                                             data-folder="<?= strtolower(htmlspecialchars($community)) ?>" 
                                             data-university="<?= strtolower(htmlspecialchars($community_details[$community]['university'] ?? '')) ?>"
                                             data-status="<?= $is_active ?>"
                                             data-tier="<?= $tier ?>">
                                            
                                            <!-- Card Header - Clean White with Purple Accents -->
                                            <div class="p-6 border-b-2 border-gray-100">
                                                <div class="flex items-start justify-between mb-4">
                                                    <div class="flex items-center gap-4 flex-1 min-w-0">
                                                        <div class="w-14 h-14 bg-purple-100 rounded-xl flex items-center justify-center border-2 border-purple-200 flex-shrink-0">
                                                            <svg class="w-7 h-7 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"></path>
                                                            </svg>
                                                        </div>
                                                        <div class="flex-1 min-w-0">
                                                            <h3 class="text-lg font-bold text-gray-900 mb-1 truncate"><?= isset($community_details[$community]['name']) ? htmlspecialchars($community_details[$community]['name']) : htmlspecialchars($community) ?></h3>
                                                            <p class="text-sm text-gray-500 truncate"><?= htmlspecialchars($community) ?></p>
                                                            <?php if (isset($community_details[$community]['university']) && !empty($community_details[$community]['university'])): ?>
                                                            <p class="text-xs text-purple-600 mt-1 truncate font-medium"><?= htmlspecialchars($community_details[$community]['university']) ?></p>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                    <?php if ($is_active === 'active'): ?>
                                                        <span class="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-bold bg-green-50 text-green-700 border-2 border-green-200 flex-shrink-0">
                                                            <span class="w-2 h-2 bg-green-500 rounded-full mr-2"></span>
                                                            Aktif
                                                        </span>
                                                    <?php else: ?>
                                                        <span class="inline-flex items-center px-3 py-1.5 rounded-full text-xs font-bold bg-red-50 text-red-700 border-2 border-red-200 flex-shrink-0">
                                                            <span class="w-2 h-2 bg-red-500 rounded-full mr-2"></span>
                                                            Kapalı
                                                        </span>
                                                    <?php endif; ?>
                                                </div>
                                                
                                                <!-- İstatistikler - Clean White Design -->
                                                <div class="grid grid-cols-3 gap-3">
                                                    <div class="bg-gray-50 rounded-lg p-3 text-center border border-gray-200">
                                                        <div class="text-xl font-bold text-gray-900 mb-1"><?= isset($community_details[$community]['members']) ? $community_details[$community]['members'] : '0' ?></div>
                                                        <div class="text-xs text-gray-600 font-medium">Üye</div>
                                                    </div>
                                                    <div class="bg-purple-50 rounded-lg p-3 text-center border-2 border-purple-200">
                                                        <div class="text-xl font-bold text-purple-700 mb-1"><?= isset($community_details[$community]['events']) ? $community_details[$community]['events'] : '0' ?></div>
                                                        <div class="text-xs text-purple-600 font-medium">Etkinlik</div>
                                                    </div>
                                                    <div class="bg-gray-50 rounded-lg p-3 text-center border border-gray-200">
                                                        <div class="text-xl font-bold text-gray-900 mb-1"><?= isset($community_details[$community]['banned']) ? $community_details[$community]['banned'] : '0' ?></div>
                                                        <div class="text-xs text-gray-600 font-medium">Banlı</div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <!-- Card Body -->
                                            <div class="p-6 bg-white">
                                                <!-- Plan Badge -->
                                                <?php if ($subscription): 
                                                    $tierLabels = [
                                                        'standard' => 'Standart',
                                                        'professional' => 'Profesyonel',
                                                        'business' => 'Business'
                                                    ];
                                                    $tierLabel = $tierLabels[$tier] ?? 'Standart';
                                                    $endDate = $subscription['end_date'] ?? null;
                                                    $daysRemaining = $subscription['days_remaining'] ?? null;
                                                ?>
                                                <div class="mb-4 bg-purple-50 rounded-xl p-4 border-2 border-purple-200">
                                                    <div class="flex items-center justify-between">
                                                        <div class="flex items-center gap-3">
                                                            <div class="w-10 h-10 bg-purple-100 rounded-lg flex items-center justify-center border-2 border-purple-300">
                                                                <svg class="w-5 h-5 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 8h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"></path>
                                                                </svg>
                                                            </div>
                                                            <div>
                                                                <div class="text-sm font-bold text-purple-900"><?= htmlspecialchars($tierLabel) ?> Plan</div>
                                                                <?php if ($endDate && $daysRemaining !== null): ?>
                                                                    <div class="text-xs text-purple-700 mt-0.5">
                                                                        <?php if ($daysRemaining > 0): ?>
                                                                            <?= $daysRemaining ?> gün kaldı
                                                                        <?php else: ?>
                                                                            <span class="font-semibold text-red-600">Süresi doldu</span>
                                                                        <?php endif; ?>
                                                                    </div>
                                                                <?php endif; ?>
                                                            </div>
                                                        </div>
                                                        <?php if ($endDate && $daysRemaining !== null && $daysRemaining > 0): ?>
                                                            <div class="text-right">
                                                                <div class="text-xs text-purple-600 mb-1">Bitiş</div>
                                                                <div class="text-sm font-semibold text-purple-900"><?= date('d.m.Y', strtotime($endDate)) ?></div>
                                                            </div>
                                                        <?php endif; ?>
                                                    </div>
                                                </div>
                                                <?php endif; ?>
                                                
                                                <!-- Başkan ve Yönetim Kurulu -->
                                                <div class="space-y-3">
                                                    <!-- Topluluk Başkanı -->
                                                    <?php if (isset($community_details[$community]['president']) && !empty($community_details[$community]['president']['name'])): ?>
                                                    <div class="bg-purple-50 rounded-xl p-4 border-2 border-purple-200">
                                                        <div class="flex items-center justify-between mb-3">
                                                            <h4 class="text-xs font-bold text-purple-900 flex items-center uppercase tracking-wider">
                                                                <svg class="w-4 h-4 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 3v4M3 5h4M6 17v4m-2-2h4m5-16l2.286 6.857L21 12l-5.714 2.143L13 21l-2.286-6.857L5 12l5.714-2.143L13 3z"></path>
                                                                </svg>
                                                                Başkan
                                                            </h4>
                                                            <span class="px-2 py-1 bg-purple-200 text-purple-800 text-xs font-bold rounded-full">Lider</span>
                                                        </div>
                                                        <div class="space-y-2">
                                                            <div class="font-bold text-gray-900 text-sm"><?= isset($community_details[$community]['president']['name']) ? htmlspecialchars($community_details[$community]['president']['name']) : 'Bilgi Yok' ?></div>
                                                            <?php if (isset($community_details[$community]['president']['email'])): ?>
                                                            <div class="flex items-center gap-2 text-xs text-purple-700">
                                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                                                </svg>
                                                                <a href="mailto:<?= htmlspecialchars($community_details[$community]['president']['email']) ?>" class="truncate hover:underline font-medium"><?= htmlspecialchars($community_details[$community]['president']['email']) ?></a>
                                                            </div>
                                                            <?php endif; ?>
                                                            <?php if (isset($community_details[$community]['president']['phone']) && !empty($community_details[$community]['president']['phone'])): ?>
                                                            <div class="flex items-center gap-2 text-xs text-purple-700">
                                                                <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 5a2 2 0 012-2h3.28a1 1 0 01.948.684l1.498 4.493a1 1 0 01-.502 1.21l-2.257 1.13a11.042 11.042 0 005.516 5.516l1.13-2.257a1 1 0 011.21-.502l4.493 1.498a1 1 0 01.684.949V19a2 2 0 01-2 2h-1C9.716 21 3 14.284 3 6V5z"></path>
                                                                </svg>
                                                                <a href="tel:<?= htmlspecialchars($community_details[$community]['president']['phone']) ?>" class="hover:underline font-medium"><?= htmlspecialchars($community_details[$community]['president']['phone']) ?></a>
                                                            </div>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                    <?php endif; ?>
                                                    
                                                    <!-- Yönetim Kurulu Özet -->
                                                    <?php if (isset($community_details[$community]['board_members'])): 
                                                        $board_count = 0;
                                                        $board_members_list = [];
                                                        if (!empty($community_details[$community]['board_members']['vice_president']['name'])) {
                                                            $board_count++;
                                                            $board_members_list[] = ['role' => 'Başkan Yardımcısı', 'name' => $community_details[$community]['board_members']['vice_president']['name'], 'email' => $community_details[$community]['board_members']['vice_president']['email'] ?? ''];
                                                        }
                                                        if (!empty($community_details[$community]['board_members']['secretary']['name'])) {
                                                            $board_count++;
                                                            $board_members_list[] = ['role' => 'Sekreter', 'name' => $community_details[$community]['board_members']['secretary']['name'], 'email' => $community_details[$community]['board_members']['secretary']['email'] ?? ''];
                                                        }
                                                        if (!empty($community_details[$community]['board_members']['treasurer']['name'])) {
                                                            $board_count++;
                                                            $board_members_list[] = ['role' => 'Muhasip', 'name' => $community_details[$community]['board_members']['treasurer']['name'], 'email' => $community_details[$community]['board_members']['treasurer']['email'] ?? ''];
                                                        }
                                                        if (!empty($community_details[$community]['board_members']['board_member']['name'])) {
                                                            $board_count++;
                                                            $board_members_list[] = ['role' => 'Üye', 'name' => $community_details[$community]['board_members']['board_member']['name'], 'email' => $community_details[$community]['board_members']['board_member']['email'] ?? ''];
                                                        }
                                                    ?>
                                                    <?php if ($board_count > 0): ?>
                                                    <div class="bg-gray-50 rounded-xl p-4 border-2 border-gray-200">
                                                        <div class="flex items-center justify-between mb-3">
                                                            <h4 class="text-xs font-bold text-gray-900 flex items-center uppercase tracking-wider">
                                                                <svg class="w-4 h-4 mr-2 text-purple-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z"></path>
                                                                </svg>
                                                                Yönetim Kurulu
                                                            </h4>
                                                            <span class="px-2 py-1 bg-purple-100 text-purple-800 text-xs font-bold rounded-full border border-purple-200"><?= $board_count ?> Üye</span>
                                                        </div>
                                                        <div class="space-y-2">
                                                            <?php foreach (array_slice($board_members_list, 0, 3) as $bm): ?>
                                                            <div class="flex items-center justify-between text-xs bg-white rounded-lg p-2 border border-gray-200">
                                                                <div class="flex items-center gap-2">
                                                                    <div class="w-1.5 h-1.5 bg-purple-500 rounded-full"></div>
                                                                    <span class="font-semibold text-gray-700"><?= htmlspecialchars($bm['role']) ?>:</span>
                                                                    <span class="text-gray-600"><?= htmlspecialchars($bm['name']) ?></span>
                                                                </div>
                                                                <?php if (!empty($bm['email'])): ?>
                                                                <a href="mailto:<?= htmlspecialchars($bm['email']) ?>" class="text-purple-600 hover:text-purple-800">
                                                                    <svg class="w-3.5 h-3.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                                                    </svg>
                                                                </a>
                                                                <?php endif; ?>
                                                            </div>
                                                            <?php endforeach; ?>
                                                            <?php if ($board_count > 3): ?>
                                                            <div class="text-xs text-purple-700 font-medium text-center pt-1">
                                                                +<?= $board_count - 3 ?> üye daha
                                                            </div>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                    <?php endif; ?>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                            
                                            <!-- Card Footer - Action Buttons -->
                                            <div class="p-6 pt-4 bg-gray-50 border-t-2 border-gray-100">
                                                <div class="grid grid-cols-2 gap-3 mb-3">
                                                    <a href="../communities/<?= urlencode($community) ?>/loading.php?community=<?= urlencode($community) ?>&auto_access=true" target="_blank" class="group/btn px-4 py-3 bg-purple-600 text-white rounded-xl hover:bg-purple-700 transition-all duration-200 font-bold text-sm flex items-center justify-center shadow-md hover:shadow-lg">
                                                        <svg class="w-4 h-4 mr-2 group-hover/btn:rotate-12 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"></path>
                                                        </svg>
                                                        Erişim
                                                    </a>
                                                    
                                                    <button onclick="openEditModal(<?= htmlspecialchars(json_encode($community), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['name'] ?? 'Bilinmeyen Topluluk'), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['community_code'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['university'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['admin']['username'] ?? ''), ENT_QUOTES) ?>)" class="group/btn px-4 py-3 bg-white text-purple-600 border-2 border-purple-600 rounded-xl hover:bg-purple-50 transition-all duration-200 font-bold text-sm flex items-center justify-center shadow-md hover:shadow-lg">
                                                        <svg class="w-4 h-4 mr-2 group-hover/btn:rotate-12 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"></path>
                                                        </svg>
                                                        Düzenle
                                                    </button>
                                                </div>
                                                <div class="grid grid-cols-4 gap-2">
                                                    <button onclick="openAssignPlanModal(<?= htmlspecialchars(json_encode($community), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['name'] ?? 'Bilinmeyen Topluluk'), ENT_QUOTES) ?>)" class="px-3 py-2.5 bg-white text-purple-600 border-2 border-purple-300 rounded-lg hover:bg-purple-50 transition-all duration-200 font-semibold text-xs flex items-center justify-center shadow-sm hover:shadow-md">
                                                        <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                                        </svg>
                                                        Plan
                                                    </button>
                                                    
                                                    <button onclick="openAssignSmsPackageModal(<?= htmlspecialchars(json_encode($community), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($community_details[$community]['name'] ?? 'Bilinmeyen Topluluk'), ENT_QUOTES) ?>)" class="px-3 py-2.5 bg-white text-purple-600 border-2 border-purple-300 rounded-lg hover:bg-purple-50 transition-all duration-200 font-semibold text-xs flex items-center justify-center shadow-sm hover:shadow-md">
                                                        <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"></path>
                                                        </svg>
                                                        SMS
                                                    </button>
                                                    
                                                    <button onclick="showCommunityQRCode('<?= htmlspecialchars($community, ENT_QUOTES) ?>', '<?= htmlspecialchars($community_details[$community]['name'] ?? $community, ENT_QUOTES) ?>')" class="px-3 py-2.5 bg-white text-purple-600 border-2 border-purple-300 rounded-lg hover:bg-purple-50 transition-all duration-200 font-semibold text-xs flex items-center justify-center shadow-sm hover:shadow-md" title="QR Kod">
                                                        <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v1m6 11h2m-6 0h-2v4m0-11v3m0 0h.01M12 12h4.01M16 20h4M4 12h4m12 0h.01M5 8h2a1 1 0 001-1V5a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1zm12 0h2a1 1 0 001-1V5a1 1 0 00-1-1h-2a1 1 0 00-1 1v2a1 1 0 001 1zM5 20h2a1 1 0 001-1v-2a1 1 0 00-1-1H5a1 1 0 00-1 1v2a1 1 0 001 1z"></path>
                                                        </svg>
                                                        QR
                                                    </button>
                                                    
                                                    <button onclick="deleteCommunity(<?= htmlspecialchars(json_encode($community), ENT_QUOTES) ?>)" class="px-3 py-2.5 bg-white text-red-600 border-2 border-red-300 rounded-lg hover:bg-red-50 transition-all duration-200 font-semibold text-xs flex items-center justify-center shadow-sm hover:shadow-md">
                                                        <svg class="w-3.5 h-3.5 mr-1.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"></path>
                                                        </svg>
                                                        Sil
                                                    </button>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                <?php elseif ($current_view === 'users'): ?>
                    <!-- Kullanıcı Yönetimi -->
                    <div class="space-y-8">
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h2 class="text-2xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                                    Tüm Kullanıcılar
                                </h2>
                            </div>
                            <div class="p-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    <?php foreach ($communities as $community): ?>
                                        <div class="border border-gray-200 rounded-lg p-4">
                                            <h3 class="font-semibold text-gray-800 mb-3"><?= isset($community_details[$community]['name']) ? $community_details[$community]['name'] : $community ?></h3>
                                            <div class="space-y-2">
                                                <div class="flex justify-between text-sm">
                                                    <span class="text-gray-600">Toplam Üye:</span>
                                                    <span class="font-medium"><?= isset($community_details[$community]['members']) ? $community_details[$community]['members'] : '0' ?></span>
                                                </div>
                                                <div class="flex justify-between text-sm">
                                                    <span class="text-gray-600">Banlı Üye:</span>
                                                    <span class="font-medium text-red-600"><?= isset($community_details[$community]['banned']) ? $community_details[$community]['banned'] : '0' ?></span>
                                                </div>
                                                <div class="flex justify-between text-sm">
                                                    <span class="text-gray-600">Aktif Üye:</span>
                                                    <span class="font-medium text-green-600"><?= (isset($community_details[$community]['members']) ? $community_details[$community]['members'] : 0) - (isset($community_details[$community]['banned']) ? $community_details[$community]['banned'] : 0) ?></span>
                                                </div>
                                            </div>
                                            <div class="mt-4 flex space-x-2">
                                                <a href="?view=user_details&community=<?= urlencode($community) ?>" class="px-3 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition duration-150">
                                                    Detayları Gör
                                                </a>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($current_view === 'user_details' && isset($_GET['community'])): ?>
                    <!-- Kullanıcı Detayları -->
                    <?php
                    $selected_community = $_GET['community'];
                    $community_path = COMMUNITIES_DIR . $selected_community;
                    $users = [];
                    $community_name = ucwords(str_replace('_', ' ', $selected_community));
                    
                    if (is_dir($community_path)) {
                        $db_path = $community_path . '/unipanel.sqlite';
                        if (file_exists($db_path)) {
                            try {
                                $db = new SQLite3($db_path);
                                
                                // Eksik sütunları ekle - PRAGMA ile kontrol et
                                $members_columns = $db->query("PRAGMA table_info(members)");
                                $existing_columns = [];
                                while ($row = $members_columns->fetchArray(SQLITE3_ASSOC)) {
                                    $existing_columns[] = $row['name'];
                                }
                                
                                if (!in_array('is_banned', $existing_columns)) {
                                try {
                                    $db->exec("ALTER TABLE members ADD COLUMN is_banned INTEGER DEFAULT 0");
                                } catch (Exception $e) {}
                                }
                                
                                if (!in_array('ban_reason', $existing_columns)) {
                                try {
                                    $db->exec("ALTER TABLE members ADD COLUMN ban_reason TEXT");
                                } catch (Exception $e) {}
                                }
                                
                                $query = $db->query("SELECT * FROM members ORDER BY full_name ASC");
                                while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
                                    $users[] = $row;
                                }
                                $db->close();
                            } catch (Exception $e) {
                                $error = "Kullanıcı bilgileri alınamadı: " . $e->getMessage();
                            }
                        }
                    }
                    ?>
                    <div class="space-y-8">
                        <!-- Başlık ve Geri Dön -->
                        <div class="flex items-center justify-between">
                            <div>
                                <h2 class="text-2xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path></svg>
                                    <?= htmlspecialchars($community_name) ?> - Kullanıcı Detayları
                                </h2>
                                <p class="text-sm text-gray-500 mt-1">Toplam <?= count($users) ?> kullanıcı</p>
                            </div>
                            <a href="?view=users" class="px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150">
                                ← Geri Dön
                            </a>
                        </div>

                        <!-- Kullanıcı Listesi -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <div class="flex items-center justify-between">
                                    <h3 class="text-lg font-semibold text-gray-800">Kullanıcı Listesi</h3>
                                    <div class="flex space-x-2">
                                        <span class="px-3 py-1 text-xs bg-green-100 text-green-700 rounded-full">
                                            Aktif: <?= count(array_filter($users, function($u) { return !$u['is_banned']; })) ?>
                                        </span>
                                        <span class="px-3 py-1 text-xs bg-red-100 text-red-700 rounded-full">
                                            Banlı: <?= count(array_filter($users, function($u) { return $u['is_banned']; })) ?>
                                        </span>
                                    </div>
                                </div>
                            </div>
                            
                            <?php if (empty($users)): ?>
                                <div class="p-8 text-center text-gray-500">
                                    <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                                    </svg>
                                    <p class="text-lg">Henüz kullanıcı bulunmamış</p>
                                </div>
                            <?php else: ?>
                                <div class="divide-y divide-gray-200">
                                    <?php foreach ($users as $user): ?>
                                        <div class="p-6">
                                            <div class="flex items-center justify-between">
                                                <div class="flex items-center">
                                                    <div class="w-12 h-12 <?= $user['is_banned'] ? 'bg-red-100' : 'bg-green-100' ?> rounded-full flex items-center justify-center mr-4">
                                                        <svg class="w-6 h-6 <?= $user['is_banned'] ? 'text-red-600' : 'text-green-600' ?>" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z"></path>
                                                        </svg>
                                                    </div>
                                                    <div>
                                                        <h4 class="text-lg font-semibold text-gray-800">
                                                            <?= htmlspecialchars($user['full_name'] ?: 'Adsız Kullanıcı') ?>
                                                            <?php if ($user['is_banned']): ?>
                                                                <span class="ml-2 px-2 py-1 text-xs bg-red-100 text-red-700 rounded-full">BANLI</span>
                                                            <?php endif; ?>
                                                        </h4>
                                                        <div class="text-sm text-gray-500 space-y-1">
                                                            <?php if ($user['email']): ?>
                                                                <p>📧 <?= htmlspecialchars($user['email']) ?></p>
                                                            <?php endif; ?>
                                                            <?php if ($user['phone_number']): ?>
                                                                <p>📱 <?= htmlspecialchars($user['phone_number']) ?></p>
                                                            <?php endif; ?>
                                                            <?php if ($user['student_id']): ?>
                                                                <p>🎓 Öğrenci No: <?= htmlspecialchars($user['student_id']) ?></p>
                                                            <?php endif; ?>
                                                            <p>📅 Kayıt: <?= htmlspecialchars($user['registration_date'] ?: 'Bilinmiyor') ?></p>
                                                            <?php if ($user['is_banned'] && $user['ban_reason']): ?>
                                                                <p class="text-red-600">🚫 Ban Sebebi: <?= htmlspecialchars($user['ban_reason']) ?></p>
                                                            <?php endif; ?>
                                                        </div>
                                                    </div>
                                                </div>
                                                <div class="flex items-center space-x-3">
                                                    <?php if ($user['is_banned']): ?>
                                                        <button onclick="performAction('unban_user', <?= htmlspecialchars(json_encode($selected_community), ENT_QUOTES) ?>, null, {user_id: <?= htmlspecialchars(json_encode($user['id']), ENT_QUOTES) ?>})" class="px-4 py-2 text-green-600 hover:text-green-800 font-medium border border-green-200 rounded-lg hover:bg-green-50 transition duration-150">
                                                            Ban Kaldır
                                                        </button>
                                                    <?php else: ?>
                                                        <button onclick="if(confirm('Bu kullanıcıyı banlamak istediğinizden emin misiniz?')) performAction('ban_user', <?= htmlspecialchars(json_encode($selected_community), ENT_QUOTES) ?>, null, {user_id: <?= htmlspecialchars(json_encode($user['id']), ENT_QUOTES) ?>, reason: 'Yönetim kararı'})" class="px-4 py-2 text-red-600 hover:text-red-800 font-medium border border-red-200 rounded-lg hover:bg-red-50 transition duration-150">
                                                            Banla
                                                        </button>
                                                    <?php endif; ?>
                                                </div>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                <?php elseif ($current_view === 'events'): ?>
                    <!-- Etkinlik Yönetimi -->
                    <?php
                    // Tüm toplulukların etkinliklerini topla
                    $all_events = [];
                    $community_events = [];
                    
                    foreach ($communities as $community) {
                        $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                        if (file_exists($db_path)) {
                            try {
                                $db = new SQLite3($db_path);
                                $events = [];
                                
                                $events_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='events'");
                                if ($events_table_exists) {
                                    $query = @$db->query("SELECT * FROM events ORDER BY date DESC, time DESC");
                                    if ($query) {
                                        while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
                                            $events[] = $row;
                                            $all_events[] = array_merge($row, ['community' => $community]);
                                        }
                                    }
                                }
                                
                                $community_events[$community] = $events;
                                $db->close();
                            } catch (Exception $e) {
                                $community_events[$community] = [];
                            }
                        }
                    }
                    ?>
                    <div class="space-y-8">
                        <!-- Etkinlik Özeti -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h2 class="text-2xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-cyan-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path></svg>
                                    Tüm Etkinlikler (<?= count($all_events) ?>)
                                </h2>
                            </div>
                            <div class="p-6">
                                <?php if (empty($all_events)): ?>
                                <div class="text-center text-gray-500 py-8">
                                    <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01"></path>
                                    </svg>
                                        <p class="text-lg">Henüz etkinlik bulunmamış</p>
                                        <p class="text-sm">Topluluklar etkinlik oluşturduğunda burada görünecek</p>
                                </div>
                                <?php else: ?>
                                    <!-- Arama Kutusu -->
                                    <div class="mb-6">
                                        <input type="text" id="eventSearch" onkeyup="filterEvents()" placeholder="Etkinlik adı, topluluk adı veya açıklama ile arama yapın..." class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-cyan-500">
                                    </div>
                                    
                                    <?php 
                                    // PERFORMANS: Lazy loading için ilk yüklemede sadece ilk 30 etkinlik
                                    $displayed_events = array_slice($all_events, 0, 30);
                                    $has_more_events = count($all_events) > 30;
                                    ?>
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6" id="eventsList">
                                        <?php foreach ($displayed_events as $event): ?>
                                            <div class="event-item" data-title="<?= strtolower(htmlspecialchars($event['title'])) ?>" data-community="<?= strtolower(htmlspecialchars($community_details[$event['community']]['name'] ?? $event['community'])) ?>" data-description="<?= strtolower(htmlspecialchars($event['description'] ?? '')) ?>">
                                            <div class="bg-gradient-to-br from-cyan-50 to-blue-50 p-6 rounded-lg border border-cyan-200">
                                                <div class="flex items-start justify-between mb-4">
                                                    <div class="flex-1">
                                                        <h3 class="text-lg font-semibold text-gray-800 mb-2"><?= htmlspecialchars($event['title']) ?></h3>
                                                        <p class="text-sm text-gray-600 mb-2"><?= htmlspecialchars($event['description'] ?: 'Açıklama yok') ?></p>
                            </div>
                                                    <span class="px-2 py-1 text-xs bg-cyan-100 text-cyan-700 rounded-full">
                                                        <?= htmlspecialchars($community_details[$event['community']]['name']) ?>
                                                    </span>
                        </div>
                                                
                                                <div class="space-y-2 text-sm text-gray-600">
                                                    <div class="flex items-center">
                                                        <svg class="w-4 h-4 mr-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"></path>
                                                        </svg>
                                                        <span><?= date('d.m.Y', strtotime($event['date'])) ?></span>
                                                    </div>
                                                    
                                                    <?php if ($event['time']): ?>
                                                    <div class="flex items-center">
                                                        <svg class="w-4 h-4 mr-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                                        </svg>
                                                        <span><?= htmlspecialchars($event['time']) ?></span>
                                                    </div>
                                                    <?php endif; ?>
                                                    
                                                    <?php if ($event['location']): ?>
                                                    <div class="flex items-center">
                                                        <svg class="w-4 h-4 mr-2 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M17.657 16.657L13.414 20.9a1.998 1.998 0 01-2.827 0l-4.244-4.243a8 8 0 1111.314 0z"></path>
                                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 11a3 3 0 11-6 0 3 3 0 016 0z"></path>
                                                        </svg>
                                                        <span><?= htmlspecialchars($event['location']) ?></span>
                                                    </div>
                                                    <?php endif; ?>
                                                </div>
                                                
                                                <div class="mt-4 flex items-center justify-between">
                                                    <span class="text-xs text-gray-500">
                                                        <?= $event['is_active'] ? 'Aktif' : 'Pasif' ?>
                                                    </span>
                                                    <a href="?action=auto_login&community=<?= urlencode($event['community']) ?>" target="_blank" class="text-xs text-cyan-600 hover:text-cyan-800 font-medium">
                                                        Topluluğa Git →
                                                    </a>
                                                </div>
                                            </div>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                    
                                    <!-- Lazy Loading: Daha Fazla Yükle Butonu -->
                                    <?php if (isset($has_more_events) && $has_more_events): ?>
                                    <div class="mt-6 text-center p-6" id="loadMoreEventsContainer">
                                        <button onclick="loadMoreSuperadminEvents()" id="loadMoreSuperadminEventsBtn" 
                                                class="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-semibold shadow-sm transition duration-200 flex items-center gap-2 mx-auto">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                            </svg>
                                            <span>Daha Fazla Etkinlik Yükle</span>
                                        </button>
                                        <div id="superadminEventsLoadingSpinner" class="hidden mt-4">
                                            <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-600"></div>
                                            <p class="text-gray-600 mt-2">Yükleniyor...</p>
                                        </div>
                                    </div>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                        
                        <!-- Topluluk Bazında Etkinlikler -->
                        <?php if (!empty($communities)): ?>
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800">Topluluk Bazında Etkinlikler</h3>
                            </div>
                            <div class="p-6">
                                <div class="space-y-6">
                                    <?php foreach ($communities as $community): ?>
                                        <div class="border border-gray-200 rounded-lg p-4">
                                            <div class="flex items-center justify-between mb-4">
                                                <h4 class="text-lg font-semibold text-gray-800"><?= htmlspecialchars($community_details[$community]['name']) ?></h4>
                                                <span class="px-3 py-1 text-sm bg-blue-100 text-blue-700 rounded-full">
                                                    <?= count($community_events[$community]) ?> etkinlik
                                                </span>
                                            </div>
                                            
                                            <?php if (empty($community_events[$community])): ?>
                                                <p class="text-gray-500 text-sm">Bu toplulukta henüz etkinlik bulunmuyor</p>
                                            <?php else: ?>
                                                <div class="space-y-3">
                                                    <?php foreach (array_slice($community_events[$community], 0, 3) as $event): ?>
                                                        <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                            <div>
                                                                <h5 class="font-medium text-gray-800"><?= htmlspecialchars($event['title']) ?></h5>
                                                                <p class="text-sm text-gray-600"><?= date('d.m.Y', strtotime($event['date'])) ?> <?= $event['time'] ? ' - ' . $event['time'] : '' ?></p>
                                                            </div>
                                                            <span class="text-xs px-2 py-1 rounded-full <?= $event['is_active'] ? 'bg-green-100 text-green-700' : 'bg-gray-100 text-gray-700' ?>">
                                                                <?= $event['is_active'] ? 'Aktif' : 'Pasif' ?>
                                                            </span>
                                                        </div>
                                                    <?php endforeach; ?>
                                                    
                                                    <?php if (count($community_events[$community]) > 3): ?>
                                                        <p class="text-sm text-gray-500 text-center">
                                                            +<?= count($community_events[$community]) - 3 ?> etkinlik daha
                                                        </p>
                                                    <?php endif; ?>
                                                </div>
                                            <?php endif; ?>
                                            
                                            <div class="mt-4">
                                                <a href="?action=auto_login&community=<?= urlencode($community) ?>" target="_blank" class="text-sm text-blue-600 hover:text-blue-800 font-medium">
                                                    Topluluğa Git →
                                                </a>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>

                <?php elseif ($current_view === 'reports'): ?>
                    <!-- Raporlar -->
                    <div class="space-y-8">
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h2 class="text-2xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-purple-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"></path></svg>
                                    Sistem Raporları
                                </h2>
                            </div>
                            <div class="p-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
                                    <div class="bg-blue-50 p-6 rounded-lg">
                                        <h3 class="text-lg font-semibold text-blue-800 mb-4">Topluluk İstatistikleri</h3>
                                        <div class="space-y-2">
                                            <div class="flex justify-between">
                                                <span class="text-blue-700">Toplam Topluluk:</span>
                                                <span class="font-bold text-blue-900"><?= $total_communities ?></span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-blue-700">Toplam Üye:</span>
                                                <span class="font-bold text-blue-900"><?= $total_members ?></span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-blue-700">Toplam Etkinlik:</span>
                                                <span class="font-bold text-blue-900"><?= $total_events ?></span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="bg-red-50 p-6 rounded-lg">
                                        <h3 class="text-lg font-semibold text-red-800 mb-4">Güvenlik Durumu</h3>
                                        <div class="space-y-2">
                                            <div class="flex justify-between">
                                                <span class="text-red-700">Banlı Kullanıcı:</span>
                                                <span class="font-bold text-red-900"><?= $total_banned ?></span>
                                            </div>
                                            <div class="flex justify-between">
                                                <span class="text-red-700">Sistem Durumu:</span>
                                                <span class="font-bold text-green-600">Aktif</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($current_view === 'logs'): ?>
                    <!-- Loglar & İzleme -->
                    <?php
                    // Veritabanını başlat (eğer tablolar yoksa oluştur)
                    initLogDatabase();
                    
                    // Eski logları temizle (90 günden eski loglar)
                    try {
                        $cleanup_db = new SQLite3(SUPERADMIN_DB);
                        $cleanup_db->exec('PRAGMA journal_mode = WAL');
                        
                        // 90 günden eski aktivite loglarını sil
                        $stmt = $cleanup_db->prepare("DELETE FROM activity_logs WHERE created_at < datetime('now', '-90 days')");
                        $stmt->execute();
                        
                        // 90 günden eski sistem loglarını sil
                        $stmt = $cleanup_db->prepare("DELETE FROM system_logs WHERE created_at < datetime('now', '-90 days')");
                        $stmt->execute();
                        
                        // 90 günden eski hata loglarını sil
                        $stmt = $cleanup_db->prepare("DELETE FROM error_logs WHERE created_at < datetime('now', '-90 days')");
                        $stmt->execute();
                        
                        // VACUUM yap (veritabanı boyutunu küçült)
                        $cleanup_db->exec('VACUUM');
                        $cleanup_db->close();
                    } catch (Exception $e) {
                        error_log("Log temizleme hatası: " . $e->getMessage());
                    }
                    
                    // Filtreleme parametreleri
                    $log_type = $_GET['log_type'] ?? 'all'; // all, activity, system, error
                    $community_filter = $_GET['community'] ?? 'all';
                    $date_from = $_GET['date_from'] ?? '';
                    $date_to = $_GET['date_to'] ?? '';
                    $search = $_GET['search'] ?? '';
                    $page = max(1, (int)($_GET['page'] ?? 1));
                    $per_page = 50;
                    $offset = ($page - 1) * $per_page;
                    
                    // Veritabanından logları çek
                    try {
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                    } catch (Exception $e) {
                        error_log("Log veritabanı hatası: " . $e->getMessage());
                        $db = null;
                    }
                    
                    // Activity Logs
                    $activity_logs = [];
                    if ($db && ($log_type === 'all' || $log_type === 'activity')) {
                        try {
                            $sql = "SELECT * FROM activity_logs WHERE 1=1";
                            $params = [];
                            
                            if ($community_filter !== 'all') {
                                $sql .= " AND community_name = ?";
                                $params[] = $community_filter;
                            }
                            
                            if ($date_from) {
                                $sql .= " AND DATE(created_at) >= ?";
                                $params[] = $date_from;
                            }
                            
                            if ($date_to) {
                                $sql .= " AND DATE(created_at) <= ?";
                                $params[] = $date_to;
                            }
                            
                            if ($search) {
                                $sql .= " AND (action_description LIKE ? OR username LIKE ? OR action_type LIKE ?)";
                                $search_param = "%$search%";
                                $params[] = $search_param;
                                $params[] = $search_param;
                                $params[] = $search_param;
                            }
                            
                            $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
                            $params[] = $per_page;
                            $params[] = $offset;
                            
                            $stmt = $db->prepare($sql);
                            if ($stmt) {
                                foreach ($params as $i => $param) {
                                    $stmt->bindValue($i + 1, $param, is_int($param) ? SQLITE3_INTEGER : SQLITE3_TEXT);
                                }
                                $result = $stmt->execute();
                                
                                if ($result) {
                                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                        $activity_logs[] = $row;
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            error_log("Activity logs sorgu hatası: " . $e->getMessage());
                        }
                    }
                    
                    // System Logs
                    $system_logs = [];
                    if ($db && ($log_type === 'all' || $log_type === 'system')) {
                        try {
                            $sql = "SELECT * FROM system_logs WHERE 1=1";
                            $params = [];
                            
                            if ($community_filter !== 'all') {
                                $sql .= " AND community_name = ?";
                                $params[] = $community_filter;
                            }
                            
                            if ($date_from) {
                                $sql .= " AND DATE(created_at) >= ?";
                                $params[] = $date_from;
                            }
                            
                            if ($date_to) {
                                $sql .= " AND DATE(created_at) <= ?";
                                $params[] = $date_to;
                            }
                            
                            if ($search) {
                                $sql .= " AND (message LIKE ? OR log_category LIKE ?)";
                                $search_param = "%$search%";
                                $params[] = $search_param;
                                $params[] = $search_param;
                            }
                            
                            $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
                            $params[] = $per_page;
                            $params[] = $offset;
                            
                            $stmt = $db->prepare($sql);
                            if ($stmt) {
                                foreach ($params as $i => $param) {
                                    $stmt->bindValue($i + 1, $param, is_int($param) ? SQLITE3_INTEGER : SQLITE3_TEXT);
                                }
                                $result = $stmt->execute();
                                
                                if ($result) {
                                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                        $system_logs[] = $row;
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            error_log("System logs sorgu hatası: " . $e->getMessage());
                        }
                    }
                    
                    // Error Logs
                    $error_logs = [];
                    if ($db && ($log_type === 'all' || $log_type === 'error')) {
                        try {
                            $sql = "SELECT * FROM error_logs WHERE 1=1";
                            $params = [];
                            
                            if ($community_filter !== 'all') {
                                $sql .= " AND community_name = ?";
                                $params[] = $community_filter;
                            }
                            
                            if ($date_from) {
                                $sql .= " AND DATE(created_at) >= ?";
                                $params[] = $date_from;
                            }
                            
                            if ($date_to) {
                                $sql .= " AND DATE(created_at) <= ?";
                                $params[] = $date_to;
                            }
                            
                            if ($search) {
                                $sql .= " AND (error_message LIKE ? OR error_type LIKE ?)";
                                $search_param = "%$search%";
                                $params[] = $search_param;
                                $params[] = $search_param;
                            }
                            
                            $sql .= " ORDER BY created_at DESC LIMIT ? OFFSET ?";
                            $params[] = $per_page;
                            $params[] = $offset;
                            
                            $stmt = $db->prepare($sql);
                            if ($stmt) {
                                foreach ($params as $i => $param) {
                                    $stmt->bindValue($i + 1, $param, is_int($param) ? SQLITE3_INTEGER : SQLITE3_TEXT);
                                }
                                $result = $stmt->execute();
                                
                                if ($result) {
                                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                        $error_logs[] = $row;
                                    }
                                }
                            }
                        } catch (Exception $e) {
                            error_log("Error logs sorgu hatası: " . $e->getMessage());
                        }
                    }
                    
                    // Toplam sayıları al
                    if ($db) {
                        $total_activity = $db->querySingle("SELECT COUNT(*) FROM activity_logs") ?: 0;
                        $total_system = $db->querySingle("SELECT COUNT(*) FROM system_logs") ?: 0;
                        $total_errors = $db->querySingle("SELECT COUNT(*) FROM error_logs") ?: 0;
                        $db->close();
                    } else {
                        $total_activity = 0;
                        $total_system = 0;
                        $total_errors = 0;
                        $activity_logs = [];
                        $system_logs = [];
                        $error_logs = [];
                    }
                    ?>
                    
                    <div class="space-y-6">
                        <!-- Bilgi Mesajı -->
                        <?php if (empty($activity_logs) && empty($system_logs) && empty($error_logs) && $log_type === 'all' && empty($search) && $community_filter === 'all'): ?>
                        <div class="bg-blue-50 border border-blue-200 rounded-xl p-6">
                            <div class="flex items-start">
                                <svg class="w-6 h-6 text-blue-600 mr-3 mt-1 flex-shrink-0" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <div>
                                    <h3 class="text-lg font-semibold text-blue-800">Henüz log kaydı yok</h3>
                                    <p class="text-blue-700 mt-1">Sistem aktiviteleri burada görünecek. Bir etkinlik oluşturduğunuzda, üye eklediğinizde veya herhangi bir admin işlemi yaptığınızda loglar burada görünecektir.</p>
                                    <p class="text-sm text-blue-600 mt-2">Test için bir toplulukta etkinlik oluşturmayı deneyin.</p>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                        
                        <!-- Filtreleme Formu -->
                        <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                            <h2 class="text-xl font-semibold text-gray-800 mb-4">Log Filtreleme</h2>
                            <form method="GET" action="index.php" class="grid grid-cols-1 md:grid-cols-5 gap-4">
                                <input type="hidden" name="view" value="logs">
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Log Türü</label>
                                    <select name="log_type" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                        <option value="all" <?= $log_type === 'all' ? 'selected' : '' ?>>Tümü</option>
                                        <option value="activity" <?= $log_type === 'activity' ? 'selected' : '' ?>>Aktivite Logları</option>
                                        <option value="system" <?= $log_type === 'system' ? 'selected' : '' ?>>Sistem Logları</option>
                                        <option value="error" <?= $log_type === 'error' ? 'selected' : '' ?>>Hata Logları</option>
                                    </select>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Topluluk</label>
                                    <select name="community" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                        <option value="all" <?= $community_filter === 'all' ? 'selected' : '' ?>>Tümü</option>
                                        <?php foreach ($communities as $comm): ?>
                                            <option value="<?= htmlspecialchars($comm) ?>" <?= $community_filter === $comm ? 'selected' : '' ?>><?= htmlspecialchars($comm) ?></option>
                                        <?php endforeach; ?>
                                    </select>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Başlangıç Tarihi</label>
                                    <input type="date" name="date_from" value="<?= htmlspecialchars($date_from) ?>" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Bitiş Tarihi</label>
                                    <input type="date" name="date_to" value="<?= htmlspecialchars($date_to) ?>" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-1">Arama</label>
                                    <input type="text" name="search" value="<?= htmlspecialchars($search) ?>" placeholder="Ara..." class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:outline-none focus:ring-2 focus:ring-blue-500">
                                </div>
                                
                                <div class="md:col-span-5 flex gap-2">
                                    <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">Filtrele</button>
                                    <a href="?view=logs" class="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300">Temizle</a>
                                </div>
                            </form>
                        </div>
                        
                        <!-- Özet İstatistikler -->
                        <div class="grid grid-cols-1 md:grid-cols-3 gap-4">
                            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm font-medium text-gray-500">Toplam Aktivite</p>
                                        <p class="text-3xl font-bold text-gray-900 mt-2"><?= number_format($total_activity) ?></p>
                                    </div>
                                    <div class="p-3 bg-blue-100 rounded-lg">
                                        <svg class="w-8 h-8 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm font-medium text-gray-500">Sistem Olayları</p>
                                        <p class="text-3xl font-bold text-gray-900 mt-2"><?= number_format($total_system) ?></p>
                                    </div>
                                    <div class="p-3 bg-green-100 rounded-lg">
                                        <svg class="w-8 h-8 text-green-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                            
                            <div class="bg-white rounded-xl shadow-sm border border-gray-200 p-6">
                                <div class="flex items-center justify-between">
                                    <div>
                                        <p class="text-sm font-medium text-gray-500">Hata Logları</p>
                                        <p class="text-3xl font-bold text-gray-900 mt-2"><?= number_format($total_errors) ?></p>
                                    </div>
                                    <div class="p-3 bg-red-100 rounded-lg">
                                        <svg class="w-8 h-8 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                        </svg>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Tab Navigation -->
                        <div class="bg-white rounded-xl shadow-sm border border-gray-200">
                            <div class="border-b border-gray-200">
                                <nav class="flex -mb-px" id="logTabs">
                                    <button onclick="switchLogTab('activity')" id="tab-activity" class="log-tab-btn active px-6 py-4 text-sm font-medium border-b-2 border-blue-600 text-blue-600">
                                        Aktivite Logları (<?= count($activity_logs) ?>)
                                    </button>
                                    <button onclick="switchLogTab('system')" id="tab-system" class="log-tab-btn px-6 py-4 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">
                                        Sistem Logları (<?= count($system_logs) ?>)
                                    </button>
                                    <button onclick="switchLogTab('error')" id="tab-error" class="log-tab-btn px-6 py-4 text-sm font-medium border-b-2 border-transparent text-gray-500 hover:text-gray-700">
                                        Hata Logları (<?= count($error_logs) ?>)
                                    </button>
                                </nav>
                            </div>
                            
                            <!-- Activity Logs Tab -->
                            <div id="tab-content-activity" class="log-tab-content p-6">
                                <div class="overflow-x-auto">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50">
                                            <tr>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tarih/Saat</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Topluluk</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Kullanıcı</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">İşlem Türü</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Açıklama</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Detaylar</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Adresi</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            <?php if (empty($activity_logs)): ?>
                                                <tr>
                                                    <td colspan="7" class="px-4 py-8 text-center text-gray-500">Aktivite logu bulunamadı</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($activity_logs as $log): ?>
                                                <tr class="hover:bg-gray-50">
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= date('d.m.Y H:i:s', strtotime($log['created_at'])) ?></td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['community_name'] ?? 'Sistem') ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?= $log['user_type'] === 'admin' ? 'bg-blue-100 text-blue-800' : 'bg-gray-100 text-gray-800' ?>">
                                                            <?= htmlspecialchars($log['username'] ?? 'N/A') ?>
                                                        </span>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['action_type']) ?></td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['action_description']) ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <?php 
                                                        if (!empty($log['additional_data'])) {
                                                            $additional = json_decode($log['additional_data'], true);
                                                            if ($additional && is_array($additional)) {
                                                                // IP adresini de ekle
                                                                $additional['ip_address'] = $log['ip_address'] ?? 'N/A';
                                                                $additional['user_agent'] = $log['user_agent'] ?? 'N/A';
                                                                $json_data = htmlspecialchars(json_encode($additional), ENT_QUOTES);
                                                                echo '<button onclick="showLogDetails(' . $json_data . ', \'' . htmlspecialchars($log['action_type'], ENT_QUOTES) . '\')" class="px-2 py-1 text-xs bg-blue-100 text-blue-700 rounded hover:bg-blue-200 transition">Detayları Gör</button>';
                                                            }
                                                        } else {
                                                            echo '<span class="text-xs text-gray-400">-</span>';
                                                        }
                                                        ?>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800 font-mono">
                                                            <?= htmlspecialchars($log['ip_address'] ?? 'N/A') ?>
                                                        </span>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <!-- System Logs Tab -->
                            <div id="tab-content-system" class="log-tab-content hidden p-6">
                                <div class="overflow-x-auto">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50">
                                            <tr>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tarih/Saat</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Seviye</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Kategori</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Mesaj</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Topluluk</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Adresi</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            <?php if (empty($system_logs)): ?>
                                                <tr>
                                                    <td colspan="6" class="px-4 py-8 text-center text-gray-500">Sistem logu bulunamadı</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($system_logs as $log): ?>
                                                <tr class="hover:bg-gray-50">
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= date('d.m.Y H:i:s', strtotime($log['created_at'])) ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium <?php
                                                            echo match($log['log_level']) {
                                                                'error' => 'bg-red-100 text-red-800',
                                                                'warning' => 'bg-yellow-100 text-yellow-800',
                                                                'info' => 'bg-blue-100 text-blue-800',
                                                                'success' => 'bg-green-100 text-green-800',
                                                                default => 'bg-gray-100 text-gray-800'
                                                            };
                                                        ?>">
                                                            <?= htmlspecialchars(strtoupper($log['log_level'])) ?>
                                                        </span>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['log_category'] ?? 'Genel') ?></td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['message']) ?></td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['community_name'] ?? 'Sistem') ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <?php 
                                                        // Sistem loglarında IP adresi context'te olabilir
                                                        $context = !empty($log['context']) ? json_decode($log['context'], true) : [];
                                                        $ip_address = $context['ip_address'] ?? 'N/A';
                                                        ?>
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800 font-mono">
                                                            <?= htmlspecialchars($ip_address) ?>
                                                        </span>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            
                            <!-- Error Logs Tab -->
                            <div id="tab-content-error" class="log-tab-content hidden p-6">
                                <div class="overflow-x-auto">
                                    <table class="min-w-full divide-y divide-gray-200">
                                        <thead class="bg-gray-50">
                                            <tr>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Tarih/Saat</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Hata Türü</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Mesaj</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Dosya</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Satır</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">Topluluk</th>
                                                <th class="px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase">IP Adresi</th>
                                            </tr>
                                        </thead>
                                        <tbody class="bg-white divide-y divide-gray-200">
                                            <?php if (empty($error_logs)): ?>
                                                <tr>
                                                    <td colspan="7" class="px-4 py-8 text-center text-gray-500">Hata logu bulunamadı</td>
                                                </tr>
                                            <?php else: ?>
                                                <?php foreach ($error_logs as $log): ?>
                                                <tr class="hover:bg-red-50">
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= date('d.m.Y H:i:s', strtotime($log['created_at'])) ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-100 text-red-800">
                                                            <?= htmlspecialchars($log['error_type']) ?>
                                                        </span>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm text-gray-900">
                                                        <div class="max-w-md truncate" title="<?= htmlspecialchars($log['error_message']) ?>">
                                                            <?= htmlspecialchars($log['error_message']) ?>
                                                        </div>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm text-gray-500">
                                                        <?php if ($log['error_file']): ?>
                                                            <div class="max-w-xs truncate" title="<?= htmlspecialchars($log['error_file']) ?>">
                                                                <?= htmlspecialchars(basename($log['error_file'])) ?>
                                                            </div>
                                                        <?php else: ?>
                                                            N/A
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="px-4 py-3 text-sm text-gray-500"><?= $log['error_line'] ?? 'N/A' ?></td>
                                                    <td class="px-4 py-3 text-sm text-gray-900"><?= htmlspecialchars($log['community_name'] ?? 'Sistem') ?></td>
                                                    <td class="px-4 py-3 text-sm">
                                                        <span class="inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium bg-orange-100 text-orange-800 font-mono">
                                                            <?= htmlspecialchars($log['ip_address'] ?? 'N/A') ?>
                                                        </span>
                                                    </td>
                                                </tr>
                                                <?php endforeach; ?>
                                            <?php endif; ?>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                        </div>
                    </div>
                    
                    <script>
                    function switchLogTab(tab) {
                        // Tüm tab butonlarını ve içeriklerini gizle
                        document.querySelectorAll('.log-tab-btn').forEach(btn => {
                            btn.classList.remove('active', 'border-blue-600', 'text-blue-600');
                            btn.classList.add('border-transparent', 'text-gray-500');
                        });
                        document.querySelectorAll('.log-tab-content').forEach(content => {
                            content.classList.add('hidden');
                        });
                        
                        // Seçili tab'ı göster
                        document.getElementById('tab-' + tab).classList.add('active', 'border-blue-600', 'text-blue-600');
                        document.getElementById('tab-' + tab).classList.remove('border-transparent', 'text-gray-500');
                        document.getElementById('tab-content-' + tab).classList.remove('hidden');
                    }
                    
                    function showLogDetails(data, actionType) {
                        const modal = document.getElementById('logDetailsModal');
                        const content = document.getElementById('logDetailsContent');
                        const title = document.getElementById('logDetailsTitle');
                        
                        // Modal başlığını ayarla
                        const actionNames = {
                            'email_send': 'E-posta Gönderimi Detayları',
                            'event_create': 'Etkinlik Oluşturma Detayları',
                            'event_update': 'Etkinlik Güncelleme Detayları',
                            'event_delete': 'Etkinlik Silme Detayları',
                            'member_add': 'Üye Ekleme Detayları',
                            'member_update': 'Üye Güncelleme Detayları',
                            'member_delete': 'Üye Silme Detayları'
                        };
                        title.textContent = actionNames[actionType] || 'Log Detayları';
                        
                        let html = '<div class="space-y-4">';
                        
                        // E-posta gönderimi için özel format
                        if (actionType === 'email_send') {
                            html += '<div class="grid grid-cols-2 gap-4">';
                            html += '<div><strong class="text-gray-700 block mb-1">Konu:</strong> <span class="text-gray-900">' + (data.subject || 'N/A') + '</span></div>';
                            html += '<div><strong class="text-gray-700 block mb-1">Alıcı Sayısı:</strong> <span class="text-gray-900">' + (data.recipient_count || 0) + '</span></div>';
                            html += '<div><strong class="text-gray-700 block mb-1">Gönderen Adı:</strong> <span class="text-gray-900">' + (data.from_name || 'N/A') + '</span></div>';
                            html += '<div><strong class="text-gray-700 block mb-1">Gönderen E-posta:</strong> <span class="text-gray-900">' + (data.from_email || 'N/A') + '</span></div>';
                            html += '</div>';
                            
                            if (data.recipients && data.recipients.length > 0) {
                                html += '<div class="border-t pt-4"><strong class="text-gray-700 block mb-2">Alıcılar (İlk 10):</strong><ul class="list-disc list-inside text-gray-900 bg-gray-50 p-3 rounded-lg">';
                                data.recipients.forEach(email => {
                                    html += '<li class="py-1">' + email + '</li>';
                                });
                                html += '</ul></div>';
                            }
                            
                            html += '<div class="border-t pt-4"><strong class="text-gray-700 block mb-2">E-posta İçeriği:</strong><div class="mt-2 p-4 bg-gray-50 rounded-lg text-gray-900 whitespace-pre-wrap max-h-96 overflow-y-auto">' + (data.message_full || data.message_preview || 'N/A') + '</div></div>';
                        }
                        // Etkinlik işlemleri için
                        else if (actionType === 'event_create' || actionType === 'event_update' || actionType === 'event_delete') {
                            html += '<div class="grid grid-cols-2 gap-4">';
                            if (data.event_id) {
                                html += '<div><strong class="text-gray-700 block mb-1">Etkinlik ID:</strong> <span class="text-gray-900">' + data.event_id + '</span></div>';
                            }
                            if (data.event_title) {
                                html += '<div><strong class="text-gray-700 block mb-1">Etkinlik Başlığı:</strong> <span class="text-gray-900">' + data.event_title + '</span></div>';
                            }
                            html += '</div>';
                            
                            // Önemli alanları önce göster
                            const importantFields = ['category', 'status', 'location', 'date', 'time', 'organizer', 'cost', 'capacity'];
                            importantFields.forEach(key => {
                                if (data[key] !== undefined && data[key] !== null && data[key] !== '') {
                                    html += '<div class="grid grid-cols-2 gap-4 py-2 border-b border-gray-100"><div><strong class="text-gray-700">' + key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + ':</strong></div><div class="text-gray-900">' + data[key] + '</div></div>';
                                }
                            });
                            
                            // Diğer tüm alanları göster
                            Object.keys(data).forEach(key => {
                                if (!importantFields.includes(key) && key !== 'event_id' && key !== 'event_title') {
                                    let value = data[key];
                                    if (value !== undefined && value !== null && value !== '') {
                                        if (typeof value === 'object') {
                                            value = JSON.stringify(value, null, 2);
                                        }
                                        html += '<div class="grid grid-cols-2 gap-4 py-2 border-b border-gray-100"><div><strong class="text-gray-700">' + key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + ':</strong></div><div class="text-gray-900 break-words">' + value + '</div></div>';
                                    }
                                }
                            });
                        }
                        // Üye işlemleri için
                        else if (actionType === 'member_add' || actionType === 'member_update' || actionType === 'member_delete') {
                            html += '<div class="grid grid-cols-2 gap-4 mb-4">';
                            if (data.member_id) {
                                html += '<div><strong class="text-gray-700 block mb-1">Üye ID:</strong> <span class="text-gray-900">' + data.member_id + '</span></div>';
                            }
                            if (data.full_name) {
                                html += '<div><strong class="text-gray-700 block mb-1">Ad Soyad:</strong> <span class="text-gray-900 font-semibold">' + data.full_name + '</span></div>';
                            }
                            html += '</div>';
                            
                            // Diğer alanları göster
                            Object.keys(data).forEach(key => {
                                if (key !== 'member_id' && key !== 'full_name') {
                                    let value = data[key];
                                    if (value !== undefined && value !== null && value !== '') {
                                        html += '<div class="grid grid-cols-2 gap-4 py-2 border-b border-gray-100"><div><strong class="text-gray-700">' + key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + ':</strong></div><div class="text-gray-900">' + value + '</div></div>';
                                    }
                                }
                            });
                        }
                        // Diğer tüm işlemler için genel format
                        else {
                            Object.keys(data).forEach(key => {
                                let value = data[key];
                                if (Array.isArray(value)) {
                                    value = value.join(', ');
                                } else if (typeof value === 'object') {
                                    value = JSON.stringify(value, null, 2);
                                }
                                html += '<div class="grid grid-cols-2 gap-4 py-2 border-b border-gray-100 last:border-0">';
                                html += '<div><strong class="text-gray-700">' + key.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()) + ':</strong></div>';
                                html += '<div class="text-gray-900 break-words">' + (value || 'N/A') + '</div>';
                                html += '</div>';
                            });
                        }
                        
                        html += '</div>';
                        
                        // IP Adresi ve User Agent bilgilerini göster (güvenlik için)
                        if (data.ip_address || data.user_agent) {
                            html += '<div class="border-t pt-4 mt-4 bg-orange-50 rounded-lg p-4">';
                            html += '<h4 class="text-sm font-semibold text-orange-800 mb-2">🔒 Güvenlik Bilgileri</h4>';
                            if (data.ip_address) {
                                html += '<div class="mb-2"><strong class="text-orange-700 text-sm">IP Adresi:</strong> <span class="text-orange-900 font-mono text-sm">' + data.ip_address + '</span></div>';
                            }
                            if (data.user_agent && data.user_agent !== 'N/A') {
                                html += '<div><strong class="text-orange-700 text-sm">Tarayıcı/User Agent:</strong> <span class="text-orange-900 text-sm break-words">' + data.user_agent + '</span></div>';
                            }
                            html += '</div>';
                        }
                        
                        html += '</div>';
                        
                        content.innerHTML = html;
                        modal.classList.remove('hidden');
                        modal.classList.add('flex');
                    }
                    
                    function closeLogDetailsModal() {
                        const modal = document.getElementById('logDetailsModal');
                        modal.classList.add('hidden');
                        modal.classList.remove('flex');
                    }
                    </script>
                    
                    <!-- Log Detay Modal -->
                    <div id="logDetailsModal" class="fixed inset-0 bg-gray-900 bg-opacity-70 hidden items-center justify-center p-4 z-50">
                        <div class="bg-white rounded-xl shadow-xl max-w-4xl w-full max-h-[90vh] overflow-y-auto">
                            <div class="p-6 border-b border-gray-200 sticky top-0 bg-white z-10">
                                <div class="flex items-center justify-between">
                                    <h3 id="logDetailsTitle" class="text-xl font-semibold text-gray-800">Log Detayları</h3>
                                    <button onclick="closeLogDetailsModal()" class="text-gray-500 hover:text-gray-700 transition">
                                        <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                        </svg>
                                    </button>
                                </div>
                            </div>
                            <div class="p-6">
                                <div id="logDetailsContent"></div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($current_view === 'requests'): ?>
                    <!-- Topluluk Talepleri -->
                    <div class="space-y-8">
                        <div class="bg-white p-6 rounded-xl card-shadow">
                            <div class="flex items-center justify-between">
                                <div>
                                    <h2 class="text-2xl font-semibold text-gray-800 mb-2">Topluluk Kayıt Talepleri</h2>
                                    <p class="text-gray-600">Marketing sayfasından gelen topluluk kayıt taleplerini görüntüleyin ve onaylayın</p>
                                </div>
                            </div>
                        </div>

                        <?php
                        initLogDatabase();
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                        $db->exec("CREATE TABLE IF NOT EXISTS community_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, community_name TEXT NOT NULL, folder_name TEXT NOT NULL, university TEXT NOT NULL, admin_username TEXT NOT NULL, admin_password_hash TEXT NOT NULL, admin_email TEXT, status TEXT DEFAULT 'pending', admin_notes TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP, processed_at DATETIME, processed_by TEXT)");
                        
                        $requests = [];
                        $result = $db->query("SELECT * FROM community_requests ORDER BY created_at DESC");
                        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                            $requests[] = $row;
                        }
                        $db->close();
                        ?>

                        <!-- Bekleyen Talepler -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-yellow-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 8v4l3 3m6-3a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    Bekleyen Talepler
                                </h3>
                            </div>
                            <div class="p-6">
                                <?php
                                $pending_requests = array_filter($requests, function($r) { return $r['status'] === 'pending'; });
                                if (empty($pending_requests)):
                                ?>
                                    <div class="text-center py-8 text-gray-500">
                                        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z"></path>
                                        </svg>
                                        <p class="text-lg">Bekleyen talep yok</p>
                                    </div>
                                <?php else: ?>
                                    <div class="space-y-4">
                                        <?php foreach ($pending_requests as $req): ?>
                                            <div class="border border-gray-200 rounded-lg p-6 hover:shadow-md transition-shadow">
                                                <div class="flex items-start justify-between mb-4">
                                                    <div class="flex-1">
                                                        <h4 class="text-lg font-semibold text-gray-800 mb-2"><?= htmlspecialchars($req['community_name']) ?></h4>
                                                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm text-gray-600">
                                                            <div>
                                                                <span class="font-medium">Üniversite:</span> <?= htmlspecialchars($req['university']) ?>
                                                            </div>
                                                            <div>
                                                                <span class="font-medium">Klasör Adı:</span> <?= htmlspecialchars($req['folder_name']) ?>
                                                            </div>
                                                            <div>
                                                                <span class="font-medium">Admin Kullanıcı:</span> <?= htmlspecialchars($req['admin_username']) ?>
                                                            </div>
                                                            <?php if (!empty($req['admin_email'])): ?>
                                                            <div>
                                                                <span class="font-medium">Admin Email:</span> <?= htmlspecialchars($req['admin_email']) ?>
                                                            </div>
                                                            <?php endif; ?>
                                                            <div>
                                                                <span class="font-medium">Talep Tarihi:</span> <?= date('d.m.Y H:i', strtotime($req['created_at'])) ?>
                                                            </div>
                                                        </div>
                                                    </div>
                                                    <div class="ml-4 flex flex-col gap-2">
                                                        <form method="POST" action="" class="inline">
                                                            <?= get_csrf_field() ?>
                                                            <input type="hidden" name="action" value="approve_request">
                                                            <input type="hidden" name="request_id" value="<?= $req['id'] ?>">
                                                            <button type="submit" onclick="return confirm('Bu talebi onaylayıp topluluk oluşturmak istediğinizden emin misiniz?')" class="px-4 py-2 bg-green-500 text-white rounded-lg hover:bg-green-600 transition duration-150 text-sm font-semibold">
                                                                <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                                                </svg>
                                                                Onayla
                                                            </button>
                                                        </form>
                                                        <button onclick="openRejectModal(<?= $req['id'] ?>)" class="px-4 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 transition duration-150 text-sm font-semibold">
                                                            <svg class="w-4 h-4 inline mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                                            </svg>
                                                            Reddet
                                                        </button>
                                                    </div>
                                                </div>
                                            </div>
                                        <?php endforeach; ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>

                        <!-- İşlenmiş Talepler -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-gray-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                    </svg>
                                    İşlenmiş Talepler
                                </h3>
                            </div>
                            <div class="p-6">
                                <?php
                                $processed_requests = array_filter($requests, function($r) { return $r['status'] !== 'pending'; });
                                if (empty($processed_requests)):
                                ?>
                                    <div class="text-center py-8 text-gray-500">
                                        <p class="text-lg">İşlenmiş talep yok</p>
                                    </div>
                                <?php else: ?>
                                    <div class="overflow-x-auto">
                                        <table class="w-full text-sm text-left">
                                            <thead class="bg-gray-50">
                                                <tr>
                                                    <th class="px-4 py-3 font-semibold text-gray-700">Topluluk Adı</th>
                                                    <th class="px-4 py-3 font-semibold text-gray-700">Üniversite</th>
                                                    <th class="px-4 py-3 font-semibold text-gray-700">Durum</th>
                                                    <th class="px-4 py-3 font-semibold text-gray-700">İşlem Tarihi</th>
                                                    <th class="px-4 py-3 font-semibold text-gray-700">Notlar</th>
                                                </tr>
                                            </thead>
                                            <tbody>
                                                <?php foreach ($processed_requests as $req): ?>
                                                    <tr class="border-b border-gray-200 hover:bg-gray-50">
                                                        <td class="px-4 py-3"><?= htmlspecialchars($req['community_name']) ?></td>
                                                        <td class="px-4 py-3"><?= htmlspecialchars($req['university']) ?></td>
                                                        <td class="px-4 py-3">
                                                            <?php if ($req['status'] === 'approved'): ?>
                                                                <span class="px-2 py-1 bg-green-100 text-green-800 rounded-full text-xs font-semibold">Onaylandı</span>
                                                            <?php else: ?>
                                                                <span class="px-2 py-1 bg-red-100 text-red-800 rounded-full text-xs font-semibold">Reddedildi</span>
                                                            <?php endif; ?>
                                                        </td>
                                                        <td class="px-4 py-3"><?= $req['processed_at'] ? date('d.m.Y H:i', strtotime($req['processed_at'])) : '-' ?></td>
                                                        <td class="px-4 py-3"><?= htmlspecialchars($req['admin_notes'] ?? '-') ?></td>
                                                    </tr>
                                                <?php endforeach; ?>
                                            </tbody>
                                        </table>
                                    </div>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Reddetme Modal -->
                    <div id="rejectModal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50">
                        <div class="flex items-center justify-center min-h-screen p-4">
                            <div class="bg-white rounded-lg shadow-xl max-w-md w-full">
                                <div class="p-6 border-b border-gray-200">
                                    <h3 class="text-xl font-semibold text-gray-800">Talebi Reddet</h3>
                                </div>
                                <form method="POST" action="" class="p-6">
                                    <?= get_csrf_field() ?>
                                    <input type="hidden" name="action" value="reject_request">
                                    <input type="hidden" name="request_id" id="reject_request_id">
                                    <div class="mb-4">
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Reddetme Nedeni</label>
                                        <textarea name="reject_reason" id="reject_reason" rows="4" class="w-full p-3 border border-gray-300 rounded-lg" placeholder="Reddetme nedenini yazın..." required></textarea>
                                    </div>
                                    <div class="flex justify-end space-x-3">
                                        <button type="button" onclick="closeRejectModal()" class="px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50">
                                            İptal
                                        </button>
                                        <button type="submit" class="px-6 py-2 bg-red-500 text-white rounded-lg hover:bg-red-600 font-semibold">
                                            Reddet
                                        </button>
                                    </div>
                                </form>
                            </div>
                        </div>
                    </div>

                    <!-- QR Kod Modal -->
                    <div id="qrCodeModal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50">
                        <div class="flex items-center justify-center min-h-screen p-4">
                            <div class="bg-white rounded-xl shadow-xl max-w-md w-full">
                                <div class="p-6 border-b border-gray-200">
                                    <div class="flex items-center justify-between">
                                        <h3 id="qrCodeTitle" class="text-xl font-semibold text-gray-800">QR Kod</h3>
                                        <button onclick="closeQRCodeModal()" class="text-gray-400 hover:text-gray-600 transition">
                                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                            </svg>
                                        </button>
                                    </div>
                                </div>
                                <div class="p-6">
                                    <div class="flex flex-col items-center justify-center">
                                        <div class="bg-white p-4 rounded-lg border-2 border-gray-200 mb-4">
                                            <img id="qrCodeImage" src="" alt="QR Kod" class="w-64 h-64 mx-auto" style="display: none;">
                                        </div>
                                        <div class="w-full mb-4">
                                            <label class="block text-sm font-medium text-gray-700 mb-2">QR Kod URL'i:</label>
                                            <div class="flex items-center gap-2">
                                                <input type="text" id="qrCodeUrl" readonly class="flex-1 px-3 py-2 border border-gray-300 rounded-lg bg-gray-50 text-sm text-gray-700">
                                                <button onclick="copyQRUrl()" class="px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition text-sm font-semibold">
                                                    Kopyala
                                                </button>
                                            </div>
                                        </div>
                                        <div class="w-full">
                                            <a id="qrCodeLink" href="#" target="_blank" class="block w-full px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition text-center font-semibold">
                                                Linki Aç
                                            </a>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>

                    <script>
                        function openRejectModal(requestId) {
                            document.getElementById('reject_request_id').value = requestId;
                            document.getElementById('rejectModal').classList.remove('hidden');
                        }
                        
                        function closeRejectModal() {
                            document.getElementById('rejectModal').classList.add('hidden');
                            document.getElementById('reject_reason').value = '';
                        }
                        
                        document.getElementById('rejectModal').addEventListener('click', function(e) {
                            if (e.target === this) {
                                closeRejectModal();
                            }
                        });
                        
                        // QR Kod Fonksiyonları
                        function showCommunityQRCode(communityFolder, communityName) {
                            const modal = document.getElementById('qrCodeModal');
                            const qrImage = document.getElementById('qrCodeImage');
                            const qrTitle = document.getElementById('qrCodeTitle');
                            const qrUrlInput = document.getElementById('qrCodeUrl');
                            const qrLink = document.getElementById('qrCodeLink');
                            
                            if (!modal || !qrImage || !qrTitle) return;
                            
                            // Gerçek URL'i oluştur
                            const baseUrl = window.location.origin;
                            const communityUrl = baseUrl + '/communities/' + encodeURIComponent(communityFolder) + '/';
                            
                            qrTitle.textContent = communityName + ' - QR Kod';
                            qrUrlInput.value = communityUrl;
                            qrLink.href = communityUrl;
                            
                            // QR kod görselini oluştur
                            const qrApiUrl = '../api/qr_code.php?type=community&id=' + encodeURIComponent(communityFolder) + '&size=300';
                            
                            qrImage.onload = function() {
                                qrImage.style.display = 'block';
                            };
                            
                            qrImage.onerror = function() {
                                qrImage.style.display = 'none';
                                console.error('QR kod yüklenemedi');
                            };
                            
                            qrImage.src = qrApiUrl;
                            modal.classList.remove('hidden');
                        }
                        
                        function closeQRCodeModal() {
                            const modal = document.getElementById('qrCodeModal');
                            if (modal) {
                                modal.classList.add('hidden');
                            }
                        }
                        
                        function copyQRUrl() {
                            const qrUrlInput = document.getElementById('qrCodeUrl');
                            if (qrUrlInput) {
                                qrUrlInput.select();
                                qrUrlInput.setSelectionRange(0, 99999); // Mobil için
                                document.execCommand('copy');
                                
                                // Kopyalandı bildirimi
                                const btn = event.target;
                                const originalText = btn.textContent;
                                btn.textContent = 'Kopyalandı!';
                                btn.classList.add('bg-green-600', 'hover:bg-green-700');
                                btn.classList.remove('bg-purple-600', 'hover:bg-purple-700');
                                
                                setTimeout(function() {
                                    btn.textContent = originalText;
                                    btn.classList.remove('bg-green-600', 'hover:bg-green-700');
                                    btn.classList.add('bg-purple-600', 'hover:bg-purple-700');
                                }, 2000);
                            }
                        }
                        
                        // Modal dışına tıklanınca kapat
                        document.getElementById('qrCodeModal')?.addEventListener('click', function(e) {
                            if (e.target === this) {
                                closeQRCodeModal();
                            }
                        });
                    </script>

<!-- Superadmin Lazy Loading JavaScript -->
<script>
// Topluluklar için
let communitiesOffset = <?= isset($has_more_communities) && $has_more_communities ? 30 : 0 ?>;
let allCommunities = <?= json_encode($communities ?? []) ?>;
let isLoadingCommunities = false;

// TOPLULUK ARAMA - EN BASİT VE ÇALIŞIR VERSİYON
// Sayfa yüklendiğinde tanımla
(function() {
    window.doSearch = function() {
        try {
            const search = (document.getElementById('communitySearch') || {}).value.toLowerCase() || '';
            const university = (document.getElementById('filterUniversity') || {}).value.toLowerCase() || '';
            const status = (document.getElementById('filterStatus') || {}).value || 'all';
            const tier = (document.getElementById('filterTier') || {}).value || 'all';
            
            const items = document.querySelectorAll('.community-item');
            let visible = 0;
            
            items.forEach(function(item) {
                const name = (item.querySelector('h3')?.textContent || '').toLowerCase();
                const dataName = (item.getAttribute('data-name') || '').toLowerCase();
                const dataFolder = (item.getAttribute('data-folder') || '').toLowerCase();
                const dataUni = (item.getAttribute('data-university') || '').toLowerCase();
                const dataStatus = item.getAttribute('data-status') || '';
                const dataTier = item.getAttribute('data-tier') || 'none';
                
                const matchSearch = !search || name.includes(search) || dataName.includes(search) || dataFolder.includes(search) || dataUni.includes(search);
                const matchUni = !university || dataUni.includes(university);
                const matchStatus = status === 'all' || (status === 'active' && dataStatus === 'active') || (status === 'inactive' && dataStatus !== 'active');
                const matchTier = tier === 'all' || dataTier === tier;
                
                if (matchSearch && matchUni && matchStatus && matchTier) {
                    item.style.display = '';
                    visible++;
                } else {
                    item.style.display = 'none';
                }
            });
            
            const resultDiv = document.getElementById('searchResult');
            if (resultDiv) {
                if (search || university || status !== 'all' || tier !== 'all') {
                    resultDiv.textContent = visible + ' topluluk bulundu';
                    resultDiv.classList.remove('hidden');
                } else {
                    resultDiv.classList.add('hidden');
                }
            }
        } catch (e) {
            console.error('Arama hatası:', e);
        }
    };

    window.clearSearch = function() {
        try {
            const search = document.getElementById('communitySearch');
            const university = document.getElementById('filterUniversity');
            const status = document.getElementById('filterStatus');
            const tier = document.getElementById('filterTier');
            
            if (search) search.value = '';
            if (university) university.value = '';
            if (status) status.value = 'all';
            if (tier) tier.value = 'all';
            
            window.doSearch();
        } catch (e) {
            console.error('Temizleme hatası:', e);
        }
    };
    
    // Sayfa yüklendiğinde de tanımla (güvenlik için)
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', function() {
            // Zaten tanımlı, sadece emin ol
        });
    }
})();

function loadMoreCommunities() {
    if (isLoadingCommunities || !allCommunities || allCommunities.length === 0) return;
    
    isLoadingCommunities = true;
    const btn = document.getElementById('loadMoreCommunitiesBtn');
    const spinner = document.getElementById('communitiesLoadingSpinner');
    
    if (btn) btn.style.display = 'none';
    if (spinner) spinner.classList.remove('hidden');
    
    // Sayfa yenileme ile yükleme (AJAX yerine)
    setTimeout(() => {
        window.location.href = '?view=communities&offset=' + communitiesOffset;
    }, 100);
}

// Etkinlikler için
let eventsOffset = <?= isset($has_more_events) && $has_more_events ? 30 : 0 ?>;
let allEvents = <?= json_encode($all_events ?? []) ?>;
let isLoadingEvents = false;

function filterEvents() {
    const searchTerm = document.getElementById('eventSearch')?.value.toLowerCase() || '';
    const items = document.querySelectorAll('.event-item');
    
    items.forEach(item => {
        const title = item.getAttribute('data-title') || '';
        const community = item.getAttribute('data-community') || '';
        const description = item.getAttribute('data-description') || '';
        
        if (title.includes(searchTerm) || community.includes(searchTerm) || description.includes(searchTerm)) {
            item.style.display = '';
        } else {
            item.style.display = 'none';
        }
    });
}

function loadMoreSuperadminEvents() {
    if (isLoadingEvents || !allEvents || allEvents.length === 0) return;
    
    isLoadingEvents = true;
    const btn = document.getElementById('loadMoreSuperadminEventsBtn');
    const spinner = document.getElementById('superadminEventsLoadingSpinner');
    
    if (btn) btn.style.display = 'none';
    if (spinner) spinner.classList.remove('hidden');
    
    // Sayfa yenileme ile yükleme (AJAX yerine)
    setTimeout(() => {
        window.location.href = '?view=events&offset=' + eventsOffset;
    }, 100);
}
</script>

                <?php elseif ($current_view === 'verification_admin'): ?>
                    <?php
                    $verificationFilter = $_GET['status'] ?? '';
                    $allowedVerificationFilters = ['pending', 'approved', 'rejected'];
                    if (!in_array($verificationFilter, $allowedVerificationFilters, true)) {
                        $verificationFilter = '';
                    }

                    $verificationCounts = ['pending' => 0, 'approved' => 0, 'rejected' => 0, 'total' => 0];
                    $verificationItems = [];

                    foreach ($communities as $communityFolder) {
                        $db_path = COMMUNITIES_DIR . $communityFolder . '/unipanel.sqlite';
                        if (!file_exists($db_path)) {
                            continue;
                        }

                        try {
                            $communityDb = new SQLite3($db_path);
                            @$communityDb->exec('PRAGMA journal_mode = WAL');

                            $hasTable = @$communityDb->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='community_verifications'");
                            if (!$hasTable) {
                                $communityDb->close();
                                continue;
                            }

                            $countResult = $communityDb->query("SELECT status, COUNT(*) as cnt FROM community_verifications GROUP BY status");
                            $communityTotal = 0;
                            if ($countResult) {
                                while ($row = $countResult->fetchArray(SQLITE3_ASSOC)) {
                                    $statusKey = $row['status'] ?? '';
                                    $cnt = (int) ($row['cnt'] ?? 0);
                                    if (isset($verificationCounts[$statusKey])) {
                                        $verificationCounts[$statusKey] += $cnt;
                                    }
                                    $communityTotal += $cnt;
                                }
                            }
                            $verificationCounts['total'] += $communityTotal;

                            $sql = "SELECT id, community_id, status, document_path, notes, admin_notes, reviewed_at, created_at 
                                    FROM community_verifications";
                            if ($verificationFilter !== '') {
                                $sql .= " WHERE status = :status";
                            }
                            $sql .= " ORDER BY created_at DESC";
                            $stmt = $communityDb->prepare($sql);
                            if ($verificationFilter !== '') {
                                $stmt->bindValue(':status', $verificationFilter, SQLITE3_TEXT);
                            }
                            $result = $stmt->execute();
                            while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                                $row['community_folder'] = $communityFolder;
                                $row['community_name'] = $community_details[$communityFolder]['name'] ?? $communityFolder;
                                $verificationItems[] = $row;
                            }

                            $communityDb->close();
                        } catch (Exception $e) {
                            if (isset($communityDb) && $communityDb instanceof SQLite3) {
                                $communityDb->close();
                            }
                            continue;
                        }
                    }

                    if (count($verificationItems) > 1) {
                        usort($verificationItems, function ($a, $b) {
                            return strtotime($b['created_at'] ?? '0') <=> strtotime($a['created_at'] ?? '0');
                        });
                    }
                    $verificationItems = array_slice($verificationItems, 0, 200);

                    $verificationFilterLabels = [
                        '' => 'Tümü',
                        'pending' => 'Beklemede',
                        'approved' => 'Onaylandı',
                        'rejected' => 'Reddedildi'
                    ];

                    $verificationBadgeStyles = [
                        'pending' => 'bg-amber-100 text-amber-800',
                        'approved' => 'bg-emerald-100 text-emerald-700',
                        'rejected' => 'bg-rose-100 text-rose-700'
                    ];
                    ?>

                    <div class="space-y-8">
                        <div class="bg-white p-6 rounded-xl card-shadow flex flex-wrap items-center justify-between gap-4">
                            <div>
                                <h2 class="text-2xl font-semibold text-gray-800 mb-1">Topluluk Doğrulama Kuyruğu</h2>
                                <p class="text-gray-600">Tüm toplulukların yüklediği belgeleri tek yerden onaylayın</p>
                            </div>
                            <div class="flex items-center gap-2">
                                <?php foreach ($verificationFilterLabels as $key => $label): ?>
                                    <?php
                                    $isActiveFilter = ($key === $verificationFilter);
                                    $query = http_build_query(array_merge($_GET, ['view' => 'verification_admin', 'status' => $key]));
                                    ?>
                                    <a href="?<?= $query ?>" class="px-4 py-2 rounded-full text-xs font-semibold border <?= $isActiveFilter ? 'bg-blue-600 text-white border-blue-600' : 'bg-white text-gray-600 border-gray-200' ?>">
                                        <?= $label ?>
                                        <?php if ($key !== ''): ?>
                                            <span class="ml-1 text-[10px] font-bold"><?= $verificationCounts[$key] ?? 0 ?></span>
                                        <?php endif; ?>
                                    </a>
                                <?php endforeach; ?>
                            </div>
                        </div>

                        <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                            <?php
                            $summaryCards = [
                                ['label' => 'Bekleyen', 'value' => $verificationCounts['pending'], 'class' => 'bg-amber-50 border-amber-200 text-amber-700'],
                                ['label' => 'Onaylanan', 'value' => $verificationCounts['approved'], 'class' => 'bg-emerald-50 border-emerald-200 text-emerald-700'],
                                ['label' => 'Reddedilen', 'value' => $verificationCounts['rejected'], 'class' => 'bg-rose-50 border-rose-200 text-rose-700'],
                                ['label' => 'Toplam Talep', 'value' => $verificationCounts['total'], 'class' => 'bg-slate-50 border-slate-200 text-slate-700']
                            ];
                            ?>
                            <?php foreach ($summaryCards as $card): ?>
                                <div class="rounded-xl border <?= $card['class'] ?> p-4">
                                    <p class="text-xs uppercase tracking-[0.3em]"><?= $card['label'] ?></p>
                                    <p class="text-3xl font-bold mt-2"><?= (int) $card['value'] ?></p>
                                </div>
                            <?php endforeach; ?>
                        </div>

                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800 flex items-center gap-2">
                                    <svg class="w-5 h-5 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4.5l7 3V12c0 4.5-3 8.5-7 9-4-.5-7-4.5-7-9V7.5l7-3z"></path>
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9.5 12.5l2 2 3-3.5"></path>
                                    </svg>
                                    Son Başvurular
                                </h3>
                                <p class="text-sm text-gray-500">En yeni 200 başvuru listelenir</p>
                            </div>
                            <div class="overflow-x-auto">
                                <table class="min-w-full text-sm divide-y divide-gray-200">
                                    <thead class="bg-gray-50 text-xs uppercase text-gray-500">
                                        <tr>
                                            <th class="px-4 py-3 text-left font-semibold">Topluluk</th>
                                            <th class="px-4 py-3 text-left font-semibold">Belge & Not</th>
                                            <th class="px-4 py-3 text-left font-semibold">Durum</th>
                                            <th class="px-4 py-3 text-left font-semibold">İşlem</th>
                                        </tr>
                                    </thead>
                                    <tbody class="divide-y divide-gray-100">
                                        <?php if (empty($verificationItems)): ?>
                                            <tr>
                                                <td colspan="4" class="px-4 py-10 text-center text-gray-500">Henüz doğrulama talebi bulunamadı.</td>
                                            </tr>
                                        <?php else: ?>
                                            <?php foreach ($verificationItems as $item): ?>
                                                <?php
                                                $statusKey = $item['status'] ?? 'pending';
                                                $badgeClass = $verificationBadgeStyles[$statusKey] ?? 'bg-gray-100 text-gray-700';
                                                $statusLabels = [
                                                    'pending' => 'Beklemede',
                                                    'approved' => 'Onaylandı',
                                                    'rejected' => 'Reddedildi'
                                                ];
                                                $statusLabel = $statusLabels[$statusKey] ?? ucfirst($statusKey);
                                                $documentPath = $item['document_path'] ?? '';
                                                $documentUrl = '';
                                                if (!empty($documentPath)) {
                                                    $normalizedDoc = ltrim($documentPath, '/');
                                                    $documentUrl = '../communities/' . rawurlencode($item['community_folder']) . '/' . $normalizedDoc;
                                                }
                                                ?>
                                                <tr class="bg-white hover:bg-gray-50">
                                                    <td class="px-4 py-4 align-top">
                                                        <div class="font-semibold text-gray-900"><?= htmlspecialchars($item['community_name']) ?></div>
                                                        <p class="text-xs text-gray-500"><?= htmlspecialchars($item['community_folder']) ?></p>
                                                        <p class="text-xs text-gray-400 mt-2">Gönderim: <?= date('d.m.Y H:i', strtotime($item['created_at'] ?? 'now')) ?></p>
                                                    </td>
                                                    <td class="px-4 py-4 align-top">
                                                        <?php if ($documentUrl): ?>
                                                            <a href="<?= htmlspecialchars($documentUrl) ?>" target="_blank" class="inline-flex items-center text-indigo-600 font-semibold text-xs hover:underline">
                                                                PDF'i Aç
                                                                <svg class="w-3.5 h-3.5 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 17l9-9m0 0H8m8 0v8"></path>
                                                                </svg>
                                                            </a>
                                                        <?php else: ?>
                                                            <span class="text-xs text-gray-400">Belge yok</span>
                                                        <?php endif; ?>
                                                        <?php if (!empty($item['notes'])): ?>
                                                            <div class="mt-2 p-2 bg-gray-50 rounded text-xs text-gray-600 border border-gray-100">
                                                                <span class="font-semibold text-gray-700 block mb-1">Topluluk Notu</span>
                                                                <?= nl2br(htmlspecialchars($item['notes'])) ?>
                                                            </div>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="px-4 py-4 align-top">
                                                        <span class="inline-flex items-center px-3 py-1 rounded-full text-xs font-semibold <?= $badgeClass ?>">
                                                            <?= $statusLabel ?>
                                                        </span>
                                                        <?php if (!empty($item['reviewed_at'])): ?>
                                                            <p class="text-xs text-gray-400 mt-2">Güncellendi: <?= date('d.m.Y H:i', strtotime($item['reviewed_at'])) ?></p>
                                                        <?php endif; ?>
                                                    </td>
                                                    <td class="px-4 py-4 align-top">
                                                        <form method="POST" class="space-y-2 verification-admin-form">
                                                            <?= get_csrf_field() ?>
                                                            <input type="hidden" name="action" value="verification_admin_update">
                                                            <input type="hidden" name="community_folder" value="<?= htmlspecialchars($item['community_folder']) ?>">
                                                            <input type="hidden" name="request_id" value="<?= (int) ($item['id'] ?? 0) ?>">
                                                            <input type="hidden" name="new_status" value="">
                                                            <textarea name="admin_notes" rows="2" class="w-full border border-gray-200 rounded-lg text-xs p-2 focus:outline-none focus:ring-2 focus:ring-blue-500" placeholder="SuperAdmin notu..."><?= htmlspecialchars($item['admin_notes'] ?? '') ?></textarea>
                                                            <div class="flex flex-wrap gap-2">
                                                                <button type="button" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-emerald-100 text-emerald-700" data-verification-admin-status="approved">
                                                                    Onayla
                                                                </button>
                                                                <button type="button" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-rose-100 text-rose-700" data-verification-admin-status="rejected">
                                                                    Reddet
                                                                </button>
                                                                <button type="button" class="px-3 py-1.5 rounded-lg text-xs font-semibold bg-slate-100 text-slate-700" data-verification-admin-status="pending">
                                                                    Beklemeye Al
                                                                </button>
                                                            </div>
                                                        </form>
                                                    </td>
                                                </tr>
                                            <?php endforeach; ?>
                                        <?php endif; ?>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>

                    <script>
                        document.querySelectorAll('.verification-admin-form button[data-verification-admin-status]').forEach((button) => {
                            button.addEventListener('click', () => {
                                const form = button.closest('.verification-admin-form');
                                if (!form) return;
                                const statusInput = form.querySelector('input[name="new_status"]');
                                statusInput.value = button.getAttribute('data-verification-admin-status');
                                form.submit();
                            });
                        });
                    </script>

                <?php elseif ($current_view === 'notifications'): ?>
                    <!-- Bildirim Gönderme Sistemi -->
                    <div class="space-y-8">
                        <!-- Mesaj Gösterimi -->
                        <?php if (!empty($success)): ?>
                            <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded-lg">
                                <div class="flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                    </svg>
                                    <?= htmlspecialchars($success) ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($error)): ?>
                            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg">
                                <div class="flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                    <?= htmlspecialchars($error) ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        <!-- Bildirim Gönderme Formu -->
                        <div class="bg-white p-6 rounded-xl shadow-md">
                            <h2 class="text-2xl font-semibold text-gray-800 mb-6 flex items-center">
                                <svg class="w-6 h-6 mr-3 text-blue-500" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-5 5v-5zM4.828 7l2.586-2.586A2 2 0 018.828 4h6.344a2 2 0 011.414.586L19.172 7H4.828zM4 7v10a2 2 0 002 2h12a2 2 0 002-2V7H4z"></path>
                                </svg>
                                Topluluklara Bildirim Gönder
                            </h2>
                            
                            <form method="POST" action="index.php" class="space-y-6" onsubmit="return validateNotificationForm()">
                                <?= get_csrf_field() ?>
                                <input type="hidden" name="action" value="send_notification">
                                
                                <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
                                    <div>
                                        <label for="notification_title" class="block text-sm font-medium text-gray-700 mb-2">Bildirim Başlığı</label>
                                        <input type="text" name="notification_title" id="notification_title" required 
                                               class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" 
                                               placeholder="Örn: Sistem Güncellemesi">
                                    </div>
                                    
                           <div>
                               <label for="notification_type" class="block text-sm font-medium text-gray-700 mb-2">Bildirim Türü</label>
                               <select name="notification_type" id="notification_type" 
                                       class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500">
                                   <option value="info">Bilgi</option>
                                   <option value="success">Başarı</option>
                                   <option value="warning">Uyarı</option>
                                   <option value="error">Hata</option>
                                   <option value="urgent">Acil</option>
                               </select>
                           </div>
                                </div>
                                
                                <div>
                                    <label for="notification_message" class="block text-sm font-medium text-gray-700 mb-2">Bildirim Mesajı</label>
                                    <textarea name="notification_message" id="notification_message" rows="4" required 
                                              class="w-full p-3 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-blue-500" 
                                              placeholder="Bildirim içeriğinizi buraya yazın..."></textarea>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-3">Hedef Topluluklar</label>
                                    <div class="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
                                        <label class="flex items-center p-3 border border-gray-300 rounded-lg hover:bg-gray-50 cursor-pointer">
                                            <input type="checkbox" name="target_communities[]" value="all" class="mr-2 text-blue-600">
                                            <span class="text-sm font-medium">Tüm Topluluklar</span>
                                        </label>
                                        <?php foreach ($communities as $community): ?>
                                            <label class="flex items-center p-3 border border-gray-300 rounded-lg hover:bg-gray-50 cursor-pointer">
                                                <input type="checkbox" name="target_communities[]" value="<?= htmlspecialchars($community) ?>" class="mr-2 text-blue-600">
                                                <span class="text-sm font-medium"><?= htmlspecialchars($community) ?></span>
                                            </label>
                                        <?php endforeach; ?>
                                    </div>
                                </div>
                                
                                <!-- Acil Bildirim Seçeneği -->
                                <div class="bg-red-50 border border-red-200 rounded-lg p-4">
                                    <label class="flex items-center cursor-pointer">
                                        <input type="checkbox" name="is_urgent" id="is_urgent" class="mr-3 text-red-600 focus:ring-red-500">
                                        <div class="flex items-center">
                                            <svg class="w-6 h-6 mr-2 text-red-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"></path>
                                            </svg>
                                            <div>
                                                <span class="text-sm font-semibold text-red-800">Acil Bildirim</span>
                                                <p class="text-xs text-red-600 mt-1">Bu bildirim topluluklarda modal olarak görünecek ve kapatılamayacak</p>
                                            </div>
                                        </div>
                                    </label>
                                </div>
                                
                                <div class="flex items-center justify-between pt-4 border-t border-gray-200">
                                    <div class="flex items-center">
                                        <input type="checkbox" name="send_immediately" id="send_immediately" checked class="mr-2 text-blue-600">
                                        <label for="send_immediately" class="text-sm text-gray-700">Hemen gönder</label>
                                    </div>
                                    
                                    <button type="submit" class="px-6 py-3 bg-blue-600 text-white rounded-lg hover:bg-blue-700 font-semibold transition duration-200 flex items-center">
                                        <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8"></path>
                                        </svg>
                                        Bildirim Gönder
                                    </button>
                                </div>
                            </form>
                        </div>
                        
                        <!-- Bildirim Geçmişi -->
                        <div class="bg-white p-6 rounded-xl shadow-md">
                            <h3 class="text-xl font-semibold text-gray-800 mb-4">Son Gönderilen Bildirimler</h3>
                            <div class="space-y-4">
                                <!-- Burada bildirim geçmişi gösterilecek -->
                                <div class="text-center text-gray-500 py-8">
                                    <svg class="w-12 h-12 mx-auto mb-4 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-5 5v-5zM4.828 7l2.586-2.586A2 2 0 018.828 4h6.344a2 2 0 011.414.586L19.172 7H4.828zM4 7v10a2 2 0 002 2h12a2 2 0 002-2V7H4z"></path>
                                    </svg>
                                    <p>Henüz bildirim gönderilmemiş</p>
                                </div>
                            </div>
                        </div>
                    </div>

                <?php elseif ($current_view === 'contact_forms'): ?>
                    <!-- İletişim Formları -->
                    <?php
                    initLogDatabase();
                    $db = new SQLite3(SUPERADMIN_DB);
                    $db->exec('PRAGMA journal_mode = WAL');
                    $db->exec("CREATE TABLE IF NOT EXISTS contact_submissions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT NOT NULL,
                        email TEXT NOT NULL,
                        phone TEXT,
                        community TEXT,
                        message TEXT NOT NULL,
                        ip_address TEXT,
                        user_agent TEXT,
                        status TEXT DEFAULT 'new',
                        read_at DATETIME,
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )");
                    
                    // Mark as read action
                    if (isset($_GET['action']) && $_GET['action'] === 'mark_read' && isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $stmt = $db->prepare("UPDATE contact_submissions SET status = 'read', read_at = CURRENT_TIMESTAMP WHERE id = ?");
                        $stmt->bindValue(1, $id, SQLITE3_INTEGER);
                        $stmt->execute();
                        header("Location: ?view=contact_forms&success=" . urlencode('Mesaj okundu olarak işaretlendi'));
                        exit;
                    }
                    
                    // Delete action
                    if (isset($_GET['action']) && $_GET['action'] === 'delete' && isset($_GET['id'])) {
                        $id = (int)$_GET['id'];
                        $stmt = $db->prepare("DELETE FROM contact_submissions WHERE id = ?");
                        $stmt->bindValue(1, $id, SQLITE3_INTEGER);
                        $stmt->execute();
                        header("Location: ?view=contact_forms&success=" . urlencode('Mesaj silindi'));
                        exit;
                    }
                    
                    // Get all submissions
                    $filter = $_GET['filter'] ?? 'all';
                    $query = "SELECT * FROM contact_submissions ORDER BY created_at DESC";
                    if ($filter === 'new') {
                        $query = "SELECT * FROM contact_submissions WHERE status = 'new' ORDER BY created_at DESC";
                    } elseif ($filter === 'read') {
                        $query = "SELECT * FROM contact_submissions WHERE status = 'read' ORDER BY created_at DESC";
                    }
                    
                    $result = $db->query($query);
                    $submissions = [];
                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $submissions[] = $row;
                    }
                    
                    $new_count = $db->querySingle("SELECT COUNT(*) FROM contact_submissions WHERE status = 'new'");
                    $read_count = $db->querySingle("SELECT COUNT(*) FROM contact_submissions WHERE status = 'read'");
                    $total_count = $db->querySingle("SELECT COUNT(*) FROM contact_submissions");
                    $db->close();
                    ?>
                    <div class="space-y-6">
                        <div class="bg-white p-6 rounded-xl card-shadow">
                            <div class="flex items-center justify-between mb-6">
                                <div>
                                    <h2 class="text-2xl font-semibold text-gray-800 mb-2">İletişim Formları</h2>
                                    <p class="text-gray-600">Marketing sayfasından gelen iletişim formu mesajları</p>
                                </div>
                                <div class="flex gap-2">
                                    <a href="?view=contact_forms&filter=all" class="px-4 py-2 rounded-lg <?= $filter === 'all' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' ?> transition">
                                        Tümü (<?= $total_count ?>)
                                    </a>
                                    <a href="?view=contact_forms&filter=new" class="px-4 py-2 rounded-lg <?= $filter === 'new' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' ?> transition">
                                        Yeni (<?= $new_count ?>)
                                    </a>
                                    <a href="?view=contact_forms&filter=read" class="px-4 py-2 rounded-lg <?= $filter === 'read' ? 'bg-blue-500 text-white' : 'bg-gray-100 text-gray-700 hover:bg-gray-200' ?> transition">
                                        Okundu (<?= $read_count ?>)
                                    </a>
                                </div>
                            </div>
                            
                            <?php if (empty($submissions)): ?>
                                <div class="text-center py-12">
                                    <svg class="w-16 h-16 mx-auto text-gray-400 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 8l7.89 5.26a2 2 0 002.22 0L21 8M5 19h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z"></path>
                                    </svg>
                                    <p class="text-gray-500 text-lg">Henüz mesaj bulunmuyor</p>
                                </div>
                            <?php else: ?>
                                <div class="space-y-4">
                                    <?php foreach ($submissions as $submission): ?>
                                        <div class="border border-gray-200 rounded-lg p-6 hover:shadow-md transition <?= $submission['status'] === 'new' ? 'bg-blue-50 border-blue-200' : 'bg-white' ?>">
                                            <div class="flex items-start justify-between mb-4">
                                                <div class="flex-1">
                                                    <div class="flex items-center gap-3 mb-2">
                                                        <h3 class="text-lg font-semibold text-gray-800"><?= htmlspecialchars($submission['name']) ?></h3>
                                                        <?php if ($submission['status'] === 'new'): ?>
                                                            <span class="px-2 py-1 bg-blue-500 text-white text-xs font-bold rounded-full">Yeni</span>
                                                        <?php endif; ?>
                                                    </div>
                                                    <div class="space-y-1 text-sm text-gray-600">
                                                        <p><i class="fas fa-envelope mr-2"></i><?= htmlspecialchars($submission['email']) ?></p>
                                                        <?php if ($submission['phone']): ?>
                                                            <p><i class="fas fa-phone mr-2"></i><?= htmlspecialchars($submission['phone']) ?></p>
                                                        <?php endif; ?>
                                                        <?php if ($submission['community']): ?>
                                                            <p><i class="fas fa-users mr-2"></i><?= htmlspecialchars($submission['community']) ?></p>
                                                        <?php endif; ?>
                                                        <p><i class="fas fa-clock mr-2"></i><?= date('d.m.Y H:i', strtotime($submission['created_at'])) ?></p>
                                                    </div>
                                                </div>
                                                <div class="flex gap-2">
                                                    <?php if ($submission['status'] === 'new'): ?>
                                                        <a href="?view=contact_forms&action=mark_read&id=<?= $submission['id'] ?>" class="px-3 py-1 bg-green-500 text-white rounded-lg text-sm hover:bg-green-600 transition">
                                                            <i class="fas fa-check"></i> Okundu
                                                        </a>
                                                    <?php endif; ?>
                                                    <a href="mailto:<?= htmlspecialchars($submission['email']) ?>" class="px-3 py-1 bg-blue-500 text-white rounded-lg text-sm hover:bg-blue-600 transition">
                                                        <i class="fas fa-reply"></i> Yanıtla
                                                    </a>
                                                    <a href="?view=contact_forms&action=delete&id=<?= $submission['id'] ?>" onclick="return confirm('Bu mesajı silmek istediğinize emin misiniz?')" class="px-3 py-1 bg-red-500 text-white rounded-lg text-sm hover:bg-red-600 transition">
                                                        <i class="fas fa-trash"></i> Sil
                                                    </a>
                                                </div>
                                            </div>
                                            <div class="mt-4 p-4 bg-gray-50 rounded-lg">
                                                <p class="text-gray-700 whitespace-pre-wrap"><?= htmlspecialchars($submission['message']) ?></p>
                                            </div>
                                            <?php if ($submission['ip_address']): ?>
                                                <div class="mt-2 text-xs text-gray-400">
                                                    <i class="fas fa-info-circle"></i> IP: <?= htmlspecialchars($submission['ip_address']) ?>
                                                </div>
                                            <?php endif; ?>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            <?php endif; ?>
                        </div>
                    </div>

                <?php elseif ($current_view === 'ads'): ?>
                    <!-- Reklam Yönetimi -->
                    <div class="space-y-8">
                        <!-- Mesaj Gösterimi -->
                        <?php if (!empty($_GET['success'])): ?>
                            <div class="bg-green-100 border border-green-400 text-green-700 px-4 py-3 rounded-lg">
                                <div class="flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"></path>
                                    </svg>
                                    <?= htmlspecialchars($_GET['success']) ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <?php if (!empty($_GET['error'])): ?>
                            <div class="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded-lg">
                                <div class="flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                    <?= htmlspecialchars($_GET['error']) ?>
                                </div>
                            </div>
                        <?php endif; ?>
                        
                        <div class="bg-white p-6 rounded-xl card-shadow">
                            <div class="flex items-center justify-between">
                                <div>
                                    <h2 class="text-2xl font-semibold text-gray-800 mb-2">Reklam Yönetimi</h2>
                                    <p class="text-gray-600">Uygulamada gösterilecek reklamları yönetin</p>
                                </div>
                                <button onclick="openAddAdModal()" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition duration-200 font-medium flex items-center">
                                    <svg class="w-5 h-5 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"></path>
                                    </svg>
                                    Yeni Reklam Ekle
                                </button>
                            </div>
                        </div>

                        <?php
                        initLogDatabase();
                        $db = new SQLite3(SUPERADMIN_DB);
                        $db->exec('PRAGMA journal_mode = WAL');
                        
                        $ads = [];
                        $result = $db->query("SELECT * FROM ads ORDER BY priority DESC, created_at DESC");
                        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                            $ads[] = $row;
                        }
                        $db->close();
                        ?>

                        <!-- Reklam Listesi -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800">Reklamlar (<?= count($ads) ?>)</h3>
                            </div>
                            <div class="p-6">
                                <?php if (empty($ads)): ?>
                                    <div class="text-center py-8 text-gray-500">
                                        <svg class="w-16 h-16 mx-auto mb-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5.882V19.24a1.76 1.76 0 01-3.417.592l-2.147-6.15M18 13a3 3 0 100-6M5.436 13.683A4.001 4.001 0 017 6h1.832c4.1 0 7.625-1.234 9.168-3v14c-1.543-1.766-5.067-3-9.168-3H7a3.988 3.988 0 01-1.564-.317z"></path>
                                        </svg>
                                        <p class="text-lg">Henüz reklam eklenmemiş</p>
                                    </div>
                                <?php else: ?>
                                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                        <?php foreach ($ads as $ad): ?>
                                            <div class="border border-gray-200 rounded-lg overflow-hidden hover:shadow-lg transition duration-200">
                                                <!-- Reklam Görseli -->
                                                <div class="h-40 bg-gradient-to-br from-indigo-500 to-purple-600 relative">
                                                    <?php if (!empty($ad['image_url'])): ?>
                                                        <?php 
                                                        // Görsel URL'ini düzelt
                                                        $image_src = $ad['image_url'];
                                                        
                                                        // Eğer relative path ise (yüklenen fotoğraf), tam path'e çevir
                                                        if (strpos($image_src, '/assets/images/ads/') === 0) {
                                                            // Superadmin panelinden erişim için tam path
                                                            $image_src = '/unipanel' . $image_src;
                                                        } elseif (strpos($image_src, 'http://') !== 0 && strpos($image_src, 'https://') !== 0) {
                                                            // Eğer sadece dosya adı ise
                                                            $image_src = '/unipanel/assets/images/ads/' . basename($image_src);
                                                        }
                                                        ?>
                                                        <img src="<?= htmlspecialchars($image_src) ?>" alt="<?= htmlspecialchars($ad['title']) ?>" class="w-full h-full object-cover" onerror="this.style.display='none'; this.parentElement.style.background='linear-gradient(to bottom right, #6366f1, #8b5cf6)'">
                                                    <?php else: ?>
                                                        <!-- Görsel yoksa gradient göster -->
                                                        <div class="w-full h-full bg-gradient-to-br from-indigo-500 to-purple-600"></div>
                                                    <?php endif; ?>
                                                    <div class="absolute top-2 right-2">
                                                        <span class="px-2 py-1 text-xs font-bold text-white bg-black bg-opacity-50 rounded">
                                                            <?= $ad['status'] === 'active' ? 'Aktif' : 'Pasif' ?>
                                                        </span>
                                                    </div>
                                                    <div class="absolute bottom-0 left-0 right-0 bg-gradient-to-t from-black to-transparent p-4">
                                                        <h4 class="text-white font-bold text-sm line-clamp-1"><?= htmlspecialchars($ad['title']) ?></h4>
                                                    </div>
                                                </div>
                                                
                                                <!-- Reklam Detayları -->
                                                <div class="p-4">
                                                    <p class="text-sm text-gray-600 mb-2 line-clamp-2"><?= htmlspecialchars($ad['description']) ?></p>
                                                    <div class="flex items-center justify-between text-xs text-gray-500 mb-3">
                                                        <span><?= htmlspecialchars($ad['advertiser']) ?></span>
                                                        <?php if ($ad['rating']): ?>
                                                            <span class="flex items-center">
                                                                <svg class="w-3 h-3 mr-1 text-yellow-500" fill="currentColor" viewBox="0 0 20 20">
                                                                    <path d="M9.049 2.927c.3-.921 1.603-.921 1.902 0l1.07 3.292a1 1 0 00.95.69h3.462c.969 0 1.371 1.24.588 1.81l-2.8 2.034a1 1 0 00-.364 1.118l1.07 3.292c.3.921-.755 1.688-1.54 1.118l-2.8-2.034a1 1 0 00-1.175 0l-2.8 2.034c-.784.57-1.838-.197-1.539-1.118l1.07-3.292a1 1 0 00-.364-1.118L2.98 8.72c-.783-.57-.38-1.81.588-1.81h3.461a1 1 0 00.951-.69l1.07-3.292z"></path>
                                                                </svg>
                                                                <?= number_format($ad['rating'], 1) ?>
                                                            </span>
                                                        <?php endif; ?>
                                                    </div>
                                                    <div class="flex items-center gap-2">
                                                        <button onclick="openEditAdModal(<?= $ad['id'] ?>, <?= htmlspecialchars(json_encode($ad['title']), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['description']), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['image_url'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['logo_url'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['call_to_action']), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['advertiser']), ENT_QUOTES) ?>, <?= $ad['rating'] ? $ad['rating'] : 'null' ?>, <?= htmlspecialchars(json_encode($ad['click_url'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['status']), ENT_QUOTES) ?>, <?= $ad['priority'] ?>, <?= htmlspecialchars(json_encode($ad['start_date'] ?? ''), ENT_QUOTES) ?>, <?= htmlspecialchars(json_encode($ad['end_date'] ?? ''), ENT_QUOTES) ?>)" class="flex-1 px-3 py-2 bg-blue-500 text-white text-sm rounded hover:bg-blue-600 transition">
                                                            Düzenle
                                                        </button>
                                                        <form method="POST" action="" class="inline" onsubmit="return confirm('Bu reklamı silmek istediğinize emin misiniz?');">
                                                            <?= get_csrf_field() ?>
                                                            <input type="hidden" name="action" value="delete_ad">
                                                            <input type="hidden" name="ad_id" value="<?= $ad['id'] ?>">
                                                            <button type="submit" class="px-3 py-2 bg-red-500 text-white text-sm rounded hover:bg-red-600 transition">
                                                                Sil
                                                            </button>
                                                        </form>
                                                    </div>
                                                </div>
                                            </div>
                                        </div>
                                        <?php endforeach; ?>
                                    </div>
                                    
                                    <!-- Lazy Loading: Daha Fazla Yükle Butonu -->
                                    <?php if (isset($has_more_events) && $has_more_events): ?>
                                    <div class="mt-6 text-center p-6" id="loadMoreEventsContainer">
                                        <button onclick="loadMoreSuperadminEvents()" id="loadMoreSuperadminEventsBtn" 
                                                class="px-6 py-3 bg-cyan-600 hover:bg-cyan-700 text-white rounded-lg font-semibold shadow-sm transition duration-200 flex items-center gap-2 mx-auto">
                                            <svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"></path>
                                            </svg>
                                            <span>Daha Fazla Etkinlik Yükle</span>
                                        </button>
                                        <div id="superadminEventsLoadingSpinner" class="hidden mt-4">
                                            <div class="inline-block animate-spin rounded-full h-8 w-8 border-b-2 border-cyan-600"></div>
                                            <p class="text-gray-600 mt-2">Yükleniyor...</p>
                                        </div>
                                    </div>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </div>
                        </div>
                    </div>

                    <!-- Reklam Ekleme Modal -->
                    <div id="addAdModal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden items-center justify-center p-4" style="display: none;">
                        <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                            <div class="p-6 border-b border-gray-200 flex items-center justify-between">
                                <h3 class="text-xl font-semibold text-gray-800">Yeni Reklam Ekle</h3>
                                <button onclick="closeAddAdModal()" class="text-gray-400 hover:text-gray-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                </button>
                            </div>
                            <form method="POST" action="?view=ads" enctype="multipart/form-data" class="p-6 space-y-4" id="addAdForm">
                                <?= get_csrf_field() ?>
                                <input type="hidden" name="action" value="add_ad">
                                <input type="hidden" name="current_view" value="ads">
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Başlık *</label>
                                    <input type="text" name="title" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Açıklama *</label>
                                    <textarea name="description" required rows="3" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></textarea>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Reklam Görseli (Fotoğraf Yükle)</label>
                                        <input type="file" name="ad_image" accept="image/*" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                        <p class="text-xs text-gray-500 mt-1">Desteklenen formatlar: JPG, PNG, GIF, WebP (Max: 5MB)</p>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Görsel URL (Alternatif)</label>
                                        <input type="url" name="image_url" placeholder="Veya URL ile ekleyin" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Logo (Fotoğraf Yükle)</label>
                                        <input type="file" name="ad_logo" accept="image/*" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                        <p class="text-xs text-gray-500 mt-1">Desteklenen formatlar: JPG, PNG, GIF, WebP (Max: 2MB)</p>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Logo URL (Alternatif)</label>
                                        <input type="url" name="logo_url" placeholder="Veya URL ile ekleyin" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Reklamveren *</label>
                                        <input type="text" name="advertiser" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Buton Metni</label>
                                        <input type="text" name="call_to_action" value="Keşfet" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-3 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Rating</label>
                                        <input type="number" name="rating" step="0.1" min="0" max="5" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Öncelik</label>
                                        <input type="number" name="priority" value="0" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Durum</label>
                                        <select name="status" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                            <option value="active">Aktif</option>
                                            <option value="inactive">Pasif</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Tıklama URL</label>
                                    <input type="url" name="click_url" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Başlangıç Tarihi</label>
                                        <input type="datetime-local" name="start_date" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Bitiş Tarihi</label>
                                        <input type="datetime-local" name="end_date" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="flex justify-end gap-3 pt-4 border-t border-gray-200">
                                    <button type="button" onclick="closeAddAdModal()" class="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition">
                                        İptal
                                    </button>
                                    <button type="submit" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition">
                                        Kaydet
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <!-- Reklam Düzenleme Modal -->
                    <div id="editAdModal" class="fixed inset-0 bg-black bg-opacity-50 z-50 hidden items-center justify-center p-4" style="display: none;">
                        <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full max-h-[90vh] overflow-y-auto">
                            <div class="p-6 border-b border-gray-200 flex items-center justify-between">
                                <h3 class="text-xl font-semibold text-gray-800">Reklam Düzenle</h3>
                                <button onclick="closeEditAdModal()" class="text-gray-400 hover:text-gray-600">
                                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                                    </svg>
                                </button>
                            </div>
                            <form method="POST" action="" enctype="multipart/form-data" class="p-6 space-y-4">
                                <?= get_csrf_field() ?>
                                <input type="hidden" name="action" value="update_ad">
                                <input type="hidden" name="ad_id" id="edit_ad_id">
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Başlık *</label>
                                    <input type="text" name="title" id="edit_title" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Açıklama *</label>
                                    <textarea name="description" id="edit_description" required rows="3" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent"></textarea>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Reklam Görseli (Fotoğraf Yükle)</label>
                                        <input type="file" name="ad_image" id="edit_ad_image" accept="image/*" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" onchange="previewImage(this, 'edit_image_preview')">
                                        <p class="text-xs text-gray-500 mt-1">Desteklenen formatlar: JPG, PNG, GIF, WebP (Max: 5MB)</p>
                                        <div id="edit_image_preview" class="mt-2"></div>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Görsel URL (Alternatif)</label>
                                        <input type="url" name="image_url" id="edit_image_url" placeholder="Veya URL ile ekleyin" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Logo (Fotoğraf Yükle)</label>
                                        <input type="file" name="ad_logo" id="edit_ad_logo" accept="image/*" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent" onchange="previewImage(this, 'edit_logo_preview')">
                                        <p class="text-xs text-gray-500 mt-1">Desteklenen formatlar: JPG, PNG, GIF, WebP (Max: 2MB)</p>
                                        <div id="edit_logo_preview" class="mt-2"></div>
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Logo URL (Alternatif)</label>
                                        <input type="url" name="logo_url" id="edit_logo_url" placeholder="Veya URL ile ekleyin" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Reklamveren *</label>
                                        <input type="text" name="advertiser" id="edit_advertiser" required class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Buton Metni</label>
                                        <input type="text" name="call_to_action" id="edit_call_to_action" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="grid grid-cols-3 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Rating</label>
                                        <input type="number" name="rating" id="edit_rating" step="0.1" min="0" max="5" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Öncelik</label>
                                        <input type="number" name="priority" id="edit_priority" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Durum</label>
                                        <select name="status" id="edit_status" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                            <option value="active">Aktif</option>
                                            <option value="inactive">Pasif</option>
                                        </select>
                                    </div>
                                </div>
                                
                                <div>
                                    <label class="block text-sm font-medium text-gray-700 mb-2">Tıklama URL</label>
                                    <input type="url" name="click_url" id="edit_click_url" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                </div>
                                
                                <div class="grid grid-cols-2 gap-4">
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Başlangıç Tarihi</label>
                                        <input type="datetime-local" name="start_date" id="edit_start_date" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                    <div>
                                        <label class="block text-sm font-medium text-gray-700 mb-2">Bitiş Tarihi</label>
                                        <input type="datetime-local" name="end_date" id="edit_end_date" class="w-full px-3 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent">
                                    </div>
                                </div>
                                
                                <div class="flex justify-end gap-3 pt-4 border-t border-gray-200">
                                    <button type="button" onclick="closeEditAdModal()" class="px-4 py-2 text-gray-700 bg-gray-100 rounded-lg hover:bg-gray-200 transition">
                                        İptal
                                    </button>
                                    <button type="submit" class="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition">
                                        Güncelle
                                    </button>
                                </div>
                            </form>
                        </div>
                    </div>

                    <script>
                    // Reklam Ekleme Modal Fonksiyonları - BASİT VE ÇALIŞIR
                    function openAddAdModal() {
                        const modal = document.getElementById('addAdModal');
                        if (modal) {
                            modal.style.display = 'flex';
                            modal.classList.remove('hidden');
                            document.body.style.overflow = 'hidden';
                            
                            // Formu temizle
                            const form = document.getElementById('addAdForm');
                            if (form) form.reset();
                        } else {
                            alert('Modal bulunamadı!');
                        }
                    }
                    
                    function closeAddAdModal() {
                        const modal = document.getElementById('addAdModal');
                        if (modal) {
                            modal.style.display = 'none';
                            modal.classList.add('hidden');
                            document.body.style.overflow = '';
                            
                            // Formu temizle
                            const form = document.getElementById('addAdForm');
                            if (form) form.reset();
                        }
                    }
                    
                    // Sayfa yüklendiğinde
                    if (document.readyState === 'loading') {
                        document.addEventListener('DOMContentLoaded', initAdModal);
                    } else {
                        initAdModal();
                    }
                    
                    function initAdModal() {
                        // Modal dışına tıklanınca kapat
                        const modal = document.getElementById('addAdModal');
                        if (modal) {
                            modal.addEventListener('click', function(e) {
                                if (e.target === modal) {
                                    closeAddAdModal();
                                }
                            });
                        }
                        
                        // ESC tuşu ile kapat
                        document.addEventListener('keydown', function(e) {
                            if (e.key === 'Escape') {
                                const modal = document.getElementById('addAdModal');
                                if (modal && modal.style.display === 'flex') {
                                    closeAddAdModal();
                                }
                            }
                        });
                    }
                    
                    // Görsel önizleme fonksiyonu
                    function previewImage(input, previewId) {
                        const preview = document.getElementById(previewId);
                        if (input.files && input.files[0]) {
                            const reader = new FileReader();
                            reader.onload = function(e) {
                                preview.innerHTML = '<img src="' + e.target.result + '" alt="Önizleme" class="w-32 h-32 object-cover rounded-lg border border-gray-300 mt-2">';
                            };
                            reader.readAsDataURL(input.files[0]);
                        } else {
                            preview.innerHTML = '';
                        }
                    }
                    function openEditAdModal(id, title, description, imageUrl, logoUrl, callToAction, advertiser, rating, clickUrl, status, priority, startDate, endDate) {
                        const modal = document.getElementById('editAdModal');
                        if (modal) {
                            document.getElementById('edit_ad_id').value = id;
                            document.getElementById('edit_title').value = title;
                            document.getElementById('edit_description').value = description;
                            document.getElementById('edit_image_url').value = imageUrl || '';
                            document.getElementById('edit_logo_url').value = logoUrl || '';
                            document.getElementById('edit_call_to_action').value = callToAction;
                            document.getElementById('edit_advertiser').value = advertiser;
                            document.getElementById('edit_rating').value = rating || '';
                            document.getElementById('edit_click_url').value = clickUrl || '';
                            document.getElementById('edit_status').value = status;
                            document.getElementById('edit_priority').value = priority;
                            document.getElementById('edit_start_date').value = startDate || '';
                            document.getElementById('edit_end_date').value = endDate || '';
                            
                            // Görsel önizlemesi
                            const imagePreview = document.getElementById('edit_image_preview');
                            if (imagePreview) {
                                if (imageUrl && imageUrl.trim() !== '') {
                                    let previewUrl = imageUrl;
                                    // Eğer relative path ise tam URL'e çevir
                                    if (previewUrl.startsWith('/assets/images/ads/')) {
                                        previewUrl = '/unipanel' + previewUrl;
                                    } else if (!previewUrl.startsWith('http://') && !previewUrl.startsWith('https://')) {
                                        previewUrl = '/unipanel/assets/images/ads/' + previewUrl;
                                    }
                                    imagePreview.innerHTML = '<img src="' + previewUrl + '" alt="Önizleme" class="w-32 h-32 object-cover rounded-lg border border-gray-300" onerror="this.style.display=\'none\'">';
                                } else {
                                    imagePreview.innerHTML = '';
                                }
                            }
                            
                            // Logo önizlemesi
                            const logoPreview = document.getElementById('edit_logo_preview');
                            if (logoPreview) {
                                if (logoUrl && logoUrl.trim() !== '') {
                                    let previewUrl = logoUrl;
                                    // Eğer relative path ise tam URL'e çevir
                                    if (previewUrl.startsWith('/assets/images/ads/')) {
                                        previewUrl = '/unipanel' + previewUrl;
                                    } else if (!previewUrl.startsWith('http://') && !previewUrl.startsWith('https://')) {
                                        previewUrl = '/unipanel/assets/images/ads/' + previewUrl;
                                    }
                                    logoPreview.innerHTML = '<img src="' + previewUrl + '" alt="Logo Önizleme" class="w-32 h-32 object-cover rounded-lg border border-gray-300" onerror="this.style.display=\'none\'">';
                                } else {
                                    logoPreview.innerHTML = '';
                                }
                            }
                            
                            modal.classList.remove('hidden');
                            modal.style.display = 'flex';
                        } else {
                            console.error('Modal bulunamadı: editAdModal');
                            alert('Düzenleme modalı bulunamadı! Sayfayı yenileyin.');
                        }
                    }
                    function closeEditAdModal() {
                        const modal = document.getElementById('editAdModal');
                        if (modal) {
                            modal.classList.add('hidden');
                            modal.style.display = 'none';
                        }
                    }
                    </script>

                <?php elseif ($current_view === 'settings'): ?>
                    <!-- Sistem Ayarları -->
                    <?php
                    // Sistem bilgilerini topla
                    $system_info = [
                        'php_version' => PHP_VERSION,
                        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Bilinmiyor',
                        'document_root' => $_SERVER['DOCUMENT_ROOT'] ?? 'Bilinmiyor',
                        'server_name' => $_SERVER['SERVER_NAME'] ?? 'Bilinmiyor',
                        'server_port' => $_SERVER['SERVER_PORT'] ?? 'Bilinmiyor',
                        'max_execution_time' => ini_get('max_execution_time'),
                        'memory_limit' => ini_get('memory_limit'),
                        'upload_max_filesize' => ini_get('upload_max_filesize'),
                        'post_max_size' => ini_get('post_max_size'),
                        'date_timezone' => date_default_timezone_get(),
                        'current_time' => date('d.m.Y H:i:s'),
                        'disk_free_space' => getDiskFreeSpace(),
                        'disk_total_space' => getDiskTotalSpace(),
                        'disk_free_space_formatted' => formatBytes(getDiskFreeSpace()),
                        'disk_total_space_formatted' => formatBytes(getDiskTotalSpace())
                    ];
                    
                    // Topluluk ayarlarını topla
                    $community_settings = [];
                    foreach ($communities as $community) {
                        $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
                        if (file_exists($db_path)) {
                            try {
                                $db = new SQLite3($db_path);
                                $settings = [];
                                
                                $settings_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
                                if ($settings_table_exists) {
                                    $query = @$db->query("SELECT * FROM settings");
                                    if ($query) {
                                        while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
                                            $settings[$row['setting_key']] = $row['setting_value'];
                                        }
                                    }
                                }
                                
                                $community_settings[$community] = $settings;
                                $db->close();
                            } catch (Exception $e) {
                                $community_settings[$community] = [];
                            }
                        }
                    }
                    ?>
                    <div class="space-y-8">
                        <!-- Sistem Bilgileri -->
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h2 class="text-2xl font-semibold text-gray-800 flex items-center">
                                    <svg class="w-6 h-6 mr-2 text-indigo-500" fill="none" stroke="currentColor" viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37a1.724 1.724 0 002.572-1.065z"></path><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"></path></svg>
                                    Sistem Ayarları
                                </h2>
                            </div>
                            <div class="p-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                                    <!-- Genel Bilgiler -->
                                    <div class="space-y-4">
                                        <h3 class="text-lg font-semibold text-gray-800">Genel Bilgiler</h3>
                                        <div class="space-y-3">
                                            <div class="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                                                <span class="text-blue-700">Sistem Adı</span>
                                                <span class="text-blue-600 font-semibold">Four Community SuperAdmin</span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                                                <span class="text-blue-700">Versiyon</span>
                                                <span class="text-blue-600 font-semibold">v1.0.0</span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                                                <span class="text-blue-700">PHP Versiyonu</span>
                                                <span class="text-blue-600 font-semibold"><?= $system_info['php_version'] ?></span>
                                        </div>
                                            <div class="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                                                <span class="text-blue-700">Sunucu</span>
                                                <span class="text-blue-600 font-semibold"><?= htmlspecialchars($system_info['server_software']) ?></span>
                                    </div>
                                            <div class="flex items-center justify-between p-3 bg-blue-50 rounded-lg">
                                                <span class="text-blue-700">Zaman Dilimi</span>
                                                <span class="text-blue-600 font-semibold"><?= $system_info['date_timezone'] ?></span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Sistem Durumu -->
                                    <div class="space-y-4">
                                        <h3 class="text-lg font-semibold text-gray-800">Sistem Durumu</h3>
                                        <div class="space-y-3">
                                            <div class="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                                                <span class="text-green-700">Topluluk Sayısı</span>
                                                <span class="text-green-600 font-semibold"><?= $total_communities ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                                                <span class="text-green-700">Toplam Üye</span>
                                                <span class="text-green-600 font-semibold"><?= $total_members ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                                                <span class="text-green-700">Toplam Etkinlik</span>
                                                <span class="text-green-600 font-semibold"><?= $total_events ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                                                <span class="text-green-700">Banlı Üye</span>
                                                <span class="text-green-600 font-semibold"><?= $total_banned ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-green-50 rounded-lg">
                                                <span class="text-green-700">Sistem Durumu</span>
                                                <span class="text-green-600 font-semibold">Aktif</span>
                                            </div>
                                        </div>
                                    </div>
                                    
                                    <!-- Teknik Bilgiler -->
                                    <div class="space-y-4">
                                        <h3 class="text-lg font-semibold text-gray-800">Teknik Bilgiler</h3>
                                        <div class="space-y-3">
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Max Execution Time</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['max_execution_time'] ?>s</span>
                                </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Memory Limit</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['memory_limit'] ?></span>
                            </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Upload Max</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['upload_max_filesize'] ?></span>
                        </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Post Max</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['post_max_size'] ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Disk Kullanımı</span>
                                                <span class="text-gray-600 font-semibold"><?= getDiskUsagePercentage($system_info['disk_total_space'], $system_info['disk_free_space']) ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Boş Alan</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['disk_free_space_formatted'] ?></span>
                                            </div>
                                            <div class="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                                                <span class="text-gray-700">Toplam Alan</span>
                                                <span class="text-gray-600 font-semibold"><?= $system_info['disk_total_space_formatted'] ?></span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Topluluk Ayarları -->
                        <?php if (!empty($communities)): ?>
                        <div class="bg-white rounded-xl card-shadow">
                            <div class="p-6 border-b border-gray-200">
                                <h3 class="text-xl font-semibold text-gray-800">Topluluk Ayarları</h3>
                            </div>
                            <div class="p-6">
                                <div class="space-y-6">
                                    <?php foreach ($communities as $community): ?>
                                        <div class="border border-gray-200 rounded-lg p-4">
                                            <div class="flex items-center justify-between mb-4">
                                                <h4 class="text-lg font-semibold text-gray-800"><?= htmlspecialchars($community_details[$community]['name']) ?></h4>
                                                <span class="px-3 py-1 text-sm <?= $community_details[$community]['status'] === 'active' ? 'bg-green-100 text-green-700' : 'bg-red-100 text-red-700' ?> rounded-full">
                                                    <?= $community_details[$community]['status'] === 'active' ? 'Aktif' : 'Kapalı' ?>
                                                </span>
                                            </div>
                                            
                                            <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                                <div class="space-y-3">
                                                    <h5 class="font-medium text-gray-800">Topluluk Bilgileri</h5>
                                                    <div class="space-y-2 text-sm">
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Topluluk Adı:</span>
                                                            <span class="font-medium"><?= htmlspecialchars($community_details[$community]['name']) ?></span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Durum:</span>
                                                            <span class="font-medium <?= $community_details[$community]['status'] === 'active' ? 'text-green-600' : 'text-red-600' ?>">
                                                                <?= $community_details[$community]['status'] === 'active' ? 'Aktif' : 'Kapalı' ?>
                                                            </span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Üye Sayısı:</span>
                                                            <span class="font-medium"><?= $community_details[$community]['members'] ?></span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Etkinlik Sayısı:</span>
                                                            <span class="font-medium"><?= $community_details[$community]['events'] ?></span>
                                                        </div>
                                                    </div>
                                                </div>
                                                
                                                <div class="space-y-3">
                                                    <h5 class="font-medium text-gray-800">Veritabanı Ayarları</h5>
                                                    <div class="space-y-2 text-sm">
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Veritabanı:</span>
                                                            <span class="font-medium text-green-600">✓ Aktif</span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Tablo Sayısı:</span>
                                                            <span class="font-medium">6 tablo</span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Son Güncelleme:</span>
                                                            <span class="font-medium"><?= date('d.m.Y H:i') ?></span>
                                                        </div>
                                                        <div class="flex justify-between">
                                                            <span class="text-gray-600">Boyut:</span>
                                                            <span class="font-medium"><?= round(filesize(COMMUNITIES_DIR . $community . '/unipanel.sqlite') / 1024, 1) ?> KB</span>
                                                        </div>
                                                    </div>
                                                </div>
                                            </div>
                                            
                                            <div class="mt-4 flex space-x-3">
                                                <a href="?action=auto_login&community=<?= urlencode($community) ?>" target="_blank" class="px-4 py-2 text-sm bg-blue-600 text-white rounded-lg hover:bg-blue-700 transition duration-150">
                                                    Topluluğa Git
                                                </a>
                                                <button onclick="toggleCommunityStatus('<?= $community ?>')" class="px-4 py-2 text-sm <?= $community_details[$community]['status'] === 'active' ? 'bg-red-600 hover:bg-red-700' : 'bg-green-600 hover:bg-green-700' ?> text-white rounded-lg transition duration-150">
                                                    <?= $community_details[$community]['status'] === 'active' ? 'Kapat' : 'Aç' ?>
                                                </button>
                                            </div>
                                        </div>
                                    <?php endforeach; ?>
                                </div>
                            </div>
                        </div>
                        <?php endif; ?>
                    </div>
                <?php endif; ?>
            </main>
        </div>
    </div>

    <!-- Topluluk Düzenleme Modal -->
    <div id="editModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50 overflow-y-auto">
        <div class="bg-white rounded-xl p-6 w-full max-w-lg mx-4 my-8">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold text-gray-800">Topluluk Düzenle</h3>
                <button onclick="closeEditModal()" class="text-gray-400 hover:text-gray-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <form method="POST" action="?action=edit" id="editForm">
                <?= get_csrf_field() ?>
                <input type="hidden" name="folder" id="editFolder">
                <div class="space-y-3">
                    <!-- Topluluk Adı -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">Topluluk Adı</label>
                        <input type="text" name="new_name" id="editName" required class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm">
                    </div>
                    
                    <!-- Üniversite ve Kod - Yan Yana -->
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Üniversite</label>
                            <select name="new_university" id="editUniversity" required class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm">
                                <option value="">Seçin</option>
                                <?php foreach ($universities as $uni): ?>
                                    <option value="<?= htmlspecialchars($uni) ?>"><?= htmlspecialchars($uni) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Kod</label>
                            <input type="text" name="new_code" id="editCode" required maxlength="4" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm font-mono text-center" style="text-transform: uppercase; letter-spacing: 0.3em;">
                        </div>
                    </div>
                    
                    <!-- Admin Bilgileri - Yan Yana -->
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Admin Kullanıcı</label>
                            <input type="text" name="new_admin" id="editAdmin" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Opsiyonel">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Yeni Şifre</label>
                            <input type="password" name="new_password" id="editPassword" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Opsiyonel">
                        </div>
                    </div>
                    
                    <!-- Klasör Adı - Küçük ve Opsiyonel -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            Klasör Adı 
                            <span class="text-xs text-gray-400 font-normal">(Değiştirmek için)</span>
                        </label>
                        <input type="text" name="new_folder" id="editFolderName" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Boş bırak = değişmez">
                    </div>
                </div>
                <div class="flex space-x-3 mt-5">
                    <button type="submit" class="flex-1 px-4 py-2.5 text-white color-primary rounded-lg hover-primary transition duration-150 text-sm font-medium">
                        Kaydet
                    </button>
                    <button type="button" onclick="closeEditModal()" class="px-4 py-2.5 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150 text-sm">
                        İptal
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Başkan Oluşturma Modal -->
    <div id="createPresidentModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50 overflow-y-auto">
        <div class="bg-white rounded-xl p-6 w-full max-w-lg mx-4 my-8">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold text-gray-800">Topluluk Başkanı Oluştur</h3>
                <button onclick="closeCreatePresidentModal()" class="text-gray-400 hover:text-gray-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <form method="POST" action="index.php" id="createPresidentForm">
                <input type="hidden" name="action" value="create_president">
                <?= get_csrf_field() ?>
                <input type="hidden" name="community_folder" id="presidentCommunityFolder">
                <div class="mb-4 p-3 bg-blue-50 rounded-lg border border-blue-200">
                    <p class="text-sm text-gray-600">
                        <span class="font-medium">Topluluk:</span> 
                        <span id="presidentCommunityName" class="text-blue-700 font-semibold"></span>
                    </p>
                </div>
                <div class="space-y-3">
                    <!-- Başkan Adı Soyadı -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            Başkan Adı Soyadı <span class="text-red-500">*</span>
                        </label>
                        <input type="text" name="president_name" id="presidentName" required class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Örn: Ahmet Yılmaz">
                    </div>
                    
                    <!-- E-posta ve Telefon - Yan Yana -->
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">E-posta</label>
                            <input type="email" name="president_email" id="presidentEmail" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="ornek@email.com">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Telefon</label>
                            <input type="tel" name="president_phone" id="presidentPhone" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="5XXXXXXXXX">
                        </div>
                    </div>
                    
                    <!-- Öğrenci No ve Bölüm - Yan Yana -->
                    <div class="grid grid-cols-2 gap-3">
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Öğrenci No</label>
                            <input type="text" name="president_student_id" id="presidentStudentId" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Örn: 202012345">
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Bölüm</label>
                            <input type="text" name="president_department" id="presidentDepartment" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="Örn: Bilgisayar Mühendisliği">
                        </div>
                    </div>
                </div>
                <div class="flex space-x-3 mt-5">
                    <button type="submit" class="flex-1 px-4 py-2.5 text-white bg-indigo-600 rounded-lg hover:bg-indigo-700 transition duration-150 text-sm font-medium">
                        Başkan Oluştur
                    </button>
                    <button type="button" onclick="closeCreatePresidentModal()" class="px-4 py-2.5 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150 text-sm">
                        İptal
                    </button>
                </div>
            </form>
        </div>
    </div>

    <!-- Plan Atama Modal -->
    <div id="assignPlanModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50 overflow-y-auto">
        <div class="bg-white rounded-xl p-6 w-full max-w-lg mx-4 my-8">
            <div class="flex items-center justify-between mb-4">
                <h3 class="text-lg font-semibold text-gray-800">Plan Ata</h3>
                <button onclick="closeAssignPlanModal()" class="text-gray-400 hover:text-gray-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <form method="POST" action="?action=assign_plan" id="assignPlanForm">
                <?= get_csrf_field() ?>
                <input type="hidden" name="community_folder" id="planCommunityFolder">
                <div class="mb-4 p-3 bg-purple-50 rounded-lg border border-purple-200">
                    <p class="text-sm text-gray-600">
                        <span class="font-medium">Topluluk:</span> 
                        <span id="planCommunityName" class="text-purple-700 font-semibold"></span>
                    </p>
                </div>
                <div class="space-y-4">
                    <!-- Plan Seçimi -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            Plan Tipi <span class="text-red-500">*</span>
                        </label>
                        <div class="space-y-2">
                            <label class="flex items-center p-3 border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 transition">
                                <input type="radio" name="plan_tier" value="standard" checked class="mr-3" onchange="updatePlanDetails()">
                                <div class="flex-1">
                                    <div class="font-medium text-gray-800">Standart</div>
                                    <div class="text-xs text-gray-500">Ücretsiz - Temel özellikler</div>
                                </div>
                                <span class="text-green-600 font-semibold">0 TL</span>
                            </label>
                            <label class="flex items-center p-3 border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 transition">
                                <input type="radio" name="plan_tier" value="professional" class="mr-3" onchange="updatePlanDetails()">
                                <div class="flex-1">
                                    <div class="font-medium text-gray-800">Profesyonel</div>
                                    <div class="text-xs text-gray-500">Mail Merkezi, Finans, API erişimi</div>
                                </div>
                                <span class="text-blue-600 font-semibold" id="professionalPrice">250 TL/ay</span>
                            </label>
                            <label class="flex items-center p-3 border border-gray-300 rounded-lg cursor-pointer hover:bg-gray-50 transition">
                                <input type="radio" name="plan_tier" value="business" class="mr-3" onchange="updatePlanDetails()">
                                <div class="flex-1">
                                    <div class="font-medium text-gray-800">Business</div>
                                    <div class="text-xs text-gray-500">Tüm özellikler + SMS Merkezi</div>
                                </div>
                                <span class="text-purple-600 font-semibold" id="businessPrice">500 TL/ay</span>
                            </label>
                        </div>
                    </div>
                    
                    <!-- Ay Sayısı -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-1">
                            Süre (Ay) <span class="text-red-500">*</span>
                        </label>
                        <select name="months" id="planMonths" required class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" onchange="updatePlanDetails()">
                            <option value="1">1 Ay</option>
                            <option value="6" selected>6 Ay</option>
                            <option value="12">12 Ay</option>
                        </select>
                    </div>
                    
                    <!-- Toplam Fiyat -->
                    <div class="p-3 bg-gray-50 rounded-lg border border-gray-200">
                        <div class="flex justify-between items-center">
                            <span class="text-sm font-medium text-gray-700">Toplam Tutar:</span>
                            <span class="text-lg font-bold text-gray-800" id="totalPrice">0 TL</span>
                        </div>
                        <div class="text-xs text-gray-500 mt-1" id="planDetails">Standart plan ücretsizdir</div>
                    </div>
                </div>
                <div class="flex space-x-3 mt-5">
                    <button type="submit" class="flex-1 px-4 py-2.5 text-white bg-purple-600 rounded-lg hover:bg-purple-700 transition duration-150 text-sm font-medium">
                        Planı Ata
                    </button>
                    <button type="button" onclick="closeAssignPlanModal()" class="px-4 py-2.5 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150 text-sm">
                        İptal
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- SMS Paketi Tahsis Modal -->
    <div id="assignSmsPackageModal" class="fixed inset-0 bg-black bg-opacity-50 hidden items-center justify-center z-50 overflow-y-auto">
        <div class="bg-white rounded-xl shadow-2xl max-w-2xl w-full mx-4 my-8">
            <div class="flex items-center justify-between p-6 border-b border-gray-200">
                <h3 class="text-xl font-semibold text-gray-800">SMS Paketi Tahsis Et</h3>
                <button onclick="closeAssignSmsPackageModal()" class="text-gray-400 hover:text-gray-600">
                    <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                    </svg>
                </button>
            </div>
            <form method="POST" action="?action=assign_sms_package" id="assignSmsPackageForm">
                <?= get_csrf_field() ?>
                <input type="hidden" name="community_folder" id="smsPackageCommunityFolder">
                <div class="mb-4 p-3 bg-purple-50 rounded-lg border border-purple-200">
                    <p class="text-sm text-gray-600">
                        <span class="font-medium">Topluluk:</span> 
                        <span id="smsPackageCommunityName" class="text-purple-700 font-semibold"></span>
                    </p>
                </div>
                <div class="p-6 space-y-4">
                    <!-- SMS Paketi Seçimi -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            SMS Paketi <span class="text-red-500">*</span>
                        </label>
                        <div class="grid grid-cols-2 md:grid-cols-3 gap-3">
                            <?php
                            require_once __DIR__ . '/../lib/payment/SubscriptionManager.php';
                            $allPackages = \UniPanel\Payment\SubscriptionManager::getPackagePrices();
                            $smsPackages = [];
                            foreach ($allPackages as $key => $package) {
                                if (isset($package['is_addon']) && $package['is_addon'] && isset($package['sms_credits'])) {
                                    $smsPackages[] = $package;
                                }
                            }
                            // SMS kredisine göre sırala
                            usort($smsPackages, function($a, $b) {
                                return $a['sms_credits'] <=> $b['sms_credits'];
                            });
                            foreach ($smsPackages as $package):
                            ?>
                                <label class="sms-package-option block cursor-pointer">
                                    <input type="radio" name="sms_package" value="<?= $package['sms_credits'] ?>" class="peer hidden" data-credits="<?= $package['sms_credits'] ?>" data-price="<?= $package['price'] ?>" required>
                                    <div class="border-2 border-gray-200 rounded-lg p-3 transition-all duration-200 peer-checked:border-purple-500 peer-checked:bg-purple-50 peer-checked:shadow-lg hover:border-purple-300 h-full">
                                        <div class="text-center">
                                            <div class="text-sm font-semibold text-gray-900 mb-1">
                                                <?= number_format($package['sms_credits'], 0, ',', '.') ?> SMS
                                            </div>
                                            <div class="text-xs text-gray-500">
                                                <?= number_format($package['price'], 0, ',', '.') ?>₺
                                            </div>
                                        </div>
                                    </div>
                                </label>
                            <?php endforeach; ?>
                        </div>
                    </div>
                    
                    <!-- Notlar -->
                    <div>
                        <label class="block text-sm font-medium text-gray-700 mb-2">
                            Notlar (Opsiyonel)
                        </label>
                        <textarea name="notes" rows="3" class="w-full p-2.5 border border-gray-300 rounded-lg input-focus text-sm" placeholder="SMS paketi tahsis notları..."></textarea>
                    </div>
                </div>
                <div class="flex space-x-3 p-6 border-t border-gray-200">
                    <button type="submit" class="flex-1 px-4 py-2.5 text-white bg-purple-600 rounded-lg hover:bg-purple-700 transition duration-150 text-sm font-medium">
                        SMS Paketini Tahsis Et
                    </button>
                    <button type="button" onclick="closeAssignSmsPackageModal()" class="px-4 py-2.5 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150 text-sm">
                        İptal
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script>
        function openEditModal(folder, name, code, university, admin) {
            try {
                const modal = document.getElementById('editModal');
                if (!modal) {
                    console.error('editModal bulunamadı!');
                    alert('Modal bulunamadı. Sayfayı yenileyin.');
                    return;
                }
                document.getElementById('editFolder').value = folder;
                document.getElementById('editFolderName').value = folder;
                document.getElementById('editName').value = name || '';
                document.getElementById('editCode').value = code || '';
                document.getElementById('editUniversity').value = university || '';
                document.getElementById('editAdmin').value = admin || '';
                document.getElementById('editPassword').value = '';
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                modal.style.display = 'flex';
            } catch (error) {
                console.error('openEditModal hatası:', error);
                alert('Modal açılırken hata oluştu: ' + error.message);
            }
        }

        function closeEditModal() {
            try {
                const modal = document.getElementById('editModal');
                if (modal) {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                    modal.style.display = 'none';
                }
            } catch (error) {
                console.error('closeEditModal hatası:', error);
            }
        }

        // AJAX işlemleri için fonksiyonlar
        function performAction(action, community, callback, extraData = {}) {
            const formData = new FormData();
            formData.append('csrf_token', '<?= generate_csrf_token() ?>');
            formData.append('action', action);
            if (community) {
                formData.append('community', community);
            }
            
            // Ekstra verileri ekle
            for (const key in extraData) {
                formData.append(key, extraData[key]);
            }
            
            // Loading göstergesi
            showLoading();
            
            fetch('index.php', {
                method: 'POST',
                body: formData
            })
            .then(response => response.text())
            .then(data => {
                hideLoading();
                if (callback) callback(data);
                // Sadece başarılı işlemlerden sonra sayfayı yenile
                setTimeout(() => {
                    location.reload();
                }, 1000);
            })
            .catch(error => {
                hideLoading();
                console.error('Hata:', error);
                alert('İşlem sırasında bir hata oluştu!');
            });
        }

        function showLoading(message = 'İşlem yapılıyor...') {
            // Eğer zaten bir loading varsa, önce kaldır
            hideLoading();
            
            // Loading overlay ekle
            const overlay = document.createElement('div');
            overlay.id = 'loading-overlay';
            overlay.className = 'fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50 backdrop-blur-sm';
            overlay.style.transition = 'opacity 0.3s ease';
            overlay.style.opacity = '0';
            
            overlay.innerHTML = `
                <div class="bg-white rounded-xl shadow-2xl p-8 flex flex-col items-center space-y-4 min-w-[280px] transform transition-all">
                    <div class="relative">
                        <div class="animate-spin rounded-full h-12 w-12 border-4 border-gray-200"></div>
                        <div class="animate-spin rounded-full h-12 w-12 border-4 border-blue-600 border-t-transparent absolute top-0 left-0"></div>
                    </div>
                    <div class="text-center">
                        <p class="text-gray-700 font-medium text-base">${message}</p>
                        <p class="text-gray-500 text-sm mt-1">Lütfen bekleyin...</p>
                    </div>
                </div>
            `;
            
            document.body.appendChild(overlay);
            
            // Fade-in animasyonu
            requestAnimationFrame(() => {
                overlay.style.opacity = '1';
            });
        }

        function hideLoading() {
            const overlay = document.getElementById('loading-overlay');
            if (overlay) {
                overlay.style.opacity = '0';
                setTimeout(() => {
                    if (overlay.parentNode) {
                        overlay.remove();
                    }
                }, 300);
            }
        }

        function enableCommunity(community) {
            if (confirm('Bu topluluğu açmak istediğinizden emin misiniz?')) {
                performAction('enable_community', community);
            }
        }

        function disableCommunity(community) {
            if (confirm('Bu topluluğu kapatmak istediğinizden emin misiniz?')) {
                performAction('disable_community', community);
            }
        }

        function deleteCommunity(community) {
            if (confirm('Bu topluluğu silmek istediğinizden emin misiniz? Bu işlem geri alınamaz!')) {
                performAction('delete', null, null, {folder: community});
            }
        }

        function openCreatePresidentModal(communityFolder, communityName) {
            try {
                const modal = document.getElementById('createPresidentModal');
                if (!modal) {
                    console.error('createPresidentModal bulunamadı!');
                    alert('Modal bulunamadı. Sayfayı yenileyin.');
                    return;
                }
                document.getElementById('presidentCommunityFolder').value = communityFolder;
                document.getElementById('presidentCommunityName').textContent = communityName;
                document.getElementById('presidentName').value = '';
                document.getElementById('presidentEmail').value = '';
                document.getElementById('presidentPhone').value = '';
                document.getElementById('presidentStudentId').value = '';
                document.getElementById('presidentDepartment').value = '';
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                modal.style.display = 'flex';
            } catch (error) {
                console.error('openCreatePresidentModal hatası:', error);
                alert('Modal açılırken hata oluştu: ' + error.message);
            }
        }

        function closeCreatePresidentModal() {
            try {
                const modal = document.getElementById('createPresidentModal');
                if (modal) {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                    modal.style.display = 'none';
                }
            } catch (error) {
                console.error('closeCreatePresidentModal hatası:', error);
            }
        }

        function openAssignPlanModal(communityFolder, communityName) {
            try {
                const modal = document.getElementById('assignPlanModal');
                if (!modal) {
                    console.error('assignPlanModal bulunamadı!');
                    alert('Modal bulunamadı. Sayfayı yenileyin.');
                    return;
                }
                document.getElementById('planCommunityFolder').value = communityFolder;
                document.getElementById('planCommunityName').textContent = communityName;
                // Varsayılan değerleri ayarla
                document.querySelector('input[name="plan_tier"][value="standard"]').checked = true;
                document.getElementById('planMonths').value = '6';
                updatePlanDetails();
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                modal.style.display = 'flex';
            } catch (error) {
                console.error('openAssignPlanModal hatası:', error);
                alert('Modal açılırken hata oluştu: ' + error.message);
            }
        }

        function closeAssignPlanModal() {
            try {
                const modal = document.getElementById('assignPlanModal');
                if (modal) {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                    modal.style.display = 'none';
                }
            } catch (error) {
                console.error('closeAssignPlanModal hatası:', error);
            }
        }
        
        function openAssignSmsPackageModal(communityFolder, communityName) {
            try {
                const modal = document.getElementById('assignSmsPackageModal');
                if (!modal) {
                    console.error('assignSmsPackageModal bulunamadı!');
                    alert('Modal bulunamadı. Sayfayı yenileyin.');
                    return;
                }
                document.getElementById('smsPackageCommunityFolder').value = communityFolder;
                document.getElementById('smsPackageCommunityName').textContent = communityName;
                // Formu sıfırla
                document.getElementById('assignSmsPackageForm').reset();
                document.getElementById('smsPackageCommunityFolder').value = communityFolder;
                modal.classList.remove('hidden');
                modal.classList.add('flex');
                modal.style.display = 'flex';
            } catch (error) {
                console.error('openAssignSmsPackageModal hatası:', error);
                alert('Modal açılırken hata oluştu: ' + error.message);
            }
        }
        
        function closeAssignSmsPackageModal() {
            try {
                const modal = document.getElementById('assignSmsPackageModal');
                if (modal) {
                    modal.classList.add('hidden');
                    modal.classList.remove('flex');
                    modal.style.display = 'none';
                }
            } catch (error) {
                console.error('closeAssignSmsPackageModal hatası:', error);
            }
        }

        function updatePlanDetails() {
            const tier = document.querySelector('input[name="plan_tier"]:checked')?.value || 'standard';
            const months = parseInt(document.getElementById('planMonths').value) || 6;
            let totalPrice = 0;
            let details = '';

            if (tier === 'standard') {
                totalPrice = 0;
                details = 'Standart plan ücretsizdir';
            } else if (tier === 'professional') {
                totalPrice = 250 * months;
                details = `${months} ay × 250 TL = ${totalPrice} TL`;
            } else if (tier === 'business') {
                totalPrice = 500 * months;
                details = `${months} ay × 500 TL = ${totalPrice} TL`;
            }

            document.getElementById('totalPrice').textContent = totalPrice.toLocaleString('tr-TR') + ' TL';
            document.getElementById('planDetails').textContent = details;
        }

        function toggleCommunityStatus(community) {
            const isActive = document.querySelector(`button[onclick="toggleCommunityStatus('${community}')"]`).textContent.trim() === 'Kapat';
            const action = isActive ? 'disable_community' : 'enable_community';
            const message = isActive ? 'Bu topluluğu kapatmak istediğinizden emin misiniz?' : 'Bu topluluğu açmak istediğinizden emin misiniz?';
            
            if (confirm(message)) {
                performAction(action, community);
            }
        }

        // Klasör adını otomatik formatla (JavaScript)
        function formatFolderNameJS(name) {
            if (!name) return '';
            
            // "Topluluğu" ve "Topluluk" kelimelerini kaldır
            name = name.replace(/\s*topluluğu\s*/gi, ' ');
            name = name.replace(/\s*topluluk\s*/gi, ' ');
            name = name.trim();
            
            // Türkçe karakterleri İngilizce karşılıklarına çevir
            const turkishMap = {
                'Ç': 'C', 'Ğ': 'G', 'İ': 'I', 'Ö': 'O', 'Ş': 'S', 'Ü': 'U',
                'ç': 'c', 'ğ': 'g', 'ı': 'i', 'ö': 'o', 'ş': 's', 'ü': 'u'
            };
            name = name.replace(/[ÇĞİÖŞÜçğıöşü]/g, function(match) {
                return turkishMap[match] || match;
            });
            
            // Küçük harfe çevir
            name = name.toLowerCase();
            
            // Boşlukları ve özel karakterleri alt çizgiye çevir
            name = name.replace(/[^a-z0-9_]+/g, '_');
            
            // Birden fazla alt çizgiyi tek alt çizgiye çevir
            name = name.replace(/_+/g, '_');
            
            // Başta ve sonda alt çizgi varsa kaldır
            name = name.replace(/^_+|_+$/g, '');
            
            return name;
        }

        // Form gönderimini normal POST ile yap (AJAX kaldırıldı)
        document.addEventListener('DOMContentLoaded', function() {
            // Topluluk adı yazılırken klasör adını otomatik formatla
            const communityNameInput = document.getElementById('community_name');
            const folderNameInput = document.getElementById('folder_name');
            
            if (communityNameInput && folderNameInput) {
                let isManualEdit = false;
                
                // Klasör adı manuel değiştirildiğinde flag'i set et
                folderNameInput.addEventListener('input', function() {
                    isManualEdit = true;
                });
                
                // Topluluk adı değiştiğinde klasör adını otomatik güncelle
                communityNameInput.addEventListener('input', function() {
                    if (!isManualEdit) {
                        const formatted = formatFolderNameJS(this.value);
                        folderNameInput.value = formatted;
                    }
                });
                
                // Topluluk adından "Topluluğu" kelimesini kaldır (görsel olarak)
                communityNameInput.addEventListener('blur', function() {
                    let value = this.value.trim();
                    value = value.replace(/\s*topluluğu\s*/gi, ' ').trim();
                    value = value.replace(/\s*topluluk\s*/gi, ' ').trim();
                    if (value !== this.value) {
                        this.value = value;
                    }
                });
            }
            
            const createForm = document.querySelector('form[action="?action=create"]');
            if (createForm) {
                // AJAX'ı kaldır, normal form gönderimi kullan
                createForm.addEventListener('submit', function(e) {
                    // Form normal şekilde gönderilsin
                    showLoading();
                });
            }

            const editForm = document.getElementById('editForm');
            if (editForm) {
                editForm.addEventListener('submit', function(e) {
                    e.preventDefault();
                    
                    showLoading();
                    
                    const formData = new FormData(this);
                    formData.append('action', 'edit');
                    formData.append('ajax', '1'); // AJAX isteği olduğunu belirt
                    
                    // Debug: Form verilerini kontrol et
                    const formDataObj = {
                        folder: formData.get('folder'),
                        new_name: formData.get('new_name'),
                        new_code: formData.get('new_code'),
                        new_university: formData.get('new_university'),
                        new_admin: formData.get('new_admin'),
                        new_password: formData.get('new_password') ? '***' : '',
                        new_folder: formData.get('new_folder'),
                        action: formData.get('action'),
                        ajax: formData.get('ajax')
                    };
                    console.log('Form gönderiliyor:', formDataObj);
                    
                    fetch('index.php', {
                        method: 'POST',
                        body: formData
                    })
                    .then(response => {
                        console.log('Response status:', response.status);
                        console.log('Response headers:', response.headers.get('content-type'));
                        
                        // Content-Type kontrolü
                        const contentType = response.headers.get('content-type');
                        if (contentType && contentType.includes('application/json')) {
                            return response.json();
                        } else {
                            return response.text().then(text => {
                                console.error('Beklenmeyen response:', text.substring(0, 500));
                                throw new Error('Beklenmeyen response formatı. Sunucu hatası olabilir.');
                            });
                        }
                    })
                    .then(data => {
                        hideLoading();
                        console.log('Sunucu response:', data);
                        
                        if (data && data.success) {
                            closeEditModal();
                            showSuccessMessage(data.message || 'Topluluk başarıyla güncellendi!');
                            // 2 saniye sonra sayfayı yenile
                            setTimeout(() => {
                                location.reload();
                            }, 2000);
                        } else {
                            // Hata mesajını göster
                            const errorMsg = data && data.message ? data.message : 'Topluluk güncellenirken bir hata oluştu!';
                            alert(errorMsg);
                            console.error('Sunucu hatası:', data);
                        }
                    })
                    .catch(error => {
                        hideLoading();
                        console.error('Fetch hatası:', error);
                        alert('Topluluk güncellenirken bir hata oluştu: ' + error.message);
                    });
                });
            }
        });

        function showSuccessMessage(message) {
            // Başarı mesajı göster
            const successDiv = document.createElement('div');
            successDiv.className = 'fixed top-4 right-4 bg-green-500 text-white px-6 py-3 rounded-lg shadow-lg z-50 relative overflow-hidden';
            successDiv.innerHTML = `
                <div>${message}</div>
                <div class="absolute bottom-0 left-0 h-1 bg-green-300 toast-progress-bar" style="width: 100%; animation: toastProgress 3s linear forwards;"></div>
            `;
            document.body.appendChild(successDiv);
            
            // 3 saniye sonra kaldır
            setTimeout(() => {
                successDiv.remove();
            }, 3000);
        }
    </script>

    <!-- Topluluk Oluşturma Modal -->
    <div id="createModal" class="fixed inset-0 bg-black bg-opacity-50 hidden z-50">
        <div class="flex items-center justify-center min-h-screen p-4">
            <div class="bg-white rounded-lg shadow-xl max-w-2xl w-full">
                <div class="p-6 border-b border-gray-200">
                    <div class="flex items-center justify-between">
                        <h3 class="text-xl font-semibold text-gray-800">Yeni Topluluk Oluştur</h3>
                        <button onclick="closeCreateModal()" class="text-gray-400 hover:text-gray-600">
                            <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"></path>
                            </svg>
                        </button>
                    </div>
                </div>
                
                <form id="createForm" method="POST" action="?action=create" class="p-6 space-y-4">
                    <?= get_csrf_field() ?>
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="community_name" class="block text-sm font-medium text-gray-700 mb-1">Topluluk Adı</label>
                            <input type="text" name="community_name" id="community_name" required class="w-full p-3 border border-gray-300 rounded-lg input-focus" placeholder="Örn: Bilgisayar Mühendisliği Topluluğu">
                        </div>
                        <div>
                            <label for="folder_name" class="block text-sm font-medium text-gray-700 mb-1">
                                Klasör Adı 
                                <span class="text-xs text-gray-400 font-normal">(Otomatik formatlanır)</span>
                            </label>
                            <input type="text" name="folder_name" id="folder_name" class="w-full p-3 border border-gray-300 rounded-lg input-focus" placeholder="Otomatik oluşturulacak">
                            <small class="text-xs text-gray-500 mt-1 block">
                                <i class="fas fa-info-circle"></i> Topluluk adından otomatik oluşturulur. Türkçe karakterler çevrilir, boşluklar alt çizgiye dönüşür.
                            </small>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="university" class="block text-sm font-medium text-gray-700 mb-1">Üniversite</label>
                            <select name="university" id="university" required class="w-full p-3 border border-gray-300 rounded-lg input-focus">
                                <option value="">Üniversite Seçin</option>
                                <?php foreach ($universities as $uni): ?>
                                    <option value="<?= htmlspecialchars($uni) ?>"><?= htmlspecialchars($uni) ?></option>
                                <?php endforeach; ?>
                            </select>
                        </div>
                        <div>
                            <label class="block text-sm font-medium text-gray-700 mb-1">Topluluk Kodu</label>
                            <div class="bg-gray-50 p-3 border border-gray-300 rounded-lg text-sm text-gray-600">
                                <strong>Otomatik Oluşturulacak:</strong> Topluluk adının ilk 3 harfi + rastgele rakam<br>
                                <span class="text-xs text-gray-500">Örnek: "Bilgisayar Mühendisliği Topluluğu" → BIL5</span>
                            </div>
                        </div>
                    </div>
                    
                    <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                            <label for="admin_username" class="block text-sm font-medium text-gray-700 mb-1">Admin Kullanıcı Adı</label>
                            <input type="text" name="admin_username" id="admin_username" required class="w-full p-3 border border-gray-300 rounded-lg input-focus" placeholder="Örn: admin">
                        </div>
                        <div>
                            <label for="admin_password" class="block text-sm font-medium text-gray-700 mb-1">Admin Şifre</label>
                            <input type="password" name="admin_password" id="admin_password" required class="w-full p-3 border border-gray-300 rounded-lg input-focus" placeholder="Güçlü şifre">
                        </div>
                    </div>
                    
                    <div class="bg-blue-50 p-4 rounded-lg border border-blue-200">
                        <p class="text-sm text-blue-700">
                            <strong>Topluluk Kodu:</strong> Topluluk adından otomatik olarak oluşturulacaktır. Format: İlk 3 harf (topluluk adından) + 1 rastgele rakam (örn: BIL5). Aynı üniversitede benzersiz olacak şekilde kontrol edilir.
                        </p>
                    </div>
                    
                    <!-- Otomatik Veri Çekme Bilgisi -->
                    <div class="border-t border-gray-200 pt-4">
                        <div class="bg-blue-50 p-4 rounded-lg border border-blue-200">
                            <div class="flex items-center mb-2">
                                <svg class="w-5 h-5 mr-2 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"></path>
                                </svg>
                                <h3 class="text-lg font-semibold text-blue-800">Otomatik Veri Çekme</h3>
                            </div>
                            <p class="text-sm text-blue-700">
                                Topluluk oluşturulduktan sonra, yönetim kurulu üyeleri ve başkan bilgileri topluluk panelinden otomatik olarak çekilecektir. Manuel giriş gerekmez.
                            </p>
                        </div>
                    </div>
                    
                    <div class="flex justify-end space-x-3 pt-4">
                        <button type="button" onclick="closeCreateModal()" class="px-4 py-2 text-gray-600 border border-gray-300 rounded-lg hover:bg-gray-50 transition duration-150">
                            İptal
                        </button>
                        <button type="submit" class="px-6 py-2 text-white color-primary rounded-lg font-semibold hover-primary transition duration-150">
                            Topluluk Oluştur
                        </button>
                    </div>
                </form>
            </div>
        </div>
    </div>

    <script>
        function openCreateModal() {
            document.getElementById('createModal').classList.remove('hidden');
        }
        
        function closeCreateModal() {
            document.getElementById('createModal').classList.add('hidden');
        }
        
        // Modal dışına tıklayınca kapat
        document.getElementById('createModal').addEventListener('click', function(e) {
            if (e.target === this) {
                closeCreateModal();
            }
        });
        
        // Bildirim formu validation
        function validateNotificationForm() {
            const title = document.getElementById('notification_title').value.trim();
            const message = document.getElementById('notification_message').value.trim();
            const checkboxes = document.querySelectorAll('input[name="target_communities[]"]:checked');
            
            if (!title) {
                alert('Bildirim başlığı gerekli!');
                document.getElementById('notification_title').focus();
                return false;
            }
            
            if (!message) {
                alert('Bildirim mesajı gerekli!');
                document.getElementById('notification_message').focus();
                return false;
            }
            
            if (checkboxes.length === 0) {
                alert('En az bir topluluk seçmelisiniz!');
                return false;
            }
            
            return true;
        }
        
    </script>
</body>
</html>

<?php
// PERFORMANS OPTİMİZASYONU: Otomatik yönetim kurulu güncelleme işlemini arka plana al
// Bu işlem sadece gerektiğinde veya arka planda çalışacak
// Her sayfa yüklendiğinde çalışması performans sorununa neden oluyordu

// Sadece manuel tetikleme veya cron job ile çalışsın
$updateBoardMembers = isset($_GET['update_board_members']) && $_GET['update_board_members'] === '1';

if ($updateBoardMembers) {
    // Timeout ayarla (max 30 saniye)
    set_time_limit(30);
    
    $updated = 0;
    $skipped = 0;
    $maxCommunities = 50; // Her seferinde max 50 topluluk güncelle
    
    foreach (array_slice($communities, 0, $maxCommunities) as $community) {
        $db_path = COMMUNITIES_DIR . $community . '/unipanel.sqlite';
        
        if (!file_exists($db_path)) {
            $skipped++;
            continue;
        }
        
        try {
            $db = getSQLite3Connection($db_path);
            if (!$db) {
                $skipped++;
                continue;
            }
            
            $db_is_writable = is_writable($db_path);
            
            // Board members tablosundan verileri çek
            $board_members = [];
            $board_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='board_members'");
            
            if ($board_table_exists) {
                try {
                    $query = $db->query("SELECT * FROM board_members LIMIT 20"); // Limit ekle
                    if ($query) {
                        while ($row = $query->fetchArray(SQLITE3_ASSOC)) {
                            $board_members[] = $row;
                        }
                    }
                } catch (Exception $e) {
                    // Hata durumunda boş array kullan
                }
            }
            
            // Board members verilerini settings tablosuna kaydet
            $settings_table_exists = (bool) @$db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
            
            if ($settings_table_exists && $db_is_writable && !empty($board_members)) {
                // Batch insert için transaction başlat
                $db->exec('BEGIN IMMEDIATE TRANSACTION');
                
                foreach ($board_members as $member) {
                    $role = strtolower($member['role']);
                    $name_key = $role . '_name';
                    $email_key = $role . '_email';
                    
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, ?, ?)");
                    if ($stmt) {
                        $stmt->bindValue(1, $name_key, SQLITE3_TEXT);
                        $stmt->bindValue(2, $member['full_name'] ?? '', SQLITE3_TEXT);
                        @$stmt->execute();
                    }
                    
                    if (!empty($member['contact_email'])) {
                        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, ?, ?)");
                        if ($stmt) {
                            $stmt->bindValue(1, $email_key, SQLITE3_TEXT);
                            $stmt->bindValue(2, $member['contact_email'], SQLITE3_TEXT);
                            @$stmt->execute();
                        }
                    }
                }
                
                // Başkan bilgilerini de güncelle
                if ($board_table_exists) {
                    $president = $db->querySingle("SELECT * FROM board_members WHERE role = 'Başkan' LIMIT 1", true);
                    if ($president && !empty($president['full_name'])) {
                        $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'president_name', ?)");
                        if ($stmt) {
                            $stmt->bindValue(1, $president['full_name'], SQLITE3_TEXT);
                            @$stmt->execute();
                        }
                        
                        if (!empty($president['contact_email'])) {
                            $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'president_email', ?)");
                            if ($stmt) {
                                $stmt->bindValue(1, $president['contact_email'], SQLITE3_TEXT);
                                @$stmt->execute();
                            }
                        }
                        
                        if (!empty($president['phone'])) {
                            $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (1, 'president_phone', ?)");
                            if ($stmt) {
                                $stmt->bindValue(1, $president['phone'], SQLITE3_TEXT);
                                @$stmt->execute();
                            }
                        }
                    }
                }
                
                $db->exec('COMMIT');
                $updated++;
            }
            
            $db->close();
            
        } catch (Exception $e) {
            $skipped++;
            error_log("Board members update hatası ({$community}): " . $e->getMessage());
        }
    }
    
    // Sonuç mesajı (sadece manuel tetiklemede göster)
    if (isset($_GET['update_board_members'])) {
        echo "<!-- Board members güncelleme tamamlandı: {$updated} güncellendi, {$skipped} atlandı -->";
    }
}

?>