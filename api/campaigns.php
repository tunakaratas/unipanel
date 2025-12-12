<?php
/**
 * Mobil API - Campaigns Endpoint
 * GET /api/campaigns.php - Tüm kampanyaları listele
 * GET /api/campaigns.php?community_id={id} - Topluluğa ait kampanyaları listele
 * GET /api/campaigns.php?id={id} - Tek bir kampanya detayı
 */

require_once __DIR__ . '/security_helper.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// OPTIONS request için hemen cevap ver
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}
require_once __DIR__ . '/../lib/autoload.php';
require_once __DIR__ . '/auth_middleware.php';
require_once __DIR__ . '/connection_pool.php';

// Rate limiting (200 istek/dakika - 10k kullanıcı için optimize edildi)
if (!checkRateLimit(200, 60)) {
    http_response_code(429);
    echo json_encode([
        'success' => false,
        'data' => null,
        'message' => null,
        'error' => 'Çok fazla istek. Lütfen daha sonra tekrar deneyin.'
    ], JSON_UNESCAPED_UNICODE);
    exit;
}

// Public index.php'deki fonksiyonları kullanmak için - Güvenli session ayarlarıyla
configureSecureSession();

require_once __DIR__ . '/../lib/core/Cache.php';
use UniPanel\Core\Cache;

$publicCache = Cache::getInstance(__DIR__ . '/../system/cache');

/**
 * University filter helpers (shared behavior with api/communities.php and api/universities.php)
 */
function normalize_university_id($value) {
    $value = trim((string)$value);
    if ($value === '') {
        return '';
    }
    // Türkçe karakter desteği için mb_strtolower kullan
    $normalized = mb_strtolower($value, 'UTF-8');
    // Boşluk, tire ve alt çizgi karakterlerini kaldır
    $normalized = str_replace([' ', '-', '_'], '', $normalized);
    return $normalized;
}

function get_requested_university_id() {
    // Accept both university_id (preferred) and university (name) for compatibility.
    $raw = '';
    if (isset($_GET['university_id'])) {
        $raw = (string)$_GET['university_id'];
    } elseif (isset($_GET['university'])) {
        $raw = (string)$_GET['university'];
    }

    $raw = trim($raw);
    if ($raw === '' || $raw === 'all') {
        return '';
    }

    $raw = basename($raw);
    if (strpos($raw, '..') !== false || strpos($raw, '/') !== false || strpos($raw, '\\') !== false) {
        return '';
    }

    return normalize_university_id($raw);
}

// get_all_communities fonksiyonunu kopyala
function get_all_communities($useCache = true) {
    global $publicCache;
    $cacheKey = 'all_communities_list_v2';
    if ($useCache && $publicCache) {
        $cached = $publicCache->get($cacheKey);
        if ($cached !== null) return $cached;
    }
    $communities_dir = __DIR__ . '/../communities';
    $communities = [];
    if (!is_dir($communities_dir)) return [];
    $dirs = scandir($communities_dir);
    $excluded_dirs = ['.', '..', 'assets', 'public', 'templates', 'system', 'docs'];
    foreach ($dirs as $dir) {
        if (in_array($dir, $excluded_dirs) || !is_dir($communities_dir . '/' . $dir)) continue;
        $db_path = $communities_dir . '/' . $dir . '/unipanel.sqlite';
        if (!file_exists($db_path)) continue;
        try {
            // Connection pool kullan (10k kullanıcı için kritik)
            // NOT: Bazı DB'ler WAL/shm nedeniyle READONLY modda açılamıyor.
            // Üniversite filtresi ve listeler için RW açıp sadece SELECT yapıyoruz.
            $connResult = ConnectionPool::getConnection($db_path, false);
            if (!$connResult) {
                continue;
            }
            $db = $connResult['db'];
            $poolId = $connResult['pool_id'];
            
            $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
            $settings = [];
            while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
            $old_exceptions = $db->enableExceptions(false);
            $member_count = (int)($db->querySingle("SELECT COUNT(*) FROM members WHERE club_id = 1") ?: 0);
            $event_count = (int)($db->querySingle("SELECT COUNT(*) FROM events WHERE club_id = 1") ?: 0);
            $db->exec("CREATE TABLE IF NOT EXISTS campaigns (id INTEGER PRIMARY KEY, club_id INTEGER NOT NULL, title TEXT NOT NULL, description TEXT, offer_text TEXT NOT NULL, partner_name TEXT, discount_percentage INTEGER, image_path TEXT, start_date TEXT, end_date TEXT, is_active INTEGER DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)");
            $campaign_count = (int)($db->querySingle("SELECT COUNT(*) FROM campaigns WHERE club_id = 1 AND is_active = 1") ?: 0);
            $db->enableExceptions($old_exceptions);
            $communities[] = [
                'id' => $dir,
                'name' => $settings['club_name'] ?? ucwords(str_replace('_', ' ', $dir)),
                'description' => $settings['club_description'] ?? '',
                'member_count' => $member_count,
                'event_count' => $event_count,
                'campaign_count' => $campaign_count
            ];
            
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, false);
        } catch (Exception $e) { continue; }
    }
    if ($publicCache) $publicCache->set($cacheKey, $communities, 600);
    return $communities;
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
    $communities_dir = __DIR__ . '/../communities';
    $all_campaigns = [];
    $requested_university_id = get_requested_university_id();
    
    // Tek bir kampanya detayı isteniyorsa
    if (isset($_GET['id']) && !empty($_GET['id'])) {
        $campaign_id = (int)$_GET['id'];
        $community_id = isset($_GET['community_id']) ? sanitizeCommunityId($_GET['community_id']) : null;
        
        if (!$community_id) {
            sendResponse(false, null, null, 'Kampanya detayı için community_id parametresi gerekli');
        }
        
        $db_path = $communities_dir . '/' . $community_id . '/unipanel.sqlite';
        if (!file_exists($db_path)) {
            sendResponse(false, null, null, 'Topluluk bulunamadı');
        }
        
        // Connection pool kullan (10k kullanıcı için kritik)
        $connResult = ConnectionPool::getConnection($db_path, false);
        if (!$connResult) {
            sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı.');
        }
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        // Kampanyalar tablosunu kontrol et ve oluştur
        $db->exec("CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY,
            club_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            offer_text TEXT NOT NULL,
            partner_name TEXT,
            discount_percentage INTEGER,
            image_path TEXT,
            start_date TEXT,
            end_date TEXT,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        $query = $db->prepare("SELECT * FROM campaigns WHERE id = ? AND club_id = 1");
        $query->bindValue(1, $campaign_id, SQLITE3_INTEGER);
        $result = $query->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$row) {
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            sendResponse(false, null, null, 'Kampanya bulunamadı');
        }
        
        // Topluluk adı
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
            $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
        }
        $community_name = $settings['club_name'] ?? $community_id;
        
        // Image path
        $image_path = null;
        if (!empty($row['image_path'])) {
            $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
        }
        
        // Partner logo
        $partner_logo = null;
        if (!empty($row['partner_logo'])) {
            $partner_logo = '/communities/' . $community_id . '/' . $row['partner_logo'];
        }
        
        // Discount type
        $discount_type = 'special';
        if (isset($row['discount_percentage']) && $row['discount_percentage'] > 0) {
            $discount_type = 'percentage';
        } elseif (isset($row['discount']) && $row['discount'] > 0) {
            $discount_type = 'fixed';
        }
        
        // Requirements JSON parse et
        $requirements = null;
        if (!empty($row['requirements'])) {
            $decoded = json_decode($row['requirements'], true);
            if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                $requirements = $decoded;
            }
        }
        
        $campaign = [
            'id' => (string)$row['id'],
            'title' => $row['title'] ?? '',
            'description' => $row['description'] ?? null,
            'short_description' => null,
            'offer_text' => $row['offer_text'] ?? '',
            'community_id' => $community_id,
            'community_name' => $community_name,
            'image_url' => $image_path,
            'image_path' => $image_path,
            'discount' => isset($row['discount']) ? (float)$row['discount'] : null,
            'discount_percentage' => isset($row['discount_percentage']) ? (int)$row['discount_percentage'] : null,
            'discount_type' => $discount_type,
            'start_date' => $row['start_date'] ?? date('Y-m-d'),
            'end_date' => $row['end_date'] ?? date('Y-m-d'),
            'partner_name' => $row['partner_name'] ?? null,
            'partner_logo' => $partner_logo,
            'terms' => $row['terms'] ?? null,
            'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
            'category' => $row['category'] ?? 'Diğer',
            'campaign_code' => $row['campaign_code'] ?? null,
            'is_active' => isset($row['is_active']) ? (bool)$row['is_active'] : true,
            'created_at' => $row['created_at'] ?? null,
            'requires_membership' => isset($row['requires_membership']) ? (bool)$row['requires_membership'] : false,
            'requirements' => $requirements
        ];
        
        // Bağlantıyı pool'a geri ver
        ConnectionPool::releaseConnection($db_path, $poolId, false);
        sendResponse(true, $campaign);
    }
    
    // Topluluk ID varsa sadece o topluluğun kampanyalarını getir
    if (isset($_GET['community_id']) && !empty($_GET['community_id'])) {
        $community_id = sanitizeCommunityId($_GET['community_id']);
        $db_path = $communities_dir . '/' . $community_id . '/unipanel.sqlite';
        
        if (!file_exists($db_path)) {
            sendResponse(false, null, null, 'Topluluk bulunamadı');
        }
        
        // Connection pool kullan (10k kullanıcı için kritik)
        $connResult = ConnectionPool::getConnection($db_path, false);
        if (!$connResult) {
            sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı.');
        }
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        // Kampanyalar tablosunu kontrol et ve oluştur
        $db->exec("CREATE TABLE IF NOT EXISTS campaigns (
            id INTEGER PRIMARY KEY,
            club_id INTEGER NOT NULL,
            title TEXT NOT NULL,
            description TEXT,
            offer_text TEXT NOT NULL,
            partner_name TEXT,
            discount_percentage INTEGER,
            image_path TEXT,
            start_date TEXT,
            end_date TEXT,
            campaign_code TEXT,
            is_active INTEGER DEFAULT 1,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
        
        // Mevcut tabloda campaign_code kolonu yoksa ekle
        $tableInfo = $db->query("PRAGMA table_info(campaigns)");
        $columns = [];
        while ($col = $tableInfo->fetchArray(SQLITE3_ASSOC)) {
            $columns[$col['name']] = true;
        }
        if (!isset($columns['campaign_code'])) {
            $db->exec("ALTER TABLE campaigns ADD COLUMN campaign_code TEXT");
        }
        
        // Topluluk adı
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
            $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
        }
        $community_name = $settings['club_name'] ?? $community_id;
        
        // Kampanyaları çek
        $query = $db->prepare("SELECT * FROM campaigns WHERE club_id = 1 AND is_active = 1 ORDER BY created_at DESC");
        $result = $query->execute();
        
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            // Image path
            $image_path = null;
            if (!empty($row['image_path'])) {
                $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
            }
            
            // Partner logo
            $partner_logo = null;
            if (!empty($row['partner_logo'])) {
                $partner_logo = '/communities/' . $community_id . '/' . $row['partner_logo'];
            }
            
            // Discount type
            $discount_type = 'special';
            if (isset($row['discount_percentage']) && $row['discount_percentage'] > 0) {
                $discount_type = 'percentage';
            } elseif (isset($row['discount']) && $row['discount'] > 0) {
                $discount_type = 'fixed';
            }
            
            $all_campaigns[] = [
                'id' => (string)$row['id'],
                'title' => $row['title'] ?? '',
                'description' => $row['description'] ?? null,
                'short_description' => null,
                'offer_text' => $row['offer_text'] ?? '',
                'community_id' => $community_id,
                'community_name' => $community_name,
                'image_url' => $image_path,
                'image_path' => $image_path,
                'discount' => isset($row['discount']) ? (float)$row['discount'] : null,
                'discount_percentage' => isset($row['discount_percentage']) ? (int)$row['discount_percentage'] : null,
                'discount_type' => $discount_type,
                'start_date' => $row['start_date'] ?? date('Y-m-d'),
                'end_date' => $row['end_date'] ?? date('Y-m-d'),
                'partner_name' => $row['partner_name'] ?? null,
                'partner_logo' => $partner_logo,
                'terms' => $row['terms'] ?? null,
                'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
                'category' => $row['category'] ?? 'Diğer',
                'campaign_code' => $row['campaign_code'] ?? null,
                'is_active' => isset($row['is_active']) ? (bool)$row['is_active'] : true,
                'created_at' => $row['created_at'] ?? null
            ];
        }
        
        // Bağlantıyı pool'a geri ver
        ConnectionPool::releaseConnection($db_path, $poolId, false);
    } else {
        // Tüm toplulukların kampanyalarını getir
        $community_folders = glob($communities_dir . '/*', GLOB_ONLYDIR);
        
        foreach ($community_folders as $folder_path) {
            $community_id = basename($folder_path);
            if ($community_id === '.' || $community_id === '..') continue;

            $db_path = $folder_path . '/unipanel.sqlite';
            if (!file_exists($db_path)) {
                continue;
            }
            
            try {
                // Connection pool kullan (10k kullanıcı için kritik)
                $connResult = ConnectionPool::getConnection($db_path, false);
                if (!$connResult) {
                    continue;
                }
                $db = $connResult['db'];
                $poolId = $connResult['pool_id'];
                
                // Kampanyalar tablosunu kontrol et ve oluştur
                $db->exec("CREATE TABLE IF NOT EXISTS campaigns (
                    id INTEGER PRIMARY KEY,
                    club_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    offer_text TEXT NOT NULL,
                    partner_name TEXT,
                    discount_percentage INTEGER,
                    image_path TEXT,
                    start_date TEXT,
                    end_date TEXT,
                    campaign_code TEXT,
                    is_active INTEGER DEFAULT 1,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )");
                
                // Mevcut tabloda campaign_code kolonu yoksa ekle
                $tableInfo = $db->query("PRAGMA table_info(campaigns)");
                $columns = [];
                while ($col = $tableInfo->fetchArray(SQLITE3_ASSOC)) {
                    $columns[$col['name']] = true;
                }
                if (!isset($columns['campaign_code'])) {
                    $db->exec("ALTER TABLE campaigns ADD COLUMN campaign_code TEXT");
                }
                
                // Topluluk adı
                $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
                $settings = [];
                if ($settings_query) {
                    while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                        $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
                    }
                }
                $community_name = $settings['club_name'] ?? $community_id;

                // Üniversite filtresi (isteğe bağlı)
                if ($requested_university_id !== '') {
                    $community_university_name = $settings['university'] ?? $settings['organization'] ?? '';
                    $community_university_id = normalize_university_id($community_university_name);
                    if ($community_university_id === '' || $community_university_id !== $requested_university_id) {
                        ConnectionPool::releaseConnection($db_path, $poolId, false);
                        continue;
                    }
                }
                
                // Kampanyaları çek
                $query = $db->prepare("SELECT * FROM campaigns WHERE club_id = 1 AND is_active = 1 ORDER BY created_at DESC");
                $result = $query->execute();
                
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    // Image path
                    $image_path = null;
                    if (!empty($row['image_path'])) {
                        $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
                    }
                    
                    // Partner logo
                    $partner_logo = null;
                    if (!empty($row['partner_logo'])) {
                        $partner_logo = '/communities/' . $community_id . '/' . $row['partner_logo'];
                    }
                    
                    // Discount type
                    $discount_type = 'special';
                    if (isset($row['discount_percentage']) && $row['discount_percentage'] > 0) {
                        $discount_type = 'percentage';
                    } elseif (isset($row['discount']) && $row['discount'] > 0) {
                        $discount_type = 'fixed';
                    }
                    
                    // Requirements JSON parse et
                    $requirements = null;
                    if (!empty($row['requirements'])) {
                        $decoded = json_decode($row['requirements'], true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                            $requirements = $decoded;
                        }
                    }
                    
                    $all_campaigns[] = [
                        'id' => (string)$row['id'],
                        'title' => $row['title'] ?? '',
                        'description' => $row['description'] ?? null,
                        'short_description' => null,
                        'offer_text' => $row['offer_text'] ?? '',
                        'community_id' => $community_id,
                        'community_name' => $community_name,
                        'university' => $settings['university'] ?? $settings['organization'] ?? null,
                        'image_url' => $image_path,
                        'image_path' => $image_path,
                        'discount' => isset($row['discount']) ? (float)$row['discount'] : null,
                        'discount_percentage' => isset($row['discount_percentage']) ? (int)$row['discount_percentage'] : null,
                        'discount_type' => $discount_type,
                        'start_date' => $row['start_date'] ?? date('Y-m-d'),
                        'end_date' => $row['end_date'] ?? date('Y-m-d'),
                        'partner_name' => $row['partner_name'] ?? null,
                        'partner_logo' => $partner_logo,
                        'terms' => $row['terms'] ?? null,
                        'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
                        'category' => $row['category'] ?? 'Diğer',
                        'campaign_code' => $row['campaign_code'] ?? null,
                        'is_active' => isset($row['is_active']) ? (bool)$row['is_active'] : true,
                        'created_at' => $row['created_at'] ?? null,
                        'requires_membership' => isset($row['requires_membership']) ? (bool)$row['requires_membership'] : false,
                        'requirements' => $requirements
                    ];
                }
                
                // Bağlantıyı pool'a geri ver
                ConnectionPool::releaseConnection($db_path, $poolId, false);
            } catch (Exception $e) {
                if (isset($poolId) && isset($db_path)) ConnectionPool::releaseConnection($db_path, $poolId, false);
                continue;
            }
        }
    }
    
    sendResponse(true, $all_campaigns);
    
} catch (Exception $e) {
    $response = sendSecureErrorResponse('İşlem sırasında bir hata oluştu', $e);
    sendResponse($response['success'], $response['data'], $response['message'], $response['error']);
}

