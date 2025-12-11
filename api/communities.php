<?php
/**
 * Mobil API - Communities Endpoint
 * GET /api/communities.php - Tüm toplulukları listele (public/index.php'deki get_all_communities fonksiyonunu kullanır)
 * GET /api/communities.php?id={id} - Topluluk detayı
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';
require_once __DIR__ . '/auth_middleware.php';
require_once __DIR__ . '/connection_pool.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization, X-CSRF-Token');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// OPTIONS request için hemen cevap ver
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

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

// Authentication kontrolü - Opsiyonel (liste için), Detay için zorunlu
$currentUser = optionalAuth();

// Public index.php'deki fonksiyonları kullanmak için
// Session başlatılmamışsa başlat (API için) - Güvenli session ayarlarıyla
configureSecureSession();

// Cache sistemini yükle
require_once __DIR__ . '/../lib/core/Cache.php';
use UniPanel\Core\Cache;

// Cache instance (global değişken olarak)
$publicCache = Cache::getInstance(__DIR__ . '/../system/cache');

// Public index.php'deki get_all_communities fonksiyonunu kopyala
function get_all_communities($useCache = true) {
    global $publicCache;
    
    $cacheKey = 'all_communities_list_v3'; // Cache key'i güncelle (yeni topluluklar için)
    
    if ($useCache && $publicCache) {
        $cached = $publicCache->get($cacheKey);
        if ($cached !== null) {
            return $cached;
        }
    }
    
    $communities_dir = __DIR__ . '/../communities';
    $communities = [];
    
    if (!is_dir($communities_dir)) {
        return [];
    }
    
    $dirs = scandir($communities_dir);
    $excluded_dirs = ['.', '..', 'assets', 'public', 'templates', 'system', 'docs'];
    
    foreach ($dirs as $dir) {
        if (in_array($dir, $excluded_dirs) || !is_dir($communities_dir . '/' . $dir)) {
            continue;
        }
        
        $db_path = $communities_dir . '/' . $dir . '/unipanel.sqlite';
        if (!file_exists($db_path)) {
            // Veritabanı yoksa, topluluk henüz onaylanmamış olabilir
            // Ancak yine de topluluk adını folder name'den alabiliriz
            // Ama şimdilik sadece veritabanı olanları gösterelim
            continue;
        }
        
        try {
            // Connection pool kullan (10k kullanıcı için kritik)
            $connResult = ConnectionPool::getConnection($db_path, true);
            if (!$connResult) {
                continue;
            }
            $community_db = $connResult['db'];
            $poolId = $connResult['pool_id'];
            
            // Settings tablosunu kontrol et
            $old_exceptions = $community_db->enableExceptions(false);
            $settings_query = $community_db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
            $settings = [];
            if ($settings_query) {
                while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                    $settings[$row['setting_key']] = $row['setting_value'];
                }
            }
            $community_db->enableExceptions($old_exceptions);
            
            $member_count = 0;
            $event_count = 0;
            $campaign_count = 0;
            
            // Members tablosunu kontrol et
            $member_result = $community_db->querySingle("SELECT COUNT(*) FROM members WHERE club_id = 1");
            if ($member_result !== false) {
                $member_count = (int)$member_result;
            }
            
            // Events tablosunu kontrol et
            $event_result = $community_db->querySingle("SELECT COUNT(*) FROM events WHERE club_id = 1");
            if ($event_result !== false) {
                $event_count = (int)$event_result;
            }
            
            // Campaigns tablosunu oluştur ve kontrol et
            $community_db->exec("CREATE TABLE IF NOT EXISTS campaigns (
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
            
            $campaign_result = $community_db->querySingle("SELECT COUNT(*) FROM campaigns WHERE club_id = 1 AND is_active = 1");
            if ($campaign_result !== false) {
                $campaign_count = (int)$campaign_result;
            }
            
            // Base URL
            $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'foursoftware.com.tr');
            $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $baseUrl = $protocol . '://' . $host;
            
            // QR kod deep link
            $qr_deep_link = 'unifour://community/' . urlencode($dir);
            
            // QR kod API URL'i
            $qr_code_url = $baseUrl . '/api/qr_code.php?type=community&id=' . urlencode($dir);
            
            $communities[] = [
                'id' => $dir,
                'name' => $settings['club_name'] ?? ucwords(str_replace('_', ' ', $dir)),
                'description' => $settings['club_description'] ?? '',
                'member_count' => (int)$member_count,
                'event_count' => (int)$event_count,
                'campaign_count' => (int)$campaign_count,
                'qr_deep_link' => $qr_deep_link,
                'qr_code_url' => $qr_code_url
            ];
            
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, true);
        } catch (Exception $e) {
            // Hata durumunda bağlantıyı release et
            if (isset($poolId)) {
                ConnectionPool::releaseConnection($db_path, $poolId, true);
            }
            error_log("Communities API error: " . $e->getMessage());
            continue;
        }
    }
    
    if ($publicCache) {
        // Cache süresini 30 saniyeye düşür (yeni topluluklar anında görünsün)
        $publicCache->set($cacheKey, $communities, 30);
    }
    
    return $communities;
}

// get_community_data fonksiyonunu kopyala
function get_community_data($community_id) {
    $db_path = __DIR__ . '/../communities/' . $community_id . '/unipanel.sqlite';
    
    if (!file_exists($db_path)) {
        return null;
    }
    
    try {
        // Connection pool kullan (10k kullanıcı için kritik)
        $connResult = ConnectionPool::getConnection($db_path, true);
        if (!$connResult) {
            return null;
        }
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        $old_exceptions = $db->enableExceptions(false);
        
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        if ($settings_query) {
            while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
        }
        
        $events = [];
        $events_stmt = $db->prepare("SELECT * FROM events WHERE club_id = 1 ORDER BY date DESC, time DESC LIMIT 20");
        if ($events_stmt) {
            $events_result = $events_stmt->execute();
            if ($events_result) {
                while ($row = $events_result->fetchArray(SQLITE3_ASSOC)) {
                    $events[] = $row;
                }
            }
        }
        
        $members = [];
        $members_stmt = $db->prepare("SELECT full_name FROM members WHERE club_id = 1 AND full_name IS NOT NULL AND full_name != '' ORDER BY full_name ASC");
        if ($members_stmt) {
            $members_result = $members_stmt->execute();
            if ($members_result) {
                while ($row = $members_result->fetchArray(SQLITE3_ASSOC)) {
                    $members[] = $row;
                }
            }
        }
        
        $campaigns = [];
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
        
        $campaigns_stmt = $db->prepare("SELECT * FROM campaigns WHERE club_id = 1 AND is_active = 1 ORDER BY created_at DESC");
        if ($campaigns_stmt) {
            $campaigns_result = $campaigns_stmt->execute();
            if ($campaigns_result) {
                while ($row = $campaigns_result->fetchArray(SQLITE3_ASSOC)) {
                    $campaigns[] = $row;
                }
            }
        }
        
        $board = [];
        $board_stmt = $db->prepare("SELECT full_name, role FROM board_members WHERE club_id = 1 ORDER BY id ASC");
        if ($board_stmt) {
            $board_result = $board_stmt->execute();
            if ($board_result) {
                while ($row = $board_result->fetchArray(SQLITE3_ASSOC)) {
                    $board[] = $row;
                }
            }
        }
        
        $db->enableExceptions($old_exceptions);
        
        // Bağlantıyı pool'a geri ver
        ConnectionPool::releaseConnection($db_path, $poolId, true);
        
        return [
            'name' => $settings['club_name'] ?? ucwords(str_replace('_', ' ', $community_id)),
            'description' => $settings['club_description'] ?? '',
            'events' => $events,
            'members' => $members,
            'campaigns' => $campaigns,
            'board' => $board
        ];
    } catch (Exception $e) {
        // Hata durumunda bağlantıyı release et
        if (isset($poolId)) {
            ConnectionPool::releaseConnection($db_path, $poolId, true);
        }
        error_log("get_community_data error: " . $e->getMessage());
        return null;
    }
}

// Response helper function
function sendResponse($success, $data = null, $message = null, $error = null, $pagination = null) {
    $response = [
        'success' => $success,
        'data' => $data,
        'message' => $message,
        'error' => $error
    ];
    
    // Pagination bilgileri varsa ekle
    if ($pagination !== null) {
        $response['pagination'] = $pagination;
    }
    
    echo json_encode($response, JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
    exit;
}

// Error handling - tüm hataları yakala
try {
    $communities_dir = __DIR__ . '/../communities';
    
    // Üniversite filtresi varsa
    if (isset($_GET['university_id']) && !empty($_GET['university_id']) && $_GET['university_id'] !== 'all') {
        // Üniversite filtresi için authentication zorunlu
        if (!$currentUser) {
            http_response_code(401);
            sendResponse(false, null, null, 'Üniversite filtresini kullanmak için giriş yapmanız gerekiyor.');
        }
        
        // University ID için özel sanitization (Türkçe karakterlere izin ver)
        $university_id = trim($_GET['university_id']);
        // Path traversal koruması
        $university_id = basename($university_id);
        if (strpos($university_id, '..') !== false || strpos($university_id, '/') !== false || strpos($university_id, '\\') !== false) {
            sendResponse(false, null, null, 'Geçersiz üniversite ID formatı');
        }
        // HTML encoding koruması
        $university_id = htmlspecialchars($university_id, ENT_QUOTES, 'UTF-8');
        $all_communities = get_all_communities();
        
        // Üniversiteye göre filtrele
        $filtered_communities = [];
        foreach ($all_communities as $community) {
            $db_path = $communities_dir . '/' . $community['id'] . '/unipanel.sqlite';
            if (file_exists($db_path)) {
                try {
                    // Connection pool kullan (10k kullanıcı için kritik)
                    $connResult = ConnectionPool::getConnection($db_path, true);
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
                    
                    // Bağlantıyı pool'a geri ver
                    ConnectionPool::releaseConnection($db_path, $poolId, true);
                    
                    $community_university = strtolower(str_replace([' ', '-', '_'], '', $settings['university'] ?? $settings['organization'] ?? ''));
                    if ($community_university === $university_id) {
                        $filtered_communities[] = $community;
                    }
                } catch (Exception $e) {
                    // Hata durumunda devam et
                }
            }
        }
        
        // Formatla ve gönder
        $formatted_communities = [];
        foreach ($filtered_communities as $community) {
            $db_path = $communities_dir . '/' . $community['id'] . '/unipanel.sqlite';
            
            $logo_path = null;
            $image_url = null;
            $categories = [];
            $tags = [];
            $is_verified = false;
            $contact_email = null;
            $website = null;
            $social_links = null;
            $university = null;
            
            if (file_exists($db_path)) {
                try {
                    // Connection pool kullan (10k kullanıcı için kritik)
                    $connResult = ConnectionPool::getConnection($db_path, true);
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
                    
                    // University bilgisini al
                    $university = $settings['university'] ?? $settings['organization'] ?? null;
                    
                    if (!empty($settings['club_logo'])) {
                        $logo_path = '/communities/' . $community['id'] . '/' . $settings['club_logo'];
                    }
                    if (!empty($settings['club_image'])) {
                        $image_url = '/communities/' . $community['id'] . '/' . $settings['club_image'];
                    }
                    // Kategorileri array olarak al (JSON veya comma-separated)
                    $category = $settings['club_category'] ?? null;
                    if (!empty($category)) {
                        // JSON array kontrolü
                        $decoded = json_decode($category, true);
                        if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                            $categories = array_filter($decoded, function($cat) {
                                return $cat !== 'other' && !empty($cat);
                            });
                        } else {
                            // Comma-separated veya tek kategori
                            $cats = explode(',', $category);
                            foreach ($cats as $cat) {
                                $cat = trim($cat);
                                if ($cat !== 'other' && !empty($cat)) {
                                    $categories[] = $cat;
                                }
                            }
                        }
                    }
                    // Max 3 kategori
                    $categories = array_slice($categories, 0, 3);
                    $tags = !empty($settings['club_tags']) ? explode(',', $settings['club_tags']) : [];
                    $is_verified = isset($settings['is_verified']) ? (bool)$settings['is_verified'] : false;
                    
                    // Hassas bilgiler sadece authenticated kullanıcılar için
                    if ($currentUser) {
                        $contact_email = $settings['contact_email'] ?? null;
                        $website = $settings['website'] ?? null;
                        
                        if (!empty($settings['instagram']) || !empty($settings['twitter']) || !empty($settings['linkedin']) || !empty($settings['facebook'])) {
                            $social_links = [
                                'instagram' => $settings['instagram'] ?? null,
                                'twitter' => $settings['twitter'] ?? null,
                                'linkedin' => $settings['linkedin'] ?? null,
                                'facebook' => $settings['facebook'] ?? null
                            ];
                        }
                    } else {
                        $contact_email = null;
                        $website = null;
                        $social_links = null;
                    }
                    
                    // Bağlantıyı pool'a geri ver
                    ConnectionPool::releaseConnection($db_path, $poolId, true);
                } catch (Exception $e) {
                    // Hata durumunda bağlantıyı release et
                    if (isset($poolId)) {
                        ConnectionPool::releaseConnection($db_path, $poolId, true);
                    }
                    error_log("Communities API error: " . $e->getMessage());
                    // Hata durumunda devam et
                }
            }
            
            // Board member count
            $board_count = 0;
            if (file_exists($db_path)) {
                try {
                    // Connection pool kullan (10k kullanıcı için kritik)
                    $connResult = ConnectionPool::getConnection($db_path, true);
                    if ($connResult) {
                        $db = $connResult['db'];
                        $poolId = $connResult['pool_id'];
                        $board_count = $db->querySingle("SELECT COUNT(*) FROM board_members WHERE club_id = 1") ?: 0;
                        // Bağlantıyı pool'a geri ver
                        ConnectionPool::releaseConnection($db_path, $poolId, true);
                    }
                } catch (Exception $e) {
                    error_log("Board count error: " . $e->getMessage());
                }
            }
            
            // Base URL
            $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'foursoftware.com.tr');
            $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $baseUrl = $protocol . '://' . $host;
            
            // QR kod deep link
            $qr_deep_link = 'unifour://community/' . urlencode($community['id']);
            
            // QR kod API URL'i
            $qr_code_url = $baseUrl . '/api/qr_code.php?type=community&id=' . urlencode($community['id']);
            
            $formatted_communities[] = [
                'id' => $community['id'],
                'name' => $community['name'],
                'description' => $community['description'] ?? '',
                'short_description' => null,
                'member_count' => (int)($community['member_count'] ?? 0),
                'event_count' => (int)($community['event_count'] ?? 0),
                'campaign_count' => (int)($community['campaign_count'] ?? 0),
                'board_member_count' => (int)$board_count,
                'image_url' => $image_url,
                'logo_path' => $logo_path,
                'categories' => $categories, // Array olarak döndür
                'tags' => $tags,
                'is_verified' => $is_verified,
                'created_at' => date('Y-m-d\TH:i:s\Z'),
                'contact_email' => $contact_email,
                'website' => $website,
                'social_links' => $social_links,
                'status' => 'active',
                'university' => $university,
                'qr_deep_link' => $qr_deep_link,
                'qr_code_url' => $qr_code_url
            ];
        }
        
        sendResponse(true, $formatted_communities);
        exit;
    }
    
    // Tek bir topluluk detayı isteniyorsa
    if (isset($_GET['id']) && !empty($_GET['id'])) {
        // Detay için authentication zorunlu
        if (!$currentUser) {
            http_response_code(401);
            sendResponse(false, null, null, 'Topluluk detaylarını görmek için giriş yapmanız gerekiyor.');
        }
        
        $community_id = sanitizeCommunityId($_GET['id']);
        $community_data = get_community_data($community_id);
        
        if (!$community_data) {
            sendResponse(false, null, null, 'Topluluk bulunamadı');
        }
        
        // Topluluk detayını formatla
        $communities_dir = __DIR__ . '/../communities';
        $db_path = $communities_dir . '/' . $community_id . '/unipanel.sqlite';
        
        if (!file_exists($db_path)) {
            sendResponse(false, null, null, 'Topluluk bulunamadı');
        }
        
        try {
            // Connection pool kullan (10k kullanıcı için kritik)
            $connResult = ConnectionPool::getConnection($db_path, true);
            if (!$connResult) {
                sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı.');
            }
            $db = $connResult['db'];
            $poolId = $connResult['pool_id'];
            
            // Topluluk bilgilerini al
            $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
            $settings = [];
            while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
            
            // İstatistikler
            $member_count = count($community_data['members'] ?? []);
            $event_count = count($community_data['events'] ?? []);
            $campaign_count = count($community_data['campaigns'] ?? []);
            $board_count = count($community_data['board'] ?? []);
            
            // Logo path
            $logo_path = null;
            if (!empty($settings['club_logo'])) {
                $logo_path = '/communities/' . $community_id . '/' . $settings['club_logo'];
            }
            
            // Image URL
            $image_url = null;
            if (!empty($settings['club_image'])) {
                $image_url = '/communities/' . $community_id . '/' . $settings['club_image'];
            }
            
            // Kategorileri array olarak al
            $categories = [];
            if (!empty($settings['club_category'])) {
                $decoded = json_decode($settings['club_category'], true);
                if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                    $categories = array_filter($decoded, function($cat) {
                        return $cat !== 'other' && !empty($cat);
                    });
                } else {
                    $cats = explode(',', $settings['club_category']);
                    foreach ($cats as $cat) {
                        $cat = trim($cat);
                        if ($cat !== 'other' && !empty($cat)) {
                            $categories[] = $cat;
                        }
                    }
                }
            }
            // Max 3 kategori
            $categories = array_slice($categories, 0, 3);
            
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, true);
            
            // Base URL
            $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'foursoftware.com.tr');
            $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $baseUrl = $protocol . '://' . $host;
            
            // QR kod deep link
            $qr_deep_link = 'unifour://community/' . urlencode($community_id);
            
            // QR kod API URL'i
            $qr_code_url = $baseUrl . '/api/qr_code.php?type=community&id=' . urlencode($community_id);
            
            $community = [
                'id' => $community_id,
                'name' => $community_data['name'] ?? $community_id,
                'description' => $community_data['description'] ?? null,
                'short_description' => null,
                'member_count' => $member_count,
                'event_count' => $event_count,
                'campaign_count' => $campaign_count,
                'board_member_count' => $board_count,
                'image_url' => $image_url,
                'logo_path' => $logo_path,
                'categories' => $categories, // Array olarak döndür
                'tags' => !empty($settings['club_tags']) ? explode(',', $settings['club_tags']) : [],
                'is_verified' => isset($settings['is_verified']) ? (bool)$settings['is_verified'] : false,
                'created_at' => $settings['created_at'] ?? date('Y-m-d H:i:s'),
            'contact_email' => ($currentUser ? ($settings['contact_email'] ?? null) : null),
            'website' => ($currentUser ? ($settings['website'] ?? null) : null),
            'social_links' => ($currentUser ? [
                'instagram' => $settings['instagram'] ?? null,
                'twitter' => $settings['twitter'] ?? null,
                'linkedin' => $settings['linkedin'] ?? null,
                'facebook' => $settings['facebook'] ?? null
            ] : null),
            'status' => 'active',
            'qr_deep_link' => $qr_deep_link,
            'qr_code_url' => $qr_code_url
        ];
        
        sendResponse(true, $community);
            
        } catch (Exception $e) {
            sendResponse(false, null, null, 'Veritabanı hatası: ' . $e->getMessage());
        }
    }
    
    // Tüm toplulukları listele - Minimal bilgi (public)
    // Hassas bilgiler (contact_email, social_links) sadece authenticated kullanıcılar için
    // Cache'i bypass et (her zaman fresh data)
    $all_communities = get_all_communities(false);
    
    // Pagination parametreleri
    $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 30;
    $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;
    
    // Limit ve offset validasyonu
    $limit = max(1, min(100, $limit)); // 1-100 arası
    $offset = max(0, $offset);
    
    // Toplam sayı
    $total_count = count($all_communities);
    
    // Pagination uygula - sadece işlenecek toplulukları al
    $paginated_communities = array_slice($all_communities, $offset, $limit);
    $has_more = ($offset + $limit) < $total_count;
    
    // Formatı Swift modellerine uygun hale getir
    $formatted_communities = [];
    foreach ($paginated_communities as $community) {
        $communities_dir = __DIR__ . '/../communities';
        $db_path = $communities_dir . '/' . $community['id'] . '/unipanel.sqlite';
        
        $logo_path = null;
        $image_url = null;
        $category = 'other';
        $tags = [];
        $is_verified = false;
        $contact_email = null;
        $website = null;
        $social_links = null;
        $university = null;
        
        if (file_exists($db_path)) {
            try {
                // Connection pool kullan (10k kullanıcı için kritik)
                $connResult = ConnectionPool::getConnection($db_path, true);
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
                
                // University bilgisini al
                $university = $settings['university'] ?? $settings['organization'] ?? null;
                
                if (!empty($settings['club_logo'])) {
                    $logo_path = '/communities/' . $community['id'] . '/' . $settings['club_logo'];
                }
                if (!empty($settings['club_image'])) {
                    $image_url = '/communities/' . $community['id'] . '/' . $settings['club_image'];
                }
                // Kategorileri array olarak al (JSON veya comma-separated)
                $categories = [];
                $category = $settings['club_category'] ?? null;
                if (!empty($category)) {
                    // JSON array kontrolü
                    $decoded = json_decode($category, true);
                    if (json_last_error() === JSON_ERROR_NONE && is_array($decoded)) {
                        $categories = array_filter($decoded, function($cat) {
                            return $cat !== 'other' && !empty($cat);
                        });
                    } else {
                        // Comma-separated veya tek kategori
                        $cats = explode(',', $category);
                        foreach ($cats as $cat) {
                            $cat = trim($cat);
                            if ($cat !== 'other' && !empty($cat)) {
                                $categories[] = $cat;
                            }
                        }
                    }
                }
                // Max 3 kategori
                $categories = array_slice($categories, 0, 3);
                $tags = !empty($settings['club_tags']) ? explode(',', $settings['club_tags']) : [];
                $is_verified = isset($settings['is_verified']) ? (bool)$settings['is_verified'] : false;
                
                // Hassas bilgiler sadece authenticated kullanıcılar için
                if ($currentUser) {
                    $contact_email = $settings['contact_email'] ?? null;
                    $website = $settings['website'] ?? null;
                    
                    if (!empty($settings['instagram']) || !empty($settings['twitter']) || !empty($settings['linkedin']) || !empty($settings['facebook'])) {
                        $social_links = [
                            'instagram' => $settings['instagram'] ?? null,
                            'twitter' => $settings['twitter'] ?? null,
                            'linkedin' => $settings['linkedin'] ?? null,
                            'facebook' => $settings['facebook'] ?? null
                        ];
                    }
                } else {
                    // Public kullanıcılar için hassas bilgileri gizle
                    $contact_email = null;
                    $website = null;
                    $social_links = null;
                }
                
                // Board member count
                $board_count = $db->querySingle("SELECT COUNT(*) FROM board_members WHERE club_id = 1") ?: 0;
                
                // Bağlantıyı pool'a geri ver
                ConnectionPool::releaseConnection($db_path, $poolId, true);
            } catch (Exception $e) {
                // Hata durumunda bağlantıyı release et
                if (isset($poolId)) {
                    ConnectionPool::releaseConnection($db_path, $poolId, true);
                }
                error_log("Communities API error: " . $e->getMessage());
                // Hata durumunda devam et
            }
        }
        
        // Board member count (eğer yukarıda alınmadıysa)
        if (!isset($board_count)) {
            $board_count = 0;
        }
        
            // Base URL
            $host = $_SERVER['HTTP_HOST'] ?? ($_SERVER['SERVER_NAME'] ?? 'foursoftware.com.tr');
            $protocol = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on') ? 'https' : 'http';
            $baseUrl = $protocol . '://' . $host;
        
        // QR kod deep link
        $qr_deep_link = 'unifour://community/' . urlencode($community['id']);
        
        // QR kod API URL'i
        $qr_code_url = $baseUrl . '/api/qr_code.php?type=community&id=' . urlencode($community['id']);
        
        $formatted_communities[] = [
            'id' => $community['id'],
            'name' => $community['name'],
            'description' => $community['description'] ?? '',
            'short_description' => null,
            'member_count' => (int)($community['member_count'] ?? 0),
            'event_count' => (int)($community['event_count'] ?? 0),
            'campaign_count' => (int)($community['campaign_count'] ?? 0),
            'board_member_count' => (int)$board_count,
            'image_url' => $image_url,
            'logo_path' => $logo_path,
                'categories' => $categories, // Array olarak döndür
            'tags' => $tags,
            'is_verified' => $is_verified,
            'created_at' => date('Y-m-d\TH:i:s\Z'),
            'contact_email' => $contact_email,
            'website' => $website,
            'social_links' => $social_links,
            'status' => 'active',
            'university' => $university,
            'qr_deep_link' => $qr_deep_link,
            'qr_code_url' => $qr_code_url
        ];
    }
    
    // Pagination bilgileri ile birlikte döndür
    sendResponse(true, $formatted_communities, null, null, [
        'count' => count($formatted_communities),
        'total' => $total_count,
        'limit' => $limit,
        'offset' => $offset,
        'has_more' => $has_more
    ]);
    
} catch (Exception $e) {
    // Hata loglama
    error_log("Communities API Error: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    error_log("Stack trace: " . $e->getTraceAsString());
    
    // Güvenli hata yanıtı
    http_response_code(500);
    sendResponse(false, null, null, 'Sunucu hatası: ' . $e->getMessage());
} catch (Error $e) {
    // PHP 7+ Error sınıfı için
    error_log("Communities API Fatal Error: " . $e->getMessage() . " in " . $e->getFile() . ":" . $e->getLine());
    error_log("Stack trace: " . $e->getTraceAsString());
    
    http_response_code(500);
    sendResponse(false, null, null, 'Sunucu hatası: ' . $e->getMessage());
}

