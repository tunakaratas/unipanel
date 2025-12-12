<?php
/**
 * Mobil API - Events Endpoint
 * GET /api/events.php - Tüm etkinlikleri listele
 * GET /api/events.php?community_id={id} - Topluluğa ait etkinlikleri listele
 * GET /api/events.php?id={id} - Tek bir etkinlik detayı
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';
require_once __DIR__ . '/auth_middleware.php';
require_once __DIR__ . '/connection_pool.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');

// OPTIONS request için hemen cevap ver
if (isset($_SERVER['REQUEST_METHOD']) && $_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
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

// Kullanıcı bilgilerini al (opsiyonel - giriş yapmışsa)
$currentUser = optionalAuth();

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

    // Basic path traversal / weird input defense (same spirit as communities.php)
    $raw = basename($raw);
    if (strpos($raw, '..') !== false || strpos($raw, '/') !== false || strpos($raw, '\\') !== false) {
        return '';
    }

    return normalize_university_id($raw);
}

// Kullanıcının üye olduğu toplulukları getir
function getUserCommunities($user_id, $user_email) {
    $communities_dir = __DIR__ . '/../communities';
    $user_communities = [];
    
    if (!is_dir($communities_dir)) {
        return $user_communities;
    }
    
    $communities = scandir($communities_dir);
    foreach ($communities as $community) {
        if ($community === '.' || $community === '..') continue;
        
        $db_path = $communities_dir . '/' . $community . '/unipanel.sqlite';
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
            
            // Email veya user_id ile kontrol et
            $check = $db->prepare("SELECT id FROM members WHERE club_id = 1 AND (LOWER(email) = LOWER(?) OR (user_id IS NOT NULL AND user_id = ?)) LIMIT 1");
            $check->bindValue(1, $user_email, SQLITE3_TEXT);
            $check->bindValue(2, $user_id, SQLITE3_INTEGER);
            $result = $check->execute();
            
            if ($result && $result->fetchArray(SQLITE3_ASSOC)) {
                $user_communities[] = $community;
            }
            
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            } catch (Exception $e) {
                // Hata durumunda bağlantıyı release et
                if (isset($poolId)) {
                    ConnectionPool::releaseConnection($db_path, $poolId, false);
                }
                error_log("Events API error: " . $e->getMessage());
                // Hata durumunda devam et
            }
    }
    
    return $user_communities;
}

// get_all_communities fonksiyonunu kopyala (communities.php'deki ile aynı)
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
        } catch (Exception $e) {
            // Hata durumunda bağlantıyı release et
            if (isset($poolId)) {
                ConnectionPool::releaseConnection($db_path, $poolId, false);
            }
            error_log("Events API error: " . $e->getMessage());
            continue;
        }
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
    $all_events = [];
    $requested_university_id = get_requested_university_id();
    
    // Debug log
    if ($requested_university_id !== '') {
        error_log("Events API: Üniversite filtresi aktif - Requested ID: '{$requested_university_id}'");
    } else {
        error_log("Events API: Üniversite filtresi yok - Tüm etkinlikler gösterilecek");
    }
    
    // Tek bir etkinlik detayı isteniyorsa
    if (isset($_GET['id']) && !empty($_GET['id'])) {
        $event_id = (int)$_GET['id'];
        $community_id = isset($_GET['community_id']) ? sanitizeCommunityId($_GET['community_id']) : null;
        
        if (!$community_id) {
            sendResponse(false, null, null, 'Etkinlik detayı için community_id parametresi gerekli');
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
    
        $query = $db->prepare("SELECT * FROM events WHERE id = ? AND club_id = 1");
        $query->bindValue(1, $event_id, SQLITE3_INTEGER);
    $result = $query->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$row) {
            // Bağlantıyı pool'a geri ver
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            sendResponse(false, null, null, 'Etkinlik bulunamadı');
        }
        
        // Anket kontrolü
        $has_survey = false;
        try {
        $survey_check = @$db->prepare("SELECT COUNT(*) FROM surveys WHERE event_id = ?");
            if ($survey_check) {
                $survey_check->bindValue(1, $event_id, SQLITE3_INTEGER);
        $survey_result = $survey_check->execute();
                if ($survey_result) {
        $survey_count = $survey_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
        $has_survey = $survey_count > 0;
                }
            }
        } catch (Exception $e) {
            // Surveys tablosu yoksa has_survey false kalır
            $has_survey = false;
        }
        
        // Topluluk adı
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
            $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
        }
        $community_name = $settings['club_name'] ?? $community_id;
        
        // Image ve video path
        $image_path = null;
        if (!empty($row['image_path'])) {
            $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
        }
        $video_path = null;
        if (!empty($row['video_path'])) {
            $video_path = '/communities/' . $community_id . '/' . $row['video_path'];
        }
        
        // RSVP sayısı
        $registered_count = 0;
        try {
            $rsvp_check = @$db->prepare("SELECT COUNT(*) FROM rsvps WHERE event_id = ?");
            if ($rsvp_check) {
                $rsvp_check->bindValue(1, $event_id, SQLITE3_INTEGER);
                $rsvp_result = $rsvp_check->execute();
                if ($rsvp_result) {
                    $registered_count = $rsvp_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
                }
            }
        } catch (Exception $e) {
            // RSVPs tablosu yoksa registered_count 0 kalır
            $registered_count = 0;
        }
        
        // Base URL
        $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
        
        // Takvim URL'i (.ics dosyası)
        $calendar_url = $baseUrl . '/api/calendar.php?event_id=' . urlencode($event_id) . '&community_id=' . urlencode($community_id);
        
        // QR kod deep link
        $qr_deep_link = 'unifour://event/' . urlencode($community_id) . '/' . urlencode($event_id);
        
        // QR kod API URL'i
        $qr_code_url = $baseUrl . '/api/qr_code.php?type=event&id=' . urlencode($event_id) . '&community_id=' . urlencode($community_id);
        
        // Event images (birden fazla fotoğraf)
        $event_images = [];
        try {
            $images_stmt = @$db->prepare("SELECT id, image_path FROM event_images WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC");
            if ($images_stmt) {
                $images_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                $images_result = $images_stmt->execute();
                if ($images_result) {
                    while ($image_row = $images_result->fetchArray(SQLITE3_ASSOC)) {
                        $image_full_path = '/communities/' . $community_id . '/' . $image_row['image_path'];
                        $event_images[] = [
                            'id' => (string)$image_row['id'],
                            'image_path' => $image_full_path,
                            'image_url' => $image_full_path
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            // event_images tablosu yoksa boş array
        }
        
        // Event videos (birden fazla video)
        $event_videos = [];
        try {
            $videos_stmt = @$db->prepare("SELECT id, video_path FROM event_videos WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC");
            if ($videos_stmt) {
                $videos_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                $videos_result = $videos_stmt->execute();
                if ($videos_result) {
                    while ($video_row = $videos_result->fetchArray(SQLITE3_ASSOC)) {
                        $video_full_path = '/communities/' . $community_id . '/' . $video_row['video_path'];
                        $event_videos[] = [
                            'id' => (string)$video_row['id'],
                            'video_path' => $video_full_path,
                            'video_url' => $video_full_path
                        ];
                    }
                }
            }
        } catch (Exception $e) {
            // event_videos tablosu yoksa boş array
        }
        
        $event = [
            'id' => (string)$row['id'],
            'title' => $row['title'] ?? '',
            'description' => $row['description'] ?? null,
            'date' => $row['date'] ?? '',
            'start_time' => $row['time'] ?? '',
            'end_time' => $row['end_time'] ?? null,
            'time' => $row['time'] ?? '',
            'location' => $row['location'] ?? null,
            'location_details' => $row['location_details'] ?? null,
            'image_url' => $image_path,
            'image_path' => $image_path,
            'video_path' => $video_path,
            'images' => $event_images,
            'videos' => $event_videos,
            'community_id' => $community_id,
            'community_name' => $community_name,
            'category' => $row['category'] ?? 'Diğer',
            'capacity' => isset($row['capacity']) ? (int)$row['capacity'] : null,
            'registered_count' => (int)$registered_count,
            'is_registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
            'registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
            'registration_deadline' => $row['registration_deadline'] ?? null,
            'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
            'organizer' => $row['organizer'] ?? null,
            'contact_email' => $row['contact_email'] ?? null,
            'contact_phone' => $row['contact_phone'] ?? null,
            'is_online' => isset($row['is_online']) ? (bool)$row['is_online'] : false,
            'online_link' => $row['online_link'] ?? null,
            'price' => isset($row['cost']) ? (float)$row['cost'] : null,
            'cost' => isset($row['cost']) ? (float)$row['cost'] : null,
            'currency' => $row['currency'] ?? 'TRY',
            'has_survey' => $has_survey,
            'status' => $row['status'] ?? 'upcoming',
            'calendar_url' => $calendar_url,
            'qr_deep_link' => $qr_deep_link,
            'qr_code_url' => $qr_code_url
        ];
        
        // Bağlantıyı pool'a geri ver
        ConnectionPool::releaseConnection($db_path, $poolId, false);
        sendResponse(true, $event);
    }
    
    // Topluluk ID varsa sadece o topluluğun etkinliklerini getir
    if (isset($_GET['community_id']) && !empty($_GET['community_id'])) {
        $community_id = sanitizeCommunityId($_GET['community_id']);
        $db_path = $communities_dir . '/' . $community_id . '/unipanel.sqlite';
        
        if (!file_exists($db_path)) {
            sendResponse(false, null, null, 'Topluluk bulunamadı');
        }
        
        // Pagination parametreleri (community_id ile de destekleniyor)
        $limit = isset($_GET['limit']) ? max(1, min(200, (int)$_GET['limit'])) : 20; // Default 20, max 200
        $offset = isset($_GET['offset']) ? max(0, (int)$_GET['offset']) : 0;
        
        // Connection pool kullan (10k kullanıcı için kritik)
        $connResult = ConnectionPool::getConnection($db_path, false);
        if (!$connResult) {
            sendResponse(false, null, null, 'Veritabanı bağlantısı kurulamadı.');
        }
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        // Topluluk adı
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
            $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
        }
        $community_name = $settings['club_name'] ?? $community_id;
        
        // Toplam etkinlik sayısını al
        $count_query = $db->query("SELECT COUNT(*) as total FROM events WHERE club_id = 1");
        $total_count = 0;
        if ($count_query) {
            $count_row = $count_query->fetchArray(SQLITE3_ASSOC);
            $total_count = $count_row['total'] ?? 0;
        }
        
        // Etkinlikleri çek (pagination ile)
        $query = $db->prepare("SELECT * FROM events WHERE club_id = 1 ORDER BY date DESC, time DESC LIMIT ? OFFSET ?");
        if (!$query) {
            error_log("Events API: Failed to prepare query for community $community_id: " . $db->lastErrorMsg());
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            sendResponse(false, null, null, 'Veritabanı sorgu hatası');
        }
        $query->bindValue(1, $limit, SQLITE3_INTEGER);
        $query->bindValue(2, $offset, SQLITE3_INTEGER);
        $result = $query->execute();
        if (!$result) {
            error_log("Events API: Failed to execute query for community $community_id: " . $db->lastErrorMsg());
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            sendResponse(false, null, null, 'Veritabanı sorgu hatası');
        }
        
        while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
            if (!$row) {
                break; // No more rows
            }
            // Anket kontrolü
            $has_survey = false;
            try {
                $survey_check = @$db->prepare("SELECT COUNT(*) FROM surveys WHERE event_id = ?");
                if ($survey_check) {
                    $survey_check->bindValue(1, $row['id'], SQLITE3_INTEGER);
                    $survey_result = $survey_check->execute();
                    if ($survey_result) {
                        $survey_count = $survey_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
                        $has_survey = $survey_count > 0;
                    }
                }
            } catch (Exception $e) {
                // Surveys tablosu yoksa has_survey false kalır
                $has_survey = false;
            }
            
            // RSVP sayısı
            $registered_count = 0;
            try {
                $rsvp_check = @$db->prepare("SELECT COUNT(*) FROM rsvps WHERE event_id = ?");
                if ($rsvp_check) {
                    $rsvp_check->bindValue(1, $row['id'], SQLITE3_INTEGER);
                    $rsvp_result = $rsvp_check->execute();
                    if ($rsvp_result) {
                        $registered_count = $rsvp_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
                    }
                }
            } catch (Exception $e) {
                // RSVPs tablosu yoksa registered_count 0 kalır
                $registered_count = 0;
            }
            
            // Image ve video path
            $image_path = null;
            if (!empty($row['image_path'])) {
                $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
            }
            $video_path = null;
            if (!empty($row['video_path'])) {
                $video_path = '/communities/' . $community_id . '/' . $row['video_path'];
            }
            
            // Base URL
            $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
            
            // Takvim URL'i (.ics dosyası)
            $calendar_url = $baseUrl . '/api/calendar.php?event_id=' . urlencode($row['id']) . '&community_id=' . urlencode($community_id);
            
            // QR kod deep link
            $qr_deep_link = 'unifour://event/' . urlencode($community_id) . '/' . urlencode($row['id']);
            
            // QR kod API URL'i
            $qr_code_url = $baseUrl . '/api/qr_code.php?type=event&id=' . urlencode($row['id']) . '&community_id=' . urlencode($community_id);
            
            // Event images (birden fazla fotoğraf) - Liste için sadece ilk birkaçını al
            $event_images = [];
            try {
                $images_stmt = @$db->prepare("SELECT id, image_path FROM event_images WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC LIMIT 5");
                if ($images_stmt) {
                    $images_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
                    $images_result = $images_stmt->execute();
                    if ($images_result) {
                        while ($image_row = $images_result->fetchArray(SQLITE3_ASSOC)) {
                            $image_full_path = '/communities/' . $community_id . '/' . $image_row['image_path'];
                            $event_images[] = [
                                'id' => (string)$image_row['id'],
                                'image_path' => $image_full_path,
                                'image_url' => $image_full_path
                            ];
                        }
                    }
                }
            } catch (Exception $e) {
                // event_images tablosu yoksa boş array
            }
            
            // Eski image_path varsa ve images array'inde yoksa ekle
            if (!empty($image_path) && empty($event_images)) {
                $event_images[] = [
                    'id' => '0',
                    'image_path' => $image_path,
                    'image_url' => $image_path
                ];
            }
            
            // Event videos (birden fazla video) - Liste için sadece ilk birkaçını al
            $event_videos = [];
            try {
                $videos_stmt = @$db->prepare("SELECT id, video_path FROM event_videos WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC LIMIT 3");
                if ($videos_stmt) {
                    $videos_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
                    $videos_result = $videos_stmt->execute();
                    if ($videos_result) {
                        while ($video_row = $videos_result->fetchArray(SQLITE3_ASSOC)) {
                            $video_full_path = '/communities/' . $community_id . '/' . $video_row['video_path'];
                            $event_videos[] = [
                                'id' => (string)$video_row['id'],
                                'video_path' => $video_full_path,
                                'video_url' => $video_full_path
                            ];
                        }
                    }
                }
            } catch (Exception $e) {
                // event_videos tablosu yoksa boş array
            }
            
            // Eski video_path varsa ve videos array'inde yoksa ekle
            if (!empty($video_path) && empty($event_videos)) {
                $event_videos[] = [
                    'id' => '0',
                    'video_path' => $video_path,
                    'video_url' => $video_path
                ];
            }
            
            $all_events[] = [
                'id' => (string)$row['id'],
                'title' => $row['title'] ?? '',
                'description' => $row['description'] ?? null,
                'date' => $row['date'] ?? '',
                'start_time' => $row['time'] ?? '',
                'end_time' => $row['end_time'] ?? null,
                'time' => $row['time'] ?? '',
                'location' => $row['location'] ?? null,
                'location_details' => $row['location_details'] ?? null,
                'image_url' => $image_path,
                'image_path' => $image_path,
                'video_path' => $video_path,
                'images' => $event_images,
                'videos' => $event_videos,
                'community_id' => $community_id,
                'community_name' => $community_name,
                'category' => $row['category'] ?? 'Diğer',
                'capacity' => isset($row['capacity']) ? (int)$row['capacity'] : null,
                'registered_count' => (int)$registered_count,
                'is_registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
                'registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
                'registration_deadline' => $row['registration_deadline'] ?? null,
                'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
                'organizer' => $row['organizer'] ?? null,
                'contact_email' => $row['contact_email'] ?? null,
                'contact_phone' => $row['contact_phone'] ?? null,
                'is_online' => isset($row['is_online']) ? (bool)$row['is_online'] : false,
                'online_link' => $row['online_link'] ?? null,
                'price' => isset($row['cost']) ? (float)$row['cost'] : null,
                'cost' => isset($row['cost']) ? (float)$row['cost'] : null,
                'currency' => $row['currency'] ?? 'TRY',
                'has_survey' => $has_survey,
                'status' => $row['status'] ?? 'upcoming',
                'calendar_url' => $calendar_url,
                'qr_deep_link' => $qr_deep_link,
                'qr_code_url' => $qr_code_url
            ];
        }
        
        // Bağlantıyı pool'a geri ver
        ConnectionPool::releaseConnection($db_path, $poolId, false);
        
        // Pagination bilgileriyle response döndür
        echo json_encode([
            'success' => true,
            'data' => $all_events,
            'count' => $total_count,
            'limit' => $limit,
            'offset' => $offset,
            'has_more' => ($offset + $limit) < $total_count,
            'message' => null,
            'error' => null
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    } else {
        // TÜM toplulukların etkinliklerini getir (giriş yapılmış olsun veya olmasın)
        // Pagination ile (memory limit'i önlemek için)
        $limit = isset($_GET['limit']) ? max(1, min(200, (int)$_GET['limit'])) : 200; // Default 200, max 200
        $offset = isset($_GET['offset']) ? max(0, (int)$_GET['offset']) : 0;
        
        // Debug
        error_log("Events API: Fetching all events. Requested University: '$requested_university_id'");
        
        $community_folders = glob($communities_dir . '/*', GLOB_ONLYDIR);
        
        foreach ($community_folders as $folder_path) {
            try {
                $community_id = basename($folder_path);
            if ($community_id === '.' || $community_id === '..') continue;

            $db_path = $folder_path . '/unipanel.sqlite';
            if (!file_exists($db_path)) {
                continue;
            }
            
            try {
                // Connection pool kullan (10k kullanıcı için kritik)
                $connResult = ConnectionPool::getConnection($db_path, true);
                if (!$connResult) {
                    continue;
                }
                $db = $connResult['db'];
                $poolId = $connResult['pool_id'];
                
                // Topluluk ayarlarını ve adını çek
                $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
                $settings = [];
                if ($settings_query) {
                    while ($setting_row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                        $settings[$setting_row['setting_key']] = $setting_row['setting_value'];
                    }
                }
                $community_name = $settings['club_name'] ?? ucwords(str_replace('_', ' ', $community_id));

                // Üniversite filtresi (isteğe bağlı)
                if ($requested_university_id !== '') {
                    $community_university_name = $settings['university'] ?? $settings['organization'] ?? '';
                    $community_university_id = normalize_university_id($community_university_name);
                    
                    if ($community_university_id === '' || $community_university_id !== $requested_university_id) {
                        ConnectionPool::releaseConnection($db_path, $poolId, true);
                        continue;
                    }
                }
                
                // Etkinlikleri çek
                $query = $db->prepare("SELECT * FROM events WHERE club_id = 1 ORDER BY date DESC, time DESC");
                if (!$query) {
                    ConnectionPool::releaseConnection($db_path, $poolId, true);
                    continue;
                }
                $result = $query->execute();
                if (!$result) {
                    ConnectionPool::releaseConnection($db_path, $poolId, true);
                    continue;
                }
                
                while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                    if (!$row) {
                        break; // No more rows
                    }
                    // Anket kontrolü
                    $has_survey = false;
                    try {
                        $survey_check = @$db->prepare("SELECT COUNT(*) FROM surveys WHERE event_id = ?");
                        if ($survey_check) {
                            $survey_check->bindValue(1, $row['id'], SQLITE3_INTEGER);
                            $survey_result = $survey_check->execute();
                            if ($survey_result) {
                                $survey_count = $survey_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
                                $has_survey = $survey_count > 0;
                            }
                        }
                    } catch (Exception $e) {
                        $has_survey = false;
                    }
                    
                    // RSVP sayısı
                    $registered_count = 0;
                    try {
                        $rsvp_check = @$db->prepare("SELECT COUNT(*) FROM rsvps WHERE event_id = ?");
                        if ($rsvp_check) {
                            $rsvp_check->bindValue(1, $row['id'], SQLITE3_INTEGER);
                            $rsvp_result = $rsvp_check->execute();
                            if ($rsvp_result) {
                                $registered_count = $rsvp_result->fetchArray(SQLITE3_NUM)[0] ?? 0;
                            }
                        }
                    } catch (Exception $e) {
                        $registered_count = 0;
                    }
                    
                    // Image ve video path
                    $image_path = null;
                    if (!empty($row['image_path'])) {
                        $image_path = '/communities/' . $community_id . '/' . $row['image_path'];
                    }
                    $video_path = null;
                    if (!empty($row['video_path'])) {
                        $video_path = '/communities/' . $community_id . '/' . $row['video_path'];
                    }
                    
                    // Base URL
                    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
                    
                    // Takvim URL'i
                    $calendar_url = $baseUrl . '/api/calendar.php?event_id=' . urlencode($row['id']) . '&community_id=' . urlencode($community_id);
                    
                    // QR deep link
                    $qr_deep_link = 'unifour://event/' . urlencode($community_id) . '/' . urlencode($row['id']);
                    
                    // QR API URL
                    $qr_code_url = $baseUrl . '/api/qr_code.php?type=event&id=' . urlencode($row['id']) . '&community_id=' . urlencode($community_id);
                    
                    // Event images
                    $event_images = [];
                    try {
                        $images_stmt = @$db->prepare("SELECT id, image_path FROM event_images WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC LIMIT 5");
                        if ($images_stmt) {
                            $images_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
                            $images_result = $images_stmt->execute();
                            if ($images_result) {
                                while ($image_row = $images_result->fetchArray(SQLITE3_ASSOC)) {
                                    $image_full_path = '/communities/' . $community_id . '/' . $image_row['image_path'];
                                    $event_images[] = [
                                        'id' => (string)$image_row['id'],
                                        'image_path' => $image_full_path,
                                        'image_url' => $image_full_path
                                    ];
                                }
                            }
                        }
                    } catch (Exception $e) {}
                    
                    if (!empty($image_path) && empty($event_images)) {
                        $event_images[] = [
                            'id' => '0',
                            'image_path' => $image_path,
                            'image_url' => $image_path
                        ];
                    }
                    
                    // Event videos
                    $event_videos = [];
                    try {
                        $videos_stmt = @$db->prepare("SELECT id, video_path FROM event_videos WHERE event_id = ? AND club_id = 1 ORDER BY uploaded_at DESC LIMIT 3");
                        if ($videos_stmt) {
                            $videos_stmt->bindValue(1, $row['id'], SQLITE3_INTEGER);
                            $videos_result = $videos_stmt->execute();
                            if ($videos_result) {
                                while ($video_row = $videos_result->fetchArray(SQLITE3_ASSOC)) {
                                    $video_full_path = '/communities/' . $community_id . '/' . $video_row['video_path'];
                                    $event_videos[] = [
                                        'id' => (string)$video_row['id'],
                                        'video_path' => $video_full_path,
                                        'video_url' => $video_full_path
                                    ];
                                }
                            }
                        }
                    } catch (Exception $e) {}
                    
                    if (!empty($video_path) && empty($event_videos)) {
                        $event_videos[] = [
                            'id' => '0',
                            'video_path' => $video_path,
                            'video_url' => $video_path
                        ];
                    }
                    
                    $all_events[] = [
                        'id' => (string)$row['id'],
                        'title' => $row['title'] ?? '',
                        'description' => $row['description'] ?? null,
                        'date' => $row['date'] ?? '',
                        'start_time' => $row['time'] ?? '',
                        'end_time' => $row['end_time'] ?? null,
                        'time' => $row['time'] ?? '',
                        'location' => $row['location'] ?? null,
                        'location_details' => $row['location_details'] ?? null,
                        'image_url' => $image_path,
                        'image_path' => $image_path,
                        'video_path' => $video_path,
                        'images' => $event_images,
                        'videos' => $event_videos,
                        'community_id' => $community_id,
                        'community_name' => $community_name,
                        'university' => $settings['university'] ?? $settings['organization'] ?? null,
                        'category' => $row['category'] ?? 'Diğer',
                        'capacity' => isset($row['capacity']) ? (int)$row['capacity'] : null,
                        'registered_count' => (int)$registered_count,
                        'is_registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
                        'registration_required' => isset($row['registration_required']) ? (bool)$row['registration_required'] : false,
                        'registration_deadline' => $row['registration_deadline'] ?? null,
                        'tags' => !empty($row['tags']) ? explode(',', $row['tags']) : [],
                        'organizer' => $row['organizer'] ?? null,
                        'contact_email' => $row['contact_email'] ?? null,
                        'contact_phone' => $row['contact_phone'] ?? null,
                        'is_online' => isset($row['is_online']) ? (bool)$row['is_online'] : false,
                        'online_link' => $row['online_link'] ?? null,
                        'price' => isset($row['cost']) ? (float)$row['cost'] : null,
                        'cost' => isset($row['cost']) ? (float)$row['cost'] : null,
                        'currency' => $row['currency'] ?? 'TRY',
                        'has_survey' => $has_survey,
                        'status' => $row['status'] ?? 'upcoming',
                        'calendar_url' => $calendar_url,
                        'qr_deep_link' => $qr_deep_link,
                        'qr_code_url' => $qr_code_url
                    ];
                }
                
                ConnectionPool::releaseConnection($db_path, $poolId, true);
            } catch (Exception $e) {
                // Hata durumunda bağlantıyı release et
                if (isset($poolId) && isset($db_path)) {
                    try {
                        ConnectionPool::releaseConnection($db_path, $poolId, true);
                    } catch (Exception $releaseError) {}
                }
                continue;
            }
            } catch (Throwable $t) {
                error_log("Events API: Fatal Loop Error for path '{$folder_path}': " . $t->getMessage());
                // Release if needed
                 if (isset($poolId) && isset($db_path)) {
                    try { ConnectionPool::releaseConnection($db_path, $poolId, true); } catch (Throwable $e) {}
                }
            }
        }
    }
    
    // Tüm etkinlikleri tarihe göre sırala (en yeni önce)
    usort($all_events, function($a, $b) {
        $dateA = ($a['date'] ?? '') . ' ' . ($a['time'] ?? '');
        $dateB = ($b['date'] ?? '') . ' ' . ($b['time'] ?? '');
        return strcmp($dateB, $dateA); // Descending order
    });
    
    // Toplam sayı
    $total_count = count($all_events);
    
    // Pagination uygula (sadece tüm topluluklar için)
    if (!isset($_GET['community_id']) && !isset($_GET['id'])) {
        $paginated_events = array_slice($all_events, $offset, $limit);
        
        // Debug: Toplam etkinlik sayısını logla
        error_log("Events API: {$total_count} etkinlik bulundu, {$limit} etkinlik döndürülüyor (offset: {$offset})");
        
        echo json_encode([
            'success' => true,
            'data' => $paginated_events,
            'count' => $total_count,
            'limit' => $limit,
            'offset' => $offset,
            'has_more' => ($offset + $limit) < $total_count,
            'message' => null,
            'error' => null
        ], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);
        exit;
    }
    
    // Tek topluluk veya tek etkinlik için pagination yok
    sendResponse(true, $all_events);
    
} catch (Exception $e) {
    error_log("Events API: Fatal error: " . $e->getMessage());
    error_log("Events API: Stack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'İşlem sırasında bir hata oluştu: ' . $e->getMessage());
} catch (Error $e) {
    error_log("Events API: Fatal PHP error: " . $e->getMessage());
    error_log("Events API: Stack trace: " . $e->getTraceAsString());
    http_response_code(500);
    sendResponse(false, null, null, 'İşlem sırasında bir hata oluştu: ' . $e->getMessage());
}

