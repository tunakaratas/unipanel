<?php
/**
 * Mobil API - Universities Endpoint
 * GET /api/universities.php - Tüm üniversiteleri listele
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';

header('Content-Type: application/json; charset=utf-8');
setSecureCORS();
header('Access-Control-Allow-Methods: GET, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight OPTIONS request
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
    $communities_dir = __DIR__ . '/../communities';
    $universities = [];
    $universityMap = [];
    
    if (!is_dir($communities_dir)) {
        sendResponse(true, []);
    }
    
    $dirs = scandir($communities_dir);
    $excluded_dirs = ['.', '..', 'assets', 'public', 'templates', 'system', 'docs'];
    
    // Tüm toplulukları tarayarak üniversiteleri bul
    foreach ($dirs as $dir) {
        if (in_array($dir, $excluded_dirs) || !is_dir($communities_dir . '/' . $dir)) {
            continue;
        }
        
        $db_path = $communities_dir . '/' . $dir . '/unipanel.sqlite';
        if (!file_exists($db_path)) {
            continue;
        }
        
        try {
            $db = new SQLite3($db_path);
            $db->exec('PRAGMA journal_mode = WAL');
            
            // Settings tablosunu oluştur (eğer yoksa)
            $db->exec("CREATE TABLE IF NOT EXISTS settings (
                id INTEGER PRIMARY KEY,
                club_id INTEGER,
                setting_key TEXT NOT NULL,
                setting_value TEXT NOT NULL
            )");
            
            $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
            $settings = [];
            if ($settings_query !== false) {
                while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                    $settings[$row['setting_key']] = $row['setting_value'];
                }
            }
            
            // Üniversite bilgisini al (university veya organization field'ından)
            $university = $settings['university'] ?? $settings['organization'] ?? null;
            
            if ($university && !empty($university)) {
                // Üniversite adını normalize et
                $university = trim($university);
                
                if (!isset($universityMap[$university])) {
                    $universityMap[$university] = [
                        'id' => strtolower(str_replace([' ', '-', '_'], '', $university)),
                        'name' => $university,
                        'community_count' => 0
                    ];
                }
                $universityMap[$university]['community_count']++;
            }
            
            $db->close();
        } catch (Exception $e) {
            // Hata durumunda devam et
        }
    }
    
    // Map'i array'e çevir ve sırala
    $universities = array_values($universityMap);
    
    // İsme göre sırala
    usort($universities, function($a, $b) {
        return strcmp($a['name'], $b['name']);
    });
    
    // Test için örnek üniversiteler ekle (eğer yoksa)
    $testUniversities = [
        'İstanbul Üniversitesi',
        'Ankara Üniversitesi',
        'Boğaziçi Üniversitesi',
        'Orta Doğu Teknik Üniversitesi',
        'Hacettepe Üniversitesi',
        'İstanbul Teknik Üniversitesi',
        'Galatasaray Üniversitesi',
        'Koç Üniversitesi',
        'Sabancı Üniversitesi',
        'Bilkent Üniversitesi'
    ];
    
    foreach ($testUniversities as $testUni) {
        $testUniId = strtolower(str_replace([' ', '-', '_'], '', $testUni));
        if (!isset($universityMap[$testUni])) {
            $universities[] = [
                'id' => $testUniId,
                'name' => $testUni,
                'community_count' => 0
            ];
        }
    }
    
    // Tekrar sırala
    usort($universities, function($a, $b) {
        return strcmp($a['name'], $b['name']);
    });
    
    // "Tümü" seçeneğini başa ekle
    array_unshift($universities, [
        'id' => 'all',
        'name' => 'Tümü',
        'community_count' => 0
    ]);
    
    sendResponse(true, $universities);
    
} catch (Exception $e) {
    $response = sendSecureErrorResponse('İşlem sırasında bir hata oluştu', $e);
    sendResponse($response['success'], $response['data'], $response['message'], $response['error']);
}

