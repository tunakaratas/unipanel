<?php
/**
 * Üniversite filtresi test scripti
 * Bu script gerçek bir API çağrısı simüle eder ve sonuçları gösterir
 */

require_once __DIR__ . '/api/security_helper.php';
require_once __DIR__ . '/lib/autoload.php';
require_once __DIR__ . '/api/connection_pool.php';

// Test için bir üniversite ID'si kullan
$test_university_id = 'bandırma17eylülüniversitesi'; // Normalize edilmiş ID

echo "=== ÜNİVERSİTE FİLTRESİ TEST ===\n\n";

// Normalize fonksiyonu
function normalize_university_id($value) {
    $value = trim((string)$value);
    if ($value === '') {
        return '';
    }
    $normalized = mb_strtolower($value, 'UTF-8');
    $normalized = str_replace([' ', '-', '_'], '', $normalized);
    return $normalized;
}

echo "Test University ID (normalized): {$test_university_id}\n\n";

// Communities dizinini tara
$communities_dir = __DIR__ . '/communities';
if (!is_dir($communities_dir)) {
    die("Communities dizini bulunamadı: {$communities_dir}\n");
}

$community_folders = glob($communities_dir . '/*', GLOB_ONLYDIR);
if ($community_folders === false) {
    $community_folders = [];
}

$excluded_dirs = ['.', '..', 'assets', 'public', 'templates', 'system', 'docs'];
$matched = [];
$skipped = [];

echo "Topluluklar taranıyor...\n\n";

foreach ($community_folders as $folder_path) {
    $community_id = basename($folder_path);
    if (in_array($community_id, $excluded_dirs)) {
        continue;
    }
    
    $db_path = $folder_path . '/unipanel.sqlite';
    if (!file_exists($db_path)) {
        continue;
    }
    
    try {
        $connResult = ConnectionPool::getConnection($db_path, false);
        if (!$connResult) {
            continue;
        }
        
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        // Settings'ten üniversite bilgisini al
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        if ($settings_query) {
            while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
        }
        
        $community_university_name = $settings['university'] ?? $settings['organization'] ?? '';
        $community_university_id = normalize_university_id($community_university_name);
        
        echo "Topluluk: {$community_id}\n";
        echo "  Üniversite Adı: '{$community_university_name}'\n";
        echo "  Normalize ID: '{$community_university_id}'\n";
        echo "  İstenen ID: '{$test_university_id}'\n";
        
        if ($community_university_id === '' || $community_university_id !== $test_university_id) {
            echo "  ❌ EŞLEŞMEDİ\n";
            $skipped[] = [
                'id' => $community_id,
                'university_name' => $community_university_name,
                'normalized_id' => $community_university_id
            ];
        } else {
            echo "  ✅ EŞLEŞTİ\n";
            $matched[] = [
                'id' => $community_id,
                'university_name' => $community_university_name,
                'normalized_id' => $community_university_id
            ];
        }
        echo "\n";
        
        ConnectionPool::releaseConnection($db_path, $poolId, false);
        
    } catch (Exception $e) {
        echo "  HATA: " . $e->getMessage() . "\n\n";
        if (isset($poolId) && isset($db_path)) {
            try {
                ConnectionPool::releaseConnection($db_path, $poolId, false);
            } catch (Exception $e2) {}
        }
    }
}

echo "\n=== SONUÇ ===\n";
echo "Eşleşen topluluklar: " . count($matched) . "\n";
echo "Atlanan topluluklar: " . count($skipped) . "\n\n";

if (count($matched) > 0) {
    echo "Eşleşen Topluluklar:\n";
    foreach ($matched as $comm) {
        echo "  - {$comm['id']} (Üniversite: '{$comm['university_name']}')\n";
    }
} else {
    echo "⚠️  HİÇBİR TOPLULUK EŞLEŞMEDİ!\n";
    echo "\nOlası sorunlar:\n";
    echo "1. Üniversite ID'si yanlış normalize edilmiş olabilir\n";
    echo "2. Topluluklarda üniversite bilgisi kayıtlı değil\n";
    echo "3. Üniversite adı farklı formatta kaydedilmiş olabilir\n";
}

if (count($skipped) > 0 && count($skipped) <= 10) {
    echo "\nAtlanan Topluluklar (ilk 10):\n";
    foreach (array_slice($skipped, 0, 10) as $comm) {
        echo "  - {$comm['id']} (Üniversite: '{$comm['university_name']}' -> Normalize: '{$comm['normalized_id']}')\n";
    }
}
