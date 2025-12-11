<?php
/**
 * Tüm topluluklara SMTP ayarlarını ekle
 * Bu script config/credentials.php'den SMTP ayarlarını çekip
 * tüm mevcut toplulukların veritabanına ekler
 */

require_once __DIR__ . '/../config/credentials.php';

$communities_dir = __DIR__ . '/../communities';
$credentials_path = __DIR__ . '/../config/credentials.php';

if (!file_exists($credentials_path)) {
    die("HATA: config/credentials.php dosyası bulunamadı!\n");
}

$credentials = require $credentials_path;

if (!isset($credentials['smtp']) || !is_array($credentials['smtp'])) {
    die("HATA: config/credentials.php'de SMTP ayarları bulunamadı!\n");
}

$smtp_config = $credentials['smtp'];

// SMTP ayarlarını hazırla
$smtp_settings = [
    'smtp_username' => $smtp_config['username'] ?? '',
    'smtp_password' => $smtp_config['password'] ?? '',
    'smtp_host' => $smtp_config['host'] ?? 'ms7.guzel.net.tr',
    'smtp_port' => (string)($smtp_config['port'] ?? 587),
    'smtp_secure' => $smtp_config['encryption'] ?? 'tls',
    'smtp_from_email' => $smtp_config['from_email'] ?? ($smtp_config['username'] ?? 'admin@foursoftware.com.tr'),
    'smtp_from_name' => $smtp_config['from_name'] ?? 'UniFour'
];

echo "SMTP Ayarları:\n";
echo "  Host: " . $smtp_settings['smtp_host'] . "\n";
echo "  Port: " . $smtp_settings['smtp_port'] . "\n";
echo "  Username: " . ($smtp_settings['smtp_username'] ? 'SET' : 'EMPTY') . "\n";
echo "  Password: " . ($smtp_settings['smtp_password'] ? 'SET' : 'EMPTY') . "\n";
echo "  From Email: " . $smtp_settings['smtp_from_email'] . "\n";
echo "  From Name: " . $smtp_settings['smtp_from_name'] . "\n\n";

if (!is_dir($communities_dir)) {
    die("HATA: communities klasörü bulunamadı: $communities_dir\n");
}

$dirs = scandir($communities_dir);
$excluded_dirs = ['.', '..', 'assets', 'templates', 'system', 'docs', 'index.php', '.htaccess'];
$processed = 0;
$success = 0;
$failed = 0;
$skipped = 0;

foreach ($dirs as $dir) {
    if (in_array($dir, $excluded_dirs) || !is_dir($communities_dir . '/' . $dir)) {
        continue;
    }
    
    $db_path = $communities_dir . '/' . $dir . '/unipanel.sqlite';
    
    if (!file_exists($db_path)) {
        echo "⏭️  ATLANDI: $dir (veritabanı yok)\n";
        $skipped++;
        continue;
    }
    
    try {
        $db = new SQLite3($db_path);
        $db->exec('PRAGMA journal_mode = WAL');
        
        // Settings tablosunun varlığını kontrol et
        $table_exists = (bool) $db->querySingle("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
        
        if (!$table_exists) {
            echo "⏭️  ATLANDI: $dir (settings tablosu yok)\n";
            $db->close();
            $skipped++;
            continue;
        }
        
        $updated_count = 0;
        
        // Her SMTP ayarını ekle/güncelle
        foreach ($smtp_settings as $key => $value) {
            if (!empty($value)) {
                try {
                    $stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                    if ($stmt) {
                        $stmt->bindValue(1, 1, SQLITE3_INTEGER);
                        $stmt->bindValue(2, $key, SQLITE3_TEXT);
                        $stmt->bindValue(3, $value, SQLITE3_TEXT);
                        $stmt->execute();
                        $updated_count++;
                    }
                } catch (Exception $e) {
                    echo "  ⚠️  Hata ($key): " . $e->getMessage() . "\n";
                }
            }
        }
        
        if ($updated_count > 0) {
            echo "✅ BAŞARILI: $dir ($updated_count ayar eklendi/güncellendi)\n";
            $success++;
        } else {
            echo "⏭️  ATLANDI: $dir (eklenecek ayar yok)\n";
            $skipped++;
        }
        
        $db->close();
        $processed++;
        
    } catch (Exception $e) {
        echo "❌ HATA: $dir - " . $e->getMessage() . "\n";
        $failed++;
        $processed++;
    }
}

echo "\n";
echo "═══════════════════════════════════════\n";
echo "ÖZET:\n";
echo "  İşlenen: $processed\n";
echo "  Başarılı: $success\n";
echo "  Başarısız: $failed\n";
echo "  Atlanan: $skipped\n";
echo "═══════════════════════════════════════\n";
