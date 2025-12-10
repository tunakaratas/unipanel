<?php
/**
 * Rastgele Veri Oluşturma Script'i
 * Tüm topluluklara üye, kampanya, market ürünü ve etkinlik verileri ekler
 */

// Güvenlik kontrolü - sadece localhost'tan çalışsın
if (php_sapi_name() !== 'cli') {
    $host = $_SERVER['HTTP_HOST'] ?? '';
    if ($host !== 'localhost' && $host !== '127.0.0.1' && strpos($host, 'localhost') === false) {
        die('Bu script sadece localhost\'ta çalışabilir!');
    }
}

// Hata raporlama
error_reporting(E_ALL);
ini_set('display_errors', 1);
set_time_limit(0);
ini_set('memory_limit', '1024M');

// Yol tanımlamaları
define('BASE_PATH', dirname(__DIR__));
define('COMMUNITIES_DIR', BASE_PATH . '/communities/');

// HTML başlığı
header('Content-Type: text/html; charset=utf-8');
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Rastgele Veri Oluşturma</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }
        .container {
            background: white;
            border-radius: 12px;
            padding: 30px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        h1 {
            color: #333;
            border-bottom: 3px solid #6366f1;
            padding-bottom: 10px;
        }
        .info {
            background: #dbeafe;
            border-left: 4px solid #3b82f6;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .success {
            background: #d1fae5;
            border-left: 4px solid #10b981;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .error {
            background: #fee2e2;
            border-left: 4px solid #ef4444;
            padding: 15px;
            margin: 10px 0;
            border-radius: 4px;
        }
        .log-item {
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
            font-family: 'Courier New', monospace;
            font-size: 13px;
        }
        .log-item.info {
            background: #e0f2fe;
            color: #0369a1;
        }
        .log-item.success {
            background: #d1fae5;
            color: #047857;
        }
        .log-item.error {
            background: #fee2e2;
            color: #991b1b;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px 0;
        }
        .stat-card {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card h3 {
            margin: 0;
            font-size: 32px;
            font-weight: bold;
        }
        .stat-card p {
            margin: 5px 0 0 0;
            opacity: 0.9;
        }
        .form-group {
            margin: 15px 0;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: 500;
        }
        input[type="number"] {
            width: 100px;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        button {
            background: #6366f1;
            color: white;
            border: none;
            padding: 12px 24px;
            border-radius: 8px;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
            margin: 10px 5px;
        }
        button:hover {
            background: #4f46e5;
        }
        button.secondary {
            background: #6b7280;
        }
        button.secondary:hover {
            background: #4b5563;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>🎲 Rastgele Veri Oluşturma</h1>
        
        <?php
        // Form parametreleri
        $confirmed = isset($_GET['confirm']) && $_GET['confirm'] === 'yes';
        $memberCount = isset($_GET['members']) ? (int)$_GET['members'] : 20;
        $eventCount = isset($_GET['events']) ? (int)$_GET['events'] : 10;
        $campaignCount = isset($_GET['campaigns']) ? (int)$_GET['campaigns'] : 5;
        $productCount = isset($_GET['products']) ? (int)$_GET['products'] : 8;
        
        if (!$confirmed) {
            ?>
            <div class="info">
                <p><strong>Bu script tüm topluluklara rastgele veri ekleyecektir:</strong></p>
                <ul>
                    <li>✅ Üyeler (members)</li>
                    <li>✅ Etkinlikler (events)</li>
                    <li>✅ Kampanyalar (campaigns)</li>
                    <li>✅ Market ürünleri (products)</li>
                </ul>
            </div>
            
            <form method="GET" style="margin-top: 20px;">
                <div class="form-group">
                    <label>Her topluluk için eklenecek üye sayısı:</label>
                    <input type="number" name="members" value="<?= $memberCount ?>" min="1" max="1000">
                </div>
                <div class="form-group">
                    <label>Her topluluk için eklenecek etkinlik sayısı:</label>
                    <input type="number" name="events" value="<?= $eventCount ?>" min="1" max="100">
                </div>
                <div class="form-group">
                    <label>Her topluluk için eklenecek kampanya sayısı:</label>
                    <input type="number" name="campaigns" value="<?= $campaignCount ?>" min="1" max="50">
                </div>
                <div class="form-group">
                    <label>Her topluluk için eklenecek ürün sayısı:</label>
                    <input type="number" name="products" value="<?= $productCount ?>" min="1" max="50">
                </div>
                <input type="hidden" name="confirm" value="yes">
                <button type="submit">Veri Oluştur</button>
                <a href="cleanup_random_data.php" style="display: inline-block; padding: 12px 24px; background: #6b7280; color: white; text-decoration: none; border-radius: 8px; margin-left: 10px;">Veri Temizle</a>
            </form>
            <?php
            exit;
        }
        
        // Veritabanı bağlantı fonksiyonu
        function getDB($dbPath) {
            $retries = 5;
            for ($i = 0; $i < $retries; $i++) {
                try {
                    $db = new SQLite3($dbPath);
                    $db->busyTimeout(5000);
                    $db->exec('PRAGMA journal_mode = WAL');
                    return $db;
                } catch (Exception $e) {
                    if ($i < $retries - 1) {
                        usleep(100000 * ($i + 1));
                        continue;
                    }
                    throw $e;
                }
            }
            return false;
        }
        
        // Rastgele isimler
        $firstNames = ['Ahmet', 'Mehmet', 'Ali', 'Ayşe', 'Fatma', 'Zeynep', 'Mustafa', 'Emre', 'Can', 'Deniz', 'Elif', 'Büşra', 'Selin', 'Cem', 'Burak', 'Kerem', 'Ege', 'Arda', 'Ece', 'Sude', 'Mert', 'Onur', 'Gizem', 'Melis', 'Berkan', 'Kaan', 'Berk', 'Yusuf', 'İrem', 'Dilara'];
        $lastNames = ['Yılmaz', 'Kaya', 'Demir', 'Şahin', 'Çelik', 'Yıldız', 'Yıldırım', 'Öztürk', 'Aydın', 'Özdemir', 'Arslan', 'Doğan', 'Kılıç', 'Aslan', 'Çetin', 'Kara', 'Koç', 'Kurt', 'Özkan', 'Şimşek', 'Polat', 'Erdoğan', 'Akar', 'Türk', 'Güneş'];
        
        // Rastgele etkinlik isimleri
        $eventTitles = [
            'Yeni Dönem Tanışma Toplantısı',
            'Kariyer Günleri',
            'Teknoloji Semineri',
            'Sosyal Sorumluluk Projesi',
            'Workshop: Web Geliştirme',
            'Networking Etkinliği',
            'Konferans: Gelecek Teknolojileri',
            'Hackathon Yarışması',
            'Kültürel Gezi',
            'Spor Turnuvası',
            'Müzik Gecesi',
            'Film Gösterimi',
            'Kitap Kulübü Toplantısı',
            'Girişimcilik Paneli',
            'Dil Öğrenme Atölyesi'
        ];
        
        // Rastgele kampanya isimleri
        $campaignTitles = [
            'Öğrenci İndirimi',
            'Yeni Üye Kampanyası',
            'Özel Fırsat',
            'Sezon Sonu İndirimi',
            'Erken Kayıt Avantajı',
            'Toplu Alım İndirimi',
            'Referans Bonusu',
            'Öğrenci Kartı İndirimi'
        ];
        
        // Rastgele ürün isimleri
        $productNames = [
            'Topluluk Tişörtü',
            'Hoodie',
            'Çanta',
            'Not Defteri',
            'Kalem Seti',
            'Rozet',
            'Anahtarlık',
            'Bardak',
            'Şapka',
            'Çorap'
        ];
        
        // İstatistikler
        $totalCommunities = 0;
        $processedCommunities = 0;
        $addedMembers = 0;
        $addedEvents = 0;
        $addedCampaigns = 0;
        $addedProducts = 0;
        $errors = [];
        
        echo "<div class='info'>";
        echo "<p><strong>🔄 Veri oluşturma işlemi başlatılıyor...</strong></p>";
        echo "<p>Her topluluk için: $memberCount üye, $eventCount etkinlik, $campaignCount kampanya, $productCount ürün eklenecek.</p>";
        echo "</div>";
        
        echo "<div class='log' style='max-height: 600px; overflow-y: auto; background: #f9fafb; padding: 15px; border-radius: 8px; margin: 20px 0;'>";
        
        // Tüm toplulukları bul
        $communities = glob(COMMUNITIES_DIR . '*', GLOB_ONLYDIR);
        $totalCommunities = count($communities);
        
        echo "<div class='log-item info'>📁 Toplam <strong>$totalCommunities</strong> topluluk bulundu.</div>";
        
        foreach ($communities as $communityPath) {
            $communityName = basename($communityPath);
            $dbPath = $communityPath . '/unipanel.sqlite';
            
            // Veritabanı yoksa atla
            if (!file_exists($dbPath)) {
                continue;
            }
            
            $processedCommunities++;
            
            try {
                $db = getDB($dbPath);
                if (!$db) {
                    $errors[] = "$communityName: Veritabanı açılamadı";
                    continue;
                }
                
                echo "<div class='log-item info'>🔄 İşleniyor: <strong>$communityName</strong></div>";
                
                $club_id = 1;
                
                // Tabloları oluştur
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
                
                $db->exec("CREATE TABLE IF NOT EXISTS products (
                    id INTEGER PRIMARY KEY,
                    club_id INTEGER,
                    name TEXT NOT NULL,
                    description TEXT,
                    price REAL DEFAULT 0,
                    stock INTEGER DEFAULT 0,
                    category TEXT DEFAULT 'Genel',
                    image_path TEXT,
                    status TEXT DEFAULT 'active',
                    commission_rate REAL DEFAULT 8.0,
                    iyzico_commission REAL DEFAULT 0,
                    platform_commission REAL DEFAULT 0,
                    total_price REAL DEFAULT 0,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )");
                
                // Üyeler ekle
                $memberStmt = $db->prepare("INSERT INTO members (club_id, full_name, email, student_id, phone_number, registration_date) VALUES (?, ?, ?, ?, ?, ?)");
                for ($i = 0; $i < $memberCount; $i++) {
                    $firstName = $firstNames[array_rand($firstNames)];
                    $lastName = $lastNames[array_rand($lastNames)];
                    $fullName = $firstName . ' ' . $lastName;
                    $email = strtolower($firstName . '.' . $lastName . rand(100, 999) . '@example.com');
                    $studentId = rand(100000, 999999);
                    $phone = '05' . rand(10, 99) . ' ' . rand(100, 999) . ' ' . rand(10, 99) . ' ' . rand(10, 99);
                    $regDate = date('Y-m-d', strtotime('-' . rand(0, 365) . ' days'));
                    
                    $memberStmt->bindValue(1, $club_id, SQLITE3_INTEGER);
                    $memberStmt->bindValue(2, $fullName, SQLITE3_TEXT);
                    $memberStmt->bindValue(3, $email, SQLITE3_TEXT);
                    $memberStmt->bindValue(4, $studentId, SQLITE3_TEXT);
                    $memberStmt->bindValue(5, $phone, SQLITE3_TEXT);
                    $memberStmt->bindValue(6, $regDate, SQLITE3_TEXT);
                    $memberStmt->execute();
                    $addedMembers++;
                }
                echo "<div class='log-item success'>  ✓ $memberCount üye eklendi</div>";
                
                // Etkinlikler ekle
                $eventStmt = $db->prepare("INSERT INTO events (club_id, title, description, date, time, location, category, status) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
                for ($i = 0; $i < $eventCount; $i++) {
                    $title = $eventTitles[array_rand($eventTitles)] . ' ' . ($i + 1);
                    $description = 'Bu etkinlik topluluğumuzun düzenlediği önemli bir organizasyondur. Tüm üyelerimiz davetlidir.';
                    $date = date('Y-m-d', strtotime('+' . rand(1, 90) . ' days'));
                    $time = sprintf('%02d:00', rand(9, 18));
                    $locations = ['A101', 'B201', 'Konferans Salonu', 'Spor Salonu', 'Kafeterya'];
                    $location = $locations[array_rand($locations)];
                    $categories = ['Genel', 'Eğitim', 'Sosyal', 'Spor', 'Kültür'];
                    $category = $categories[array_rand($categories)];
                    $statuses = ['planlanıyor', 'devam ediyor', 'tamamlandı'];
                    $status = $statuses[array_rand($statuses)];
                    
                    $eventStmt->bindValue(1, $club_id, SQLITE3_INTEGER);
                    $eventStmt->bindValue(2, $title, SQLITE3_TEXT);
                    $eventStmt->bindValue(3, $description, SQLITE3_TEXT);
                    $eventStmt->bindValue(4, $date, SQLITE3_TEXT);
                    $eventStmt->bindValue(5, $time, SQLITE3_TEXT);
                    $eventStmt->bindValue(6, $location, SQLITE3_TEXT);
                    $eventStmt->bindValue(7, $category, SQLITE3_TEXT);
                    $eventStmt->bindValue(8, $status, SQLITE3_TEXT);
                    $eventStmt->execute();
                    $addedEvents++;
                }
                echo "<div class='log-item success'>  ✓ $eventCount etkinlik eklendi</div>";
                
                // Kampanyalar ekle
                $campaignStmt = $db->prepare("INSERT INTO campaigns (club_id, title, description, offer_text, partner_name, discount_percentage, start_date, end_date, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)");
                for ($i = 0; $i < $campaignCount; $i++) {
                    $title = $campaignTitles[array_rand($campaignTitles)];
                    $description = 'Özel kampanya fırsatı! Kaçırma!';
                    $offerText = '%' . rand(10, 50) . ' indirim fırsatı!';
                    $partners = ['ABC Mağaza', 'XYZ Restoran', 'Tech Store', 'Book Shop', 'Sport Center'];
                    $partnerName = $partners[array_rand($partners)];
                    $discount = rand(10, 50);
                    $startDate = date('Y-m-d', strtotime('-' . rand(0, 30) . ' days'));
                    $endDate = date('Y-m-d', strtotime('+' . rand(1, 60) . ' days'));
                    $isActive = rand(0, 1);
                    
                    $campaignStmt->bindValue(1, $club_id, SQLITE3_INTEGER);
                    $campaignStmt->bindValue(2, $title, SQLITE3_TEXT);
                    $campaignStmt->bindValue(3, $description, SQLITE3_TEXT);
                    $campaignStmt->bindValue(4, $offerText, SQLITE3_TEXT);
                    $campaignStmt->bindValue(5, $partnerName, SQLITE3_TEXT);
                    $campaignStmt->bindValue(6, $discount, SQLITE3_INTEGER);
                    $campaignStmt->bindValue(7, $startDate, SQLITE3_TEXT);
                    $campaignStmt->bindValue(8, $endDate, SQLITE3_TEXT);
                    $campaignStmt->bindValue(9, $isActive, SQLITE3_INTEGER);
                    $campaignStmt->execute();
                    $addedCampaigns++;
                }
                echo "<div class='log-item success'>  ✓ $campaignCount kampanya eklendi</div>";
                
                // Ürünler ekle
                $productStmt = $db->prepare("INSERT INTO products (club_id, name, description, price, stock, category, status, commission_rate, iyzico_commission, platform_commission, total_price) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
                for ($i = 0; $i < $productCount; $i++) {
                    $name = $productNames[array_rand($productNames)];
                    $description = 'Topluluk ürünümüz, kaliteli ve özel tasarım.';
                    $price = rand(50, 500);
                    $stock = rand(10, 100);
                    $categories = ['Giyim', 'Aksesuar', 'Kırtasiye', 'Genel'];
                    $category = $categories[array_rand($categories)];
                    $status = 'active';
                    $commissionRate = 8.0;
                    $iyzicoCommission = $price * 0.029; // %2.9
                    $platformCommission = $price * ($commissionRate / 100);
                    $totalPrice = $price + $iyzicoCommission + $platformCommission;
                    
                    $productStmt->bindValue(1, $club_id, SQLITE3_INTEGER);
                    $productStmt->bindValue(2, $name, SQLITE3_TEXT);
                    $productStmt->bindValue(3, $description, SQLITE3_TEXT);
                    $productStmt->bindValue(4, $price, SQLITE3_REAL);
                    $productStmt->bindValue(5, $stock, SQLITE3_INTEGER);
                    $productStmt->bindValue(6, $category, SQLITE3_TEXT);
                    $productStmt->bindValue(7, $status, SQLITE3_TEXT);
                    $productStmt->bindValue(8, $commissionRate, SQLITE3_REAL);
                    $productStmt->bindValue(9, $iyzicoCommission, SQLITE3_REAL);
                    $productStmt->bindValue(10, $platformCommission, SQLITE3_REAL);
                    $productStmt->bindValue(11, $totalPrice, SQLITE3_REAL);
                    $productStmt->execute();
                    $addedProducts++;
                }
                echo "<div class='log-item success'>  ✓ $productCount ürün eklendi</div>";
                
                // WAL checkpoint
                $db->exec('PRAGMA wal_checkpoint(TRUNCATE)');
                $db->close();
                
            } catch (Exception $e) {
                $errors[] = "$communityName: " . $e->getMessage();
                echo "<div class='log-item error'>  ✗ Hata: " . htmlspecialchars($e->getMessage()) . "</div>";
            }
        }
        
        echo "</div>";
        
        // Özet
        echo "<div class='stats'>";
        echo "<div class='stat-card'>";
        echo "<h3>" . number_format($addedMembers) . "</h3>";
        echo "<p>Üye Eklendi</p>";
        echo "</div>";
        
        echo "<div class='stat-card'>";
        echo "<h3>" . number_format($addedEvents) . "</h3>";
        echo "<p>Etkinlik Eklendi</p>";
        echo "</div>";
        
        echo "<div class='stat-card'>";
        echo "<h3>" . number_format($addedCampaigns) . "</h3>";
        echo "<p>Kampanya Eklendi</p>";
        echo "</div>";
        
        echo "<div class='stat-card'>";
        echo "<h3>" . number_format($addedProducts) . "</h3>";
        echo "<p>Ürün Eklendi</p>";
        echo "</div>";
        echo "</div>";
        
        if (!empty($errors)) {
            echo "<div class='error'>";
            echo "<strong>⚠️ Hatalar:</strong>";
            echo "<ul>";
            foreach ($errors as $error) {
                echo "<li>" . htmlspecialchars($error) . "</li>";
            }
            echo "</ul>";
            echo "</div>";
        } else {
            echo "<div class='success'>";
            echo "<strong>✅ Veri oluşturma işlemi tamamlandı!</strong>";
            echo "<p>Toplam <strong>$processedCommunities</strong> topluluk işlendi.</p>";
            echo "</div>";
        }
        
        echo "<div style='margin-top: 30px;'>";
        echo "<a href='generate_random_data.php' style='display: inline-block; padding: 12px 24px; background: #6366f1; color: white; text-decoration: none; border-radius: 8px; margin-right: 10px;'>Tekrar Oluştur</a>";
        echo "<a href='cleanup_random_data.php' style='display: inline-block; padding: 12px 24px; background: #ef4444; color: white; text-decoration: none; border-radius: 8px;'>Veri Temizle</a>";
        echo "</div>";
        ?>
    </div>
</body>
</html>
