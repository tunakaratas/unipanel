<?php
namespace UniPanel\Payment;

use Exception;

/**
 * Abonelik Yönetim Sınıfı
 * Topluluk aboneliklerini yönetir
 */

class SubscriptionManager {
    private $db;
    private $communityId;
    
    public function __construct($db, $communityId) {
        $this->db = $db;
        $this->communityId = $communityId;
        // Tabloyu otomatik oluştur
        $this->createSubscriptionTable();
    }
    
    /**
     * Abonelik tablosunu oluştur (Güçlendirilmiş - Gerçek Hayat Senaryoları İçin)
     */
    public function createSubscriptionTable() {
        // Veritabanı yazılabilir mi kontrol et
        $db_path = $this->db->filename ?? null;
        $is_writable = false;
        
        if ($db_path && file_exists($db_path)) {
            if (!is_writable($db_path)) {
                @chmod($db_path, 0644);
                @chmod(dirname($db_path), 0755);
            }
            $is_writable = is_writable($db_path);
        }
        
        // Tablo zaten var mı kontrol et
        $table_exists = false;
        try {
            $result = $this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($result !== false) {
                $table_exists = $result->fetchArray() !== false;
            }
        } catch (\Exception $e) {
            // Tablo kontrolü başarısız, devam et
        }
        
        // Tablo yoksa ve yazılabilir değilse, hiçbir şey yapma
        if (!$table_exists && !$is_writable) {
            error_log("SubscriptionManager: Cannot create subscriptions table - database is readonly");
            return; // Readonly veritabanında tablo oluşturulamaz
        }
        
        try {
            // Önce basit tabloyu oluştur
            $result = @$this->db->exec("CREATE TABLE IF NOT EXISTS subscriptions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            community_id TEXT NOT NULL,
            payment_id TEXT,
            payment_status TEXT DEFAULT 'pending',
            amount REAL DEFAULT 250.00,
            currency TEXT DEFAULT 'TRY',
            start_date DATETIME,
            end_date DATETIME,
            is_active INTEGER DEFAULT 0,
            tier TEXT DEFAULT 'standard',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )");
            
            // Exec başarısız olduysa kontrol et
            if ($result === false) {
                $error_msg = $this->db->lastErrorMsg();
                if (strpos($error_msg, 'readonly') !== false) {
                    error_log("SubscriptionManager: Cannot create subscriptions table - readonly database");
                    return; // Readonly veritabanında devam etme
                }
            }
        } catch (\Exception $e) {
            // Readonly veritabanı hatası - sessizce devam et
            if (strpos($e->getMessage(), 'readonly') !== false) {
                error_log("SubscriptionManager: Cannot create subscriptions table (readonly) - " . $e->getMessage());
                return; // Tablo oluşturulamazsa devam etme
            }
            // Diğer hatalar için logla ama devam et
            error_log("SubscriptionManager: Table creation error - " . $e->getMessage());
        }
        
        // Tablo oluşturuldu mu kontrol et
        try {
            $result = $this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($result === false || $result->fetchArray() === false) {
                // Tablo oluşturulamadı, devam etme
                error_log("SubscriptionManager: subscriptions table does not exist after creation attempt");
                return;
            }
        } catch (\Exception $e) {
            error_log("SubscriptionManager: Table existence check failed - " . $e->getMessage());
            return;
        }
        
        // Yeni kolonları ekle (migration)
        try {
            $this->migrateSubscriptionTable();
        } catch (\Exception $e) {
            error_log("SubscriptionManager: Migration failed - " . $e->getMessage());
            // Migration hatası kritik değil, devam et
        }
        
        // Index oluştur (kolonlar eklendikten sonra)
        try {
            $columns = [];
            $result = $this->db->query("PRAGMA table_info(subscriptions)");
            if ($result !== false) {
                while ($row = $result->fetchArray(\SQLITE3_ASSOC)) {
                    $columns[] = $row['name'];
                }
            }
            
            // Veritabanı yazılabilirse index oluştur
            $db_path = $this->db->filename ?? null;
            if ($db_path && is_writable($db_path)) {
                @$this->db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_id ON subscriptions(payment_id) WHERE payment_id IS NOT NULL");
                
                // payment_token kolonu varsa index oluştur
                if (in_array('payment_token', $columns)) {
                    @$this->db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_token ON subscriptions(payment_token) WHERE payment_token IS NOT NULL");
                }
                
                @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_community_id ON subscriptions(community_id)");
                @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_payment_status ON subscriptions(payment_status)");
                
                // expires_at kolonu varsa index oluştur
                if (in_array('expires_at', $columns)) {
                    @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_expires_at ON subscriptions(expires_at) WHERE expires_at IS NOT NULL");
                }
            }
        } catch (\Exception $e) {
            // Readonly hatası sessizce geç
            if (strpos($e->getMessage(), 'readonly') === false) {
                error_log("Subscription index creation warning: " . $e->getMessage());
            }
        }
        
        // Subscription Logs Tablosu
        try {
            $db_path = $this->db->filename ?? null;
            if ($db_path && !is_writable($db_path)) {
                // Readonly ise tablo oluşturma işlemlerini atla
                return;
            }
            
            @$this->db->exec("CREATE TABLE IF NOT EXISTS subscription_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                subscription_id INTEGER,
                community_id TEXT NOT NULL,
                log_type TEXT NOT NULL,
                log_message TEXT,
                log_data TEXT,
                ip_address TEXT,
                user_agent TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (subscription_id) REFERENCES subscriptions(id) ON DELETE CASCADE
            )");
        } catch (\Exception $e) {
            if (strpos($e->getMessage(), 'readonly') === false) {
                error_log("Subscription logs table creation warning: " . $e->getMessage());
            }
        }
        
        // Subscription Rate Limits Tablosu
        try {
            @$this->db->exec("CREATE TABLE IF NOT EXISTS subscription_rate_limits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                community_id TEXT NOT NULL,
                ip_address TEXT,
                action_type TEXT NOT NULL,
                action_count INTEGER DEFAULT 0,
                hour_timestamp TEXT NOT NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )");
        } catch (\Exception $e) {
            if (strpos($e->getMessage(), 'readonly') === false) {
                error_log("Subscription rate limits table creation warning: " . $e->getMessage());
            }
        }
        
        // SMS Usage Tablosu - SMS kullanımını takip eder
        try {
            @$this->db->exec("CREATE TABLE IF NOT EXISTS sms_usage (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                community_id TEXT NOT NULL,
                recipient_count INTEGER NOT NULL,
                message_content TEXT,
                provider TEXT,
                sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                month_year TEXT NOT NULL,
                FOREIGN KEY (community_id) REFERENCES subscriptions(community_id)
            )");
            
            // SMS Usage için index
            @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_sms_usage_community_month ON sms_usage(community_id, month_year)");
            @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_sms_usage_sent_at ON sms_usage(sent_at)");
        } catch (\Exception $e) {
            if (strpos($e->getMessage(), 'readonly') === false) {
                error_log("SMS usage table creation warning: " . $e->getMessage());
            }
        }
        
        // SMS Kredileri Tablosu (Superadmin tarafından tahsis edilen SMS paketleri)
        try {
            @$this->db->exec("CREATE TABLE IF NOT EXISTS sms_credits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                community_id TEXT NOT NULL,
                credits INTEGER NOT NULL DEFAULT 0,
                package_name TEXT,
                assigned_by TEXT DEFAULT 'superadmin',
                assigned_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                notes TEXT
            )");
            
            // SMS Credits için index
            @$this->db->exec("CREATE INDEX IF NOT EXISTS idx_sms_credits_community ON sms_credits(community_id)");
        } catch (\Exception $e) {
            if (strpos($e->getMessage(), 'readonly') === false) {
                error_log("SMS credits table creation warning: " . $e->getMessage());
            }
        }
        
        // Tablo oluşturuldu mu tekrar kontrol et (migration ve diğer işlemler için)
        try {
            $result = $this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($result === false || $result->fetchArray() === false) {
                // Tablo yok, migration ve diğer işlemleri yapma
                error_log("SubscriptionManager: subscriptions table does not exist, skipping migrations");
                return;
            }
        } catch (\Exception $e) {
            error_log("SubscriptionManager: Table existence check failed - " . $e->getMessage());
            return;
        }
        
        // Migration: tier sütunu yoksa ekle
        try {
            $this->migrateTierColumn();
        } catch (\Exception $e) {
            error_log("SubscriptionManager: migrateTierColumn failed - " . $e->getMessage());
        }
        
        // Standart sürümü otomatik aktif et (eğer abonelik yoksa)
        try {
            $this->ensureStandardSubscription();
        } catch (\Exception $e) {
            error_log("SubscriptionManager: ensureStandardSubscription failed - " . $e->getMessage());
            // Hata kritik değil, devam et
        }
    }
    
    /**
     * Subscriptions tablosu migration (yeni kolonları ekle)
     */
    private function migrateSubscriptionTable() {
        try {
            // Önce tablonun varlığını kontrol et
            $table_check = $this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($table_check === false || $table_check->fetchArray() === false) {
                return; // Tablo yoksa migration yapma
            }
            
            // Mevcut kolonları kontrol et
            $existingColumns = [];
            $result = @$this->db->query("PRAGMA table_info(subscriptions)");
            if ($result !== false) {
                while ($row = $result->fetchArray(\SQLITE3_ASSOC)) {
                    $existingColumns[] = $row['name'];
                }
            }
            
            // Yeni kolonları ekle (eğer yoksa) - UNIQUE constraint olmadan
            $newColumns = [
                'payment_token' => 'TEXT',
                'months' => 'INTEGER DEFAULT 1',
                'session_id' => 'TEXT',
                'ip_address' => 'TEXT',
                'user_agent' => 'TEXT',
                'retry_count' => 'INTEGER DEFAULT 0',
                'last_retry_at' => 'DATETIME',
                'expires_at' => 'DATETIME',
                'verified_at' => 'DATETIME',
                'refunded_at' => 'DATETIME',
                'refund_amount' => 'REAL DEFAULT 0',
                'refund_reason' => 'TEXT',
                'notification_sent' => 'INTEGER DEFAULT 0'
            ];
            
            foreach ($newColumns as $columnName => $columnType) {
                if (!in_array($columnName, $existingColumns)) {
                    try {
                        // Veritabanı yazılabilir mi kontrol et
                        $db_path = $this->db->filename ?? null;
                        if ($db_path && !is_writable($db_path)) {
                            continue; // Readonly ise bu kolonu atla
                        }
                        
                        // SQLite'da UNIQUE constraint ile kolon eklenemez, sadece kolon tipi
                        $result = @$this->db->exec("ALTER TABLE subscriptions ADD COLUMN {$columnName} {$columnType}");
                        if ($result === false) {
                            $error_msg = $this->db->lastErrorMsg();
                            if (strpos($error_msg, 'readonly') === false && strpos($error_msg, 'duplicate column') === false) {
                                error_log("Subscription column migration warning: {$columnName} - " . $error_msg);
                            }
                        }
                    } catch (\Exception $e) {
                        // Readonly veritabanı hatası sessizce geç, diğer hataları logla
                        if (strpos($e->getMessage(), 'readonly') === false && strpos($e->getMessage(), 'duplicate column') === false) {
                            error_log("Subscription column migration warning: {$columnName} - " . $e->getMessage());
                        }
                    }
                }
            }
            
            // Unique index'leri oluştur (kolonlar eklendikten sonra)
            try {
                $db_path = $this->db->filename ?? null;
                if ($db_path && !is_writable($db_path)) {
                    return; // Readonly ise index oluşturma
                }
                
                $updatedColumns = [];
                $result = @$this->db->query("PRAGMA table_info(subscriptions)");
                if ($result !== false) {
                    while ($row = $result->fetchArray(\SQLITE3_ASSOC)) {
                        $updatedColumns[] = $row['name'];
                    }
                }
                
                // payment_token için unique index
                if (in_array('payment_token', $updatedColumns)) {
                    @$this->db->exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_payment_token ON subscriptions(payment_token) WHERE payment_token IS NOT NULL");
                }
            } catch (\Exception $e) {
                if (strpos($e->getMessage(), 'readonly') === false) {
                    error_log("Subscription unique index creation warning: " . $e->getMessage());
                }
            }
            
        } catch (\Exception $e) {
            error_log("Subscription table migration error: " . $e->getMessage());
        }
    }
    
    /**
     * Tier sütunu migration
     */
    private function migrateTierColumn() {
        try {
            // Önce tablonun varlığını kontrol et
            $table_check = @$this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($table_check === false || $table_check->fetchArray() === false) {
                return; // Tablo yoksa çık
            }
            
            // Veritabanı yazılabilir mi kontrol et
            $db_path = $this->db->filename ?? null;
            if ($db_path && !is_writable($db_path)) {
                return; // Readonly ise migration yapma
            }
            
            // Mevcut sütunları kontrol et
            $existingColumns = [];
            $result = @$this->db->query("PRAGMA table_info(subscriptions)");
            if ($result !== false) {
                while ($row = $result->fetchArray(\SQLITE3_ASSOC)) {
                    $existingColumns[] = $row['name'];
                }
            }
            
            // tier sütunu yoksa ekle
            if (!in_array('tier', $existingColumns)) {
                try {
                    $result = @$this->db->exec("ALTER TABLE subscriptions ADD COLUMN tier TEXT DEFAULT 'standard'");
                    if ($result === false) {
                        $error_msg = $this->db->lastErrorMsg();
                        if (strpos($error_msg, 'readonly') === false && strpos($error_msg, 'duplicate column') === false) {
                            error_log("Tier sütunu eklenirken hata: " . $error_msg);
                        }
                        return;
                    }
                    
                    // Mevcut kayıtları güncelle (amount'a göre tier belirle) - sadece yazılabilirse
                    if ($db_path && is_writable($db_path)) {
                        @$this->db->exec("UPDATE subscriptions SET tier = 'standard' WHERE amount = 0 OR tier IS NULL");
                        @$this->db->exec("UPDATE subscriptions SET tier = 'professional' WHERE amount > 0 AND amount <= 250 AND (tier IS NULL OR tier = 'standard')");
                        @$this->db->exec("UPDATE subscriptions SET tier = 'business' WHERE amount > 250 AND (tier IS NULL OR tier = 'standard')");
                    }
                } catch (\Exception $e) {
                    // Readonly hatası sessizce geç
                    if (strpos($e->getMessage(), 'readonly') === false && strpos($e->getMessage(), 'duplicate column') === false) {
                        error_log("Tier sütunu eklenirken hata: " . $e->getMessage());
                    }
                }
            }
        } catch (\Exception $e) {
            // Genel hata - sessizce geç
            if (strpos($e->getMessage(), 'readonly') === false && strpos($e->getMessage(), 'no such table') === false) {
                error_log("migrateTierColumn error: " . $e->getMessage());
            }
        }
    }
    
    /**
     * Standart sürümü otomatik aktif et - Her zaman aktif olmalı
     */
    private function ensureStandardSubscription() {
        // Önce tablonun varlığını kontrol et
        $table_exists = false;
        try {
            $result = $this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            $table_exists = $result !== false && $result->fetchArray() !== false;
        } catch (\Exception $e) {
            error_log("SubscriptionManager: Table check failed - " . $e->getMessage());
            return; // Tablo yoksa veya hata varsa çık
        }
        
        if (!$table_exists) {
            error_log("SubscriptionManager: subscriptions table does not exist, skipping ensureStandardSubscription");
            return;
        }
        
        // Standart abonelik var mı kontrol et
        $check_stmt = $this->db->prepare("
            SELECT id FROM subscriptions 
            WHERE community_id = ? 
            AND tier = 'standard'
            AND payment_status = 'success'
            LIMIT 1
        ");
        
        if ($check_stmt === false) {
            error_log("SubscriptionManager: prepare() failed - " . $this->db->lastErrorMsg());
            return;
        }
        
        $check_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
        $check_result = $check_stmt->execute();
        
        if ($check_result === false) {
            error_log("SubscriptionManager: execute() failed - " . $this->db->lastErrorMsg());
            return;
        }
        
        $existing_standard = $check_result->fetchArray(\SQLITE3_ASSOC);
        
        // Eğer standart abonelik yoksa, otomatik oluştur
        if (!$existing_standard) {
            $startDate = date('Y-m-d H:i:s');
            // Standart sürüm sınırsız, end_date'i çok ileri bir tarih yap
            $endDate = date('Y-m-d H:i:s', strtotime('+100 years'));
            
            $stmt = $this->db->prepare("
                INSERT INTO subscriptions 
                (community_id, payment_id, payment_status, amount, tier, start_date, end_date, is_active, payment_token)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            
            if ($stmt === false) {
                error_log("SubscriptionManager: INSERT prepare() failed - " . $this->db->lastErrorMsg());
                return;
            }
            
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(2, 'STANDARD-FREE-' . $this->communityId . '-' . time(), \SQLITE3_TEXT);
            $stmt->bindValue(3, 'success', \SQLITE3_TEXT);
            $stmt->bindValue(4, 0.00, \SQLITE3_FLOAT);
            $stmt->bindValue(5, 'standard', \SQLITE3_TEXT);
            $stmt->bindValue(6, $startDate, \SQLITE3_TEXT);
            $stmt->bindValue(7, $endDate, \SQLITE3_TEXT);
            $stmt->bindValue(8, 1, \SQLITE3_INTEGER);
            $stmt->bindValue(9, bin2hex(random_bytes(16)), \SQLITE3_TEXT);
            
            $result = $stmt->execute();
            if ($result === false) {
                error_log("SubscriptionManager: INSERT execute() failed - " . $this->db->lastErrorMsg());
                return;
            }
            
            $subscription_id = $this->db->lastInsertRowID();
            $this->logSubscriptionAction($subscription_id, 'standard_auto_created', 'Standart abonelik otomatik oluşturuldu', []);
        } else {
            // Mevcut standart aboneliği her zaman aktif yap
            $update_stmt = $this->db->prepare("
                UPDATE subscriptions 
                SET is_active = 1, 
                    payment_status = 'success',
                    updated_at = CURRENT_TIMESTAMP
                WHERE community_id = ? 
                AND tier = 'standard'
            ");
            
            if ($update_stmt === false) {
                error_log("SubscriptionManager: UPDATE prepare() failed - " . $this->db->lastErrorMsg());
                return;
            }
            
            $update_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $result = $update_stmt->execute();
            
            if ($result === false) {
                error_log("SubscriptionManager: UPDATE execute() failed - " . $this->db->lastErrorMsg());
                return;
            }
        }
    }
    
    /**
     * Aktif aboneliği kontrol et - Standart her zaman aktif
     */
    public function isActive() {
        // Tabloyu garantile
        $this->createSubscriptionTable();
        
        // Standart abonelik her zaman aktif
        $standard_stmt = $this->db->prepare("
            SELECT * FROM subscriptions 
            WHERE community_id = ? 
            AND tier = 'standard'
            AND payment_status = 'success'
            AND is_active = 1
            LIMIT 1
        ");
        if ($standard_stmt === false) {
            error_log("SubscriptionManager isActive: standard prepare() failed - " . $this->db->lastErrorMsg());
            return true; // Varsayılan olarak aktif döndür
        }
        $standard_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
        $standard_result = $standard_stmt->execute();
        $standard_subscription = $standard_result->fetchArray(\SQLITE3_ASSOC);
        
        if ($standard_subscription) {
            return true; // Standart abonelik her zaman aktif
        }
        
        // Profesyonel veya Business aboneliği kontrol et
        $stmt = $this->db->prepare("
            SELECT * FROM subscriptions 
            WHERE community_id = ? 
            AND tier IN ('professional', 'business')
            AND is_active = 1 
            AND payment_status = 'success'
            AND end_date > datetime('now')
            ORDER BY end_date DESC 
            LIMIT 1
        ");
        if ($stmt === false) {
            error_log("SubscriptionManager isActive: prepare() failed - " . $this->db->lastErrorMsg());
            return false;
        }
        $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
        $result = $stmt->execute();
        $subscription = $result->fetchArray(\SQLITE3_ASSOC);
        
        return $subscription !== false;
    }
    
    /**
     * Abonelik bilgilerini al - En yüksek tier'ı önceliklendir
     */
    public function getSubscription() {
        // Önce tablonun varlığını kontrol et
        $table_check = @$this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
        if ($table_check === false || $table_check->fetchArray() === false) {
            // Tablo yoksa oluşturmayı dene
            $this->createSubscriptionTable();
            // Tekrar kontrol et
            $table_check = @$this->db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='subscriptions'");
            if ($table_check === false || $table_check->fetchArray() === false) {
                // Tablo hala yoksa null dön
                return null;
            }
        }
        
        // Önce aktif profesyonel/business aboneliği kontrol et
        $stmt = @$this->db->prepare("
            SELECT * FROM subscriptions 
            WHERE community_id = ? 
            AND tier IN ('professional', 'business')
            AND payment_status = 'success'
            AND is_active = 1
            AND end_date > datetime('now')
            ORDER BY 
                CASE tier
                    WHEN 'business' THEN 3
                    WHEN 'professional' THEN 2
                    ELSE 1
                END DESC,
                created_at DESC
            LIMIT 1
        ");
        if ($stmt === false) {
            $error_msg = $this->db->lastErrorMsg();
            if (strpos($error_msg, 'no such table') === false) {
                error_log("SubscriptionManager: prepare() failed - " . $error_msg);
            }
            return null;
        }
        $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
        $result = $stmt->execute();
        $paid_subscription = $result->fetchArray(\SQLITE3_ASSOC);
        
        if ($paid_subscription) {
            return $paid_subscription;
        }
        
        // Aktif paid abonelik yoksa standart aboneliği getir
        $standard_stmt = @$this->db->prepare("
            SELECT * FROM subscriptions 
            WHERE community_id = ? 
            AND tier = 'standard'
            AND payment_status = 'success'
            AND is_active = 1
            ORDER BY created_at DESC 
            LIMIT 1
        ");
        if ($standard_stmt === false) {
            $error_msg = $this->db->lastErrorMsg();
            if (strpos($error_msg, 'no such table') === false) {
                error_log("SubscriptionManager: standard prepare() failed - " . $error_msg);
            }
            return null;
        }
        $standard_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
        $standard_result = $standard_stmt->execute();
        $standard_subscription = $standard_result->fetchArray(\SQLITE3_ASSOC);
        
        if ($standard_subscription) {
            return $standard_subscription;
        }
        
        // Hiç abonelik yoksa null döndür (ensureStandardSubscription otomatik oluşturur)
        return null;
    }
    
    /**
     * Mevcut tier'ı al (standart, professional, business)
     */
    public function getCurrentTier() {
        $subscription = $this->getSubscription();
        
        if (!$subscription) {
            return 'standard'; // Varsayılan standart
        }
        
        $tier = strtolower($subscription['tier'] ?? 'standard');
        
        // Eğer paid abonelik süresi dolmuşsa standart'a dön
        if ($tier !== 'standard') {
            if ($subscription['end_date'] && strtotime($subscription['end_date']) < time()) {
                return 'standard';
            }
            if ($subscription['payment_status'] !== 'success' || !$subscription['is_active']) {
                return 'standard';
            }
        }
        
        return $tier;
    }
    
    /**
     * Paket fiyatlarını getir
     */
    public static function getPackagePrices() {
        $currentMonth = (int)date('n');
        $isSeptember = ($currentMonth === 9); // Eylül ayı kontrolü
        
        // Sürüm bazlı aylık fiyatlar
        $standardMonthly = 0.00;
        $professionalMonthly = 250.00;
        // Business paket: SMS kredili sistem (fiyatsız - SMS paketlerine göre)
        
        // Süre bazlı indirimler (1, 6, 12 ay)
        $discounts = [
            1 => 0,    // 1 ay: %0 indirim
            6 => 5,    // 6 ay: %5 indirim
            12 => 10   // 12 ay: %10 indirim
        ];
        
        $packages = [];
        
        // Standart Sürüm
        foreach ([1, 6, 12] as $months) {
            $basePrice = $standardMonthly * $months;
            $discount = $discounts[$months];
            $price = $basePrice * (1 - $discount / 100);
            
            $packages["standard_{$months}"] = [
                'tier' => 'standard',
                'tier_label' => 'Standart',
                'months' => $months,
                'price' => 0, // Standart sürüm her zaman ücretsiz
                'original_price' => $basePrice,
                'monthly_price' => $standardMonthly,
                'discount' => 0,
                'label' => "Standart - Ücretsiz",
                'badge' => 'Ücretsiz',
                'unlimited' => true,
                'features' => [
                    'Pano, etkinlik ve üye yönetimi',
                    'Yönetim kurulu & görev atamaları',
                    'Market: en fazla 2 ürün yayınlama',
                    'Kampanyalar: 3 aktif kampanya limiti',
                    'Mail merkezlerini sınırsız kullanabilirsiniz',
                    'Temel bildirimler ve otomatik yedekleme',
                    'Standart destek (mesai saatlerinde)'
                ]
            ];
        }
        
        // Professional Sürüm (250 TL/ay)
        foreach ([1, 6, 12] as $months) {
            $basePrice = $professionalMonthly * $months;
            $discount = $discounts[$months];
            $price = $basePrice * (1 - $discount / 100);
            
            $packages["professional_{$months}"] = [
                'tier' => 'professional',
                'tier_label' => 'Profesyonel',
                'months' => $months,
                'price' => $isSeptember ? 0 : $price,
                'original_price' => $basePrice,
                'monthly_price' => $professionalMonthly,
                'discount' => $discount,
                'label' => "Profesyonel - {$months} Aylık",
                'badge' => $months === 6 ? 'Popüler' : ($months === 12 ? 'En İyi Değer' : ''),
                'features' => [
                    'Tüm Standart özellikler',
                    'Market: sınırsız ürün & varyantlar',
                    'Kampanyalar: sınırsız aktif kampanya',
                    'Raporlar & Analitik + AI önerileri',
                    'Öncelikli destek (24 saat içinde dönüş)'
                ]
            ];
        }
        
        // Business Sürüm - Aylık Abonelik
        // Her ay 500 SMS hediye ile gelir
        $businessMonthly = 500.00;
        
        foreach ([1, 6, 12] as $months) {
            $basePrice = $businessMonthly * $months;
            $discount = $discounts[$months];
            $price = $basePrice * (1 - $discount / 100);
            
            $packages["business_{$months}"] = [
                'tier' => 'business',
                'tier_label' => 'Business',
                'months' => $months,
                'price' => $price,
                'original_price' => $basePrice,
                'monthly_price' => $businessMonthly,
                'discount' => $discount,
                'monthly_sms_gift' => 500, // Her ay 500 SMS hediye
                'label' => "Business - {$months} Aylık",
                'badge' => $months === 12 ? 'En Avantajlı' : '',
                'features' => [
                    'Tüm Profesyonel özellikler',
                    'Her ay 500 SMS hediyesi + NetGSM entegrasyonu',
                    'SMS ve Mail merkezlerinde canlı gönderim',
                    'Finans & muhasebe entegrasyonları',
                    'Gelişmiş analitik, AI içgörü ve KPI raporları',
                    'Kampanya & pazar yeri premium araçları',
                    'Özel entegrasyonlar, SSO ve müşteri temsilcisi',
                    '7/24 öncelikli destek ve SLA'
                ]
            ];
        }
        
        // SMS Ek Paketleri (Business abonelerine ek olarak)
        // 10.000 SMS paketi %7 komisyon (avantajlı), diğerleri %10
        $smsAddonPackages = [
            1000 => ['netgsm' => 284, 'commission' => 10],
            3000 => ['netgsm' => 689, 'commission' => 10],
            5000 => ['netgsm' => 869, 'commission' => 10],
            10000 => ['netgsm' => 871, 'commission' => 7],  // Avantajlı paket
            25000 => ['netgsm' => 2035, 'commission' => 10],
            50000 => ['netgsm' => 3738, 'commission' => 10],
            100000 => ['netgsm' => 6462, 'commission' => 10]
        ];
        
        foreach ($smsAddonPackages as $smsCount => $priceInfo) {
            $netgsmPrice = $priceInfo['netgsm'];
            $commissionRate = $priceInfo['commission'];
            $totalPrice = round($netgsmPrice * (1 + $commissionRate / 100), 2);
            
            $packages["business_sms_addon_{$smsCount}"] = [
                'tier' => 'business_addon',
                'tier_label' => 'SMS Ek Paketi',
                'sms_credits' => $smsCount,
                'price' => $totalPrice,
                'netgsm_price' => $netgsmPrice,
                'commission_rate' => $commissionRate,
                'commission' => round($totalPrice - $netgsmPrice, 2),
                'label' => number_format($smsCount, 0, ',', '.') . " SMS Kredisi",
                'badge' => $smsCount === 10000 ? 'Avantajlı %7' : ($smsCount === 50000 ? 'En İyi Değer' : ''),
                'is_addon' => true,
                'features' => [
                    number_format($smsCount, 0, ',', '.') . ' SMS gönderim hakkı',
                    'Sınırsız süre geçerlilik',
                    'NetGSM altyapısı',
                    $commissionRate === 7 ? 'Sadece %7 komisyon!' : 'Standart fiyatlandırma'
                ]
            ];
        }
        
        return $packages;
    }
    
    /**
     * Sürüm bazlı paketleri getir
     */
    public static function getPackagesByTier() {
        $allPackages = self::getPackagePrices();
        $grouped = [
            'standard' => [],
            'professional' => [],
            'business' => [],
            'business_addon' => []
        ];
        
        foreach ($allPackages as $key => $package) {
            $grouped[$package['tier']][] = $package;
        }
        
        return $grouped;
    }
    
    /**
     * Eylül ayı kontrolü
     */
    public static function isSeptemberPromotion() {
        $currentMonth = (int)date('n');
        return ($currentMonth === 9);
    }
    
    /**
     * Paket fiyatını hesapla
     */
    public static function calculatePackagePrice($months) {
        $monthlyPrice = 250.00;
        return $monthlyPrice * $months;
    }
    
    /**
     * Yeni abonelik oluştur (Güçlendirilmiş - Gerçek Hayat Senaryoları İçin)
     */
    public function createSubscription($paymentId, $paymentStatus = 'pending', $months = 1, $amount = null, $tier = 'standard') {
        try {
            // 1. Rate Limiting Kontrolü
            $ip_address = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $rate_limit_key = "subscription_{$this->communityId}";
            $current_hour = date('Y-m-d H:00:00');
            
            $rate_check = $this->db->prepare("SELECT action_count FROM subscription_rate_limits WHERE community_id = ? AND action_type = ? AND hour_timestamp = ?");
            $rate_check->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $rate_check->bindValue(2, $rate_limit_key, \SQLITE3_TEXT);
            $rate_check->bindValue(3, $current_hour, \SQLITE3_TEXT);
            $rate_result = $rate_check->execute();
            $rate_row = $rate_result->fetchArray(\SQLITE3_ASSOC);
            $attempt_count = $rate_row ? (int)$rate_row['action_count'] : 0;
            
            // Maksimum 5 abonelik denemesi/saat
            if ($attempt_count >= 5) {
                $this->logSubscriptionAction(null, 'rate_limit_exceeded', "Rate limit aşıldı: {$rate_limit_key}", ['attempts' => $attempt_count]);
                throw new \Exception('Çok fazla abonelik denemesi! Lütfen 1 saat sonra tekrar deneyin.');
            }
            
            // 2. Payment ID Tekrarı Kontrolü (Çift Ödeme Koruması) - Güvenlik
            if (!empty($paymentId)) {
                $check_stmt = $this->db->prepare("SELECT id, payment_status, tier FROM subscriptions WHERE payment_id = ? AND community_id = ?");
                $check_stmt->bindValue(1, $paymentId, \SQLITE3_TEXT);
                $check_stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
                $check_result = $check_stmt->execute();
                $existing = $check_result->fetchArray(\SQLITE3_ASSOC);
                
                if ($existing) {
                    if ($existing['payment_status'] === 'success') {
                        $this->logSubscriptionAction($existing['id'], 'duplicate_subscription_attempt', "Çift abonelik denemesi: {$paymentId}", [
                            'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown',
                            'user_agent' => $_SERVER['HTTP_USER_AGENT'] ?? 'unknown'
                        ]);
                        throw new \Exception('Bu ödeme zaten kaydedilmiş! Aboneliğiniz zaten aktif.', $existing['id']);
                    } else {
                        // Pending abonelik varsa, onu güncelle
                        return $this->updateSubscription($existing['id'], $paymentId, $paymentStatus);
                    }
                }
            }
            
            // 3. Tutar Validasyonu - Gerçek hayat senaryosu
            if ($amount !== null && $amount < 0) {
                throw new \Exception('Geçerli bir tutar giriniz!');
            }
            if ($amount !== null && $amount > 100000) {
                throw new \Exception('Maksimum ödeme tutarı 100.000 TL\'dir.');
            }
            
            // Tier ve amount uyumluluğu kontrolü
            if ($tier === 'professional' && $amount > 0) {
                // Professional: 250 TL/ay (1 ay: 250, 6 ay: 1425, 12 ay: 2700)
                $expected_min = 250 * $months * 0.9; // %10 indirim toleransı
                $expected_max = 250 * $months * 1.1; // %10 fazla toleransı
                if ($amount < $expected_min || $amount > $expected_max) {
                    error_log("Professional package price mismatch: Expected ~" . (250 * $months) . " TL, Got: {$amount} TL");
                    // Uyarı ver ama engelleme yok (promosyonlar olabilir)
                }
            } elseif ($tier === 'business' && $amount > 0) {
                // Business: 500 TL/ay (1 ay: 500, 6 ay: 2850, 12 ay: 5400)
                $expected_min = 500 * $months * 0.9;
                $expected_max = 500 * $months * 1.1;
                if ($amount < $expected_min || $amount > $expected_max) {
                    error_log("Business package price mismatch: Expected ~" . (500 * $months) . " TL, Got: {$amount} TL");
                    // Uyarı ver ama engelleme yok
                }
            }
            
            // 4. Payment Token Oluştur (Güvenlik için) - Önce token oluştur, sonra kontrol et
            $payment_token = bin2hex(random_bytes(16));
            
            // 4.5. Payment Token Tekrarı Kontrolü (Ek Güvenlik) - Token oluşturulduktan sonra kontrol et
            $token_check_stmt = $this->db->prepare("SELECT id FROM subscriptions WHERE payment_token = ? AND community_id = ? LIMIT 1");
            $token_check_stmt->bindValue(1, $payment_token, \SQLITE3_TEXT);
            $token_check_stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $token_check_result = $token_check_stmt->execute();
            $existing_token = $token_check_result->fetchArray(\SQLITE3_ASSOC);
            
            // Eğer token çakışırsa (çok nadir), yeni token oluştur
            $max_retries = 5;
            $retry_count = 0;
            while ($existing_token && $retry_count < $max_retries) {
                $payment_token = bin2hex(random_bytes(16));
                $token_check_stmt->bindValue(1, $payment_token, \SQLITE3_TEXT);
                $token_check_result = $token_check_stmt->execute();
                $existing_token = $token_check_result->fetchArray(\SQLITE3_ASSOC);
                $retry_count++;
            }
            
            if ($existing_token) {
                $this->logSubscriptionAction(null, 'duplicate_token_attempt', "Token çakışması: {$payment_token} (5 deneme sonrası)", [
                    'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                ]);
                throw new \Exception('Güvenlik hatası: Ödeme token oluşturulamadı!');
            }
            
            // 5. Expiry Time (30 dakika - pending ödemeler için)
            $expires_at = null;
            if ($paymentStatus === 'pending') {
                $expires_at = date('Y-m-d H:i:s', time() + 1800); // 30 dakika
            }
            
            // 6. Session ve IP Bilgileri
            $session_id = session_id();
            $user_agent = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            
            $startDate = date('Y-m-d H:i:s');
            
            // Standart sürüm sınırsız - Gerçek hayat senaryosu: Standart her zaman aktif
            if ($tier === 'standard' || $amount == 0) {
                $endDate = date('Y-m-d H:i:s', strtotime('+100 years'));
                $amount = 0;
                $paymentStatus = 'success';
                $expires_at = null; // Standart sürüm için expiry yok
                $tier = 'standard'; // Zorla standart tier
            } else {
                // Profesyonel veya Business için normal süre hesapla
                $endDate = date('Y-m-d H:i:s', strtotime("+{$months} months"));
                
                // Tier validasyonu - Sadece professional veya business olabilir
                if (!in_array($tier, ['professional', 'business'])) {
                    throw new \Exception('Geçersiz paket seçimi! Sadece Professional veya Business paketleri satın alınabilir.');
                }
            }
            
            if ($amount === null) {
                $amount = self::calculatePackagePrice($months);
            }
            
            // 7. Abonelik Kaydı Oluştur
            $stmt = $this->db->prepare("
                INSERT INTO subscriptions 
                (community_id, payment_id, payment_token, payment_status, amount, tier, months, start_date, end_date, is_active, session_id, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(2, $paymentId, \SQLITE3_TEXT);
            $stmt->bindValue(3, $payment_token, \SQLITE3_TEXT);
            $stmt->bindValue(4, $paymentStatus, \SQLITE3_TEXT);
            $stmt->bindValue(5, $amount, \SQLITE3_FLOAT);
            $stmt->bindValue(6, $tier, \SQLITE3_TEXT);
            $stmt->bindValue(7, $months, \SQLITE3_INTEGER);
            $stmt->bindValue(8, $startDate, \SQLITE3_TEXT);
            $stmt->bindValue(9, $endDate, \SQLITE3_TEXT);
            $stmt->bindValue(10, $paymentStatus === 'success' ? 1 : 0, \SQLITE3_INTEGER);
            $stmt->bindValue(11, $session_id, \SQLITE3_TEXT);
            $stmt->bindValue(12, $ip_address, \SQLITE3_TEXT);
            $stmt->bindValue(13, $user_agent, \SQLITE3_TEXT);
            $stmt->bindValue(14, $expires_at, \SQLITE3_TEXT);
            
            $stmt->execute();
            $subscription_id = $this->db->lastInsertRowID();
            
            // 8. Rate Limit Sayacını Artır
            if ($rate_row) {
                $update_rate = $this->db->prepare("UPDATE subscription_rate_limits SET action_count = action_count + 1 WHERE community_id = ? AND action_type = ? AND hour_timestamp = ?");
                $update_rate->bindValue(1, $this->communityId, \SQLITE3_TEXT);
                $update_rate->bindValue(2, $rate_limit_key, \SQLITE3_TEXT);
                $update_rate->bindValue(3, $current_hour, \SQLITE3_TEXT);
                $update_rate->execute();
            } else {
                $insert_rate = $this->db->prepare("INSERT INTO subscription_rate_limits (community_id, ip_address, action_type, action_count, hour_timestamp) VALUES (?, ?, ?, 1, ?)");
                $insert_rate->bindValue(1, $this->communityId, \SQLITE3_TEXT);
                $insert_rate->bindValue(2, $ip_address, \SQLITE3_TEXT);
                $insert_rate->bindValue(3, $rate_limit_key, \SQLITE3_TEXT);
                $insert_rate->bindValue(4, $current_hour, \SQLITE3_TEXT);
                $insert_rate->execute();
            }
            
            // 9. Log Kaydı
            $this->logSubscriptionAction($subscription_id, 'subscription_created', 'Abonelik kaydı oluşturuldu', [
                'payment_id' => $paymentId,
                'tier' => $tier,
                'months' => $months,
                'amount' => $amount
            ]);
            
            return $subscription_id;
            
        } catch (\Exception $e) {
            error_log("Subscription creation error: " . $e->getMessage());
            $this->logSubscriptionAction(null, 'subscription_error', "Abonelik oluşturma hatası: " . $e->getMessage(), []);
            throw $e;
        }
    }
    
    /**
     * Aboneliği güncelle (Güçlendirilmiş - Güvenlik ve Gerçek Hayat Senaryoları)
     */
    public function updateSubscription($subscriptionId, $paymentId, $paymentStatus) {
        try {
            // Mevcut aboneliği kontrol et
            $check_stmt = $this->db->prepare("SELECT * FROM subscriptions WHERE id = ? AND community_id = ?");
            $check_stmt->bindValue(1, $subscriptionId, \SQLITE3_INTEGER);
            $check_stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $check_result = $check_stmt->execute();
            $existing = $check_result->fetchArray(\SQLITE3_ASSOC);
            
            if (!$existing) {
                throw new \Exception('Abonelik kaydı bulunamadı');
            }
            
            // Standart abonelik güncelleme koruması - Standart abonelik değiştirilemez
            if ($existing['tier'] === 'standard' && $paymentStatus !== 'success') {
                // Standart abonelik her zaman success olmalı
                $paymentStatus = 'success';
            }
            
            // Expiry kontrolü
            if ($existing['expires_at'] && strtotime($existing['expires_at']) < time() && $existing['payment_status'] === 'pending') {
                // Expired abonelikleri otomatik iptal et
                $expired_stmt = $this->db->prepare("UPDATE subscriptions SET payment_status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $expired_stmt->bindValue(1, $subscriptionId, \SQLITE3_INTEGER);
                $expired_stmt->execute();
                $this->logSubscriptionAction($subscriptionId, 'subscription_expired', 'Abonelik süresi doldu', $existing);
                throw new \Exception('Abonelik süresi dolmuş');
            }
            
            // Çift ödeme koruması - Zaten başarılıysa tekrar işleme
            if ($existing['payment_status'] === 'success' && $paymentStatus === 'success') {
                // Aynı payment_id ile tekrar güncelleme denemesi
                if ($existing['payment_id'] === $paymentId) {
                    $this->logSubscriptionAction($subscriptionId, 'duplicate_update_attempt', "Çift güncelleme denemesi: {$paymentId}", [
                        'ip' => $_SERVER['REMOTE_ADDR'] ?? 'unknown'
                    ]);
                    // Hata fırlatma, sadece log kaydet
                    return $subscriptionId; // Mevcut aboneliği döndür
                }
            }
            
            // Session ve IP kontrolü - Güvenlik
            $current_session = session_id();
            $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            
            // Session hijacking kontrolü (eğer session_id kaydedilmişse)
            if (!empty($existing['session_id']) && $existing['session_id'] !== $current_session) {
                // Farklı session'dan güncelleme denemesi - uyarı ver ama engelleme yok (callback'ler farklı session olabilir)
                error_log("Subscription update from different session: Original: {$existing['session_id']}, Current: {$current_session}");
            }
            
            $isActive = $paymentStatus === 'success' ? 1 : 0;
            $verified_at = ($paymentStatus === 'success' && !$existing['verified_at']) ? date('Y-m-d H:i:s') : $existing['verified_at'];
            
            $stmt = $this->db->prepare("
                UPDATE subscriptions 
                SET payment_id = ?, 
                    payment_status = ?, 
                    is_active = ?,
                    verified_at = ?,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND community_id = ?
            ");
            $stmt->bindValue(1, $paymentId, \SQLITE3_TEXT);
            $stmt->bindValue(2, $paymentStatus, \SQLITE3_TEXT);
            $stmt->bindValue(3, $isActive, \SQLITE3_INTEGER);
            $stmt->bindValue(4, $verified_at, \SQLITE3_TEXT);
            $stmt->bindValue(5, $subscriptionId, \SQLITE3_INTEGER);
            $stmt->bindValue(6, $this->communityId, \SQLITE3_TEXT);
            
            $update_result = $stmt->execute();
            
            if (!$update_result) {
                throw new \Exception('Abonelik güncellenemedi: ' . $this->db->lastErrorMsg());
            }
            
            // Güncelleme başarılı mı kontrol et
            $verify_stmt = $this->db->prepare("SELECT payment_status, is_active FROM subscriptions WHERE id = ? AND community_id = ?");
            $verify_stmt->bindValue(1, $subscriptionId, \SQLITE3_INTEGER);
            $verify_stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $verify_result = $verify_stmt->execute();
            $updated = $verify_result->fetchArray(\SQLITE3_ASSOC);
            
            if (!$updated || $updated['payment_status'] !== $paymentStatus) {
                throw new \Exception('Abonelik güncelleme doğrulama hatası');
            }
            
            // Log kaydı
            $this->logSubscriptionAction($subscriptionId, 'subscription_updated', "Abonelik güncellendi: {$paymentStatus}", [
                'payment_id' => $paymentId,
                'old_status' => $existing['payment_status'],
                'new_status' => $paymentStatus,
                'tier' => $existing['tier'] ?? 'unknown',
                'ip' => $current_ip
            ]);
            
            // Email/SMS bildirimi gönder (eğer başarılıysa ve gönderilmediyse)
            if ($paymentStatus === 'success' && !$existing['notification_sent']) {
                $this->sendSubscriptionNotification($subscriptionId);
            }
            
            // Business paket kontrolü - NetGSM entegrasyonunu otomatik yap (sessizce)
            if ($paymentStatus === 'success' && strtolower($existing['tier'] ?? '') === 'business') {
                $this->autoIntegrateNetGSM();
            }
            
            return $subscriptionId;
            
        } catch (\Exception $e) {
            error_log("Subscription update error: " . $e->getMessage());
            $this->logSubscriptionAction($subscriptionId, 'subscription_update_error', "Abonelik güncelleme hatası: " . $e->getMessage(), [
                'payment_id' => $paymentId,
                'payment_status' => $paymentStatus
            ]);
            throw $e;
        }
    }
    
    /**
     * Plan değişikliği yap (Superadmin tarafından)
     * Tier, months ve amount'u günceller, yeni başlangıç tarihi belirler
     */
    public function updateSubscriptionPlan($subscriptionId, $newTier, $months, $amount) {
        try {
            // Mevcut aboneliği kontrol et
            $check_stmt = $this->db->prepare("SELECT * FROM subscriptions WHERE id = ? AND community_id = ?");
            $check_stmt->bindValue(1, $subscriptionId, \SQLITE3_INTEGER);
            $check_stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $check_result = $check_stmt->execute();
            $existing = $check_result->fetchArray(\SQLITE3_ASSOC);
            
            if (!$existing) {
                throw new \Exception('Abonelik kaydı bulunamadı');
            }
            
            // Yeni başlangıç ve bitiş tarihlerini hesapla
            $start_date = date('Y-m-d H:i:s');
            $end_date = date('Y-m-d H:i:s', strtotime("+{$months} months"));
            
            // Payment ID oluştur (superadmin ataması için)
            $payment_id = 'SUPERADMIN-ASSIGN-' . $this->communityId . '-' . time();
            
            // Aboneliği güncelle
            $stmt = $this->db->prepare("
                UPDATE subscriptions 
                SET tier = ?,
                    months = ?,
                    amount = ?,
                    payment_id = ?,
                    payment_status = 'success',
                    is_active = 1,
                    start_date = ?,
                    end_date = ?,
                    verified_at = CURRENT_TIMESTAMP,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = ? AND community_id = ?
            ");
            $stmt->bindValue(1, $newTier, \SQLITE3_TEXT);
            $stmt->bindValue(2, $months, \SQLITE3_INTEGER);
            $stmt->bindValue(3, $amount, \SQLITE3_REAL);
            $stmt->bindValue(4, $payment_id, \SQLITE3_TEXT);
            $stmt->bindValue(5, $start_date, \SQLITE3_TEXT);
            $stmt->bindValue(6, $end_date, \SQLITE3_TEXT);
            $stmt->bindValue(7, $subscriptionId, \SQLITE3_INTEGER);
            $stmt->bindValue(8, $this->communityId, \SQLITE3_TEXT);
            
            $update_result = $stmt->execute();
            
            if (!$update_result) {
                throw new \Exception('Plan güncellenemedi: ' . $this->db->lastErrorMsg());
            }
            
            // Log kaydı
            $this->logSubscriptionAction($subscriptionId, 'plan_updated', "Plan değiştirildi: {$existing['tier']} -> {$newTier}", [
                'old_tier' => $existing['tier'],
                'new_tier' => $newTier,
                'old_months' => $existing['months'],
                'new_months' => $months,
                'old_amount' => $existing['amount'],
                'new_amount' => $amount,
                'updated_by' => 'superadmin'
            ]);
            
            // Business paket kontrolü - NetGSM entegrasyonunu otomatik yap
            if (strtolower($newTier) === 'business') {
                $this->autoIntegrateNetGSM();
            }
            
            return $subscriptionId;
            
        } catch (\Exception $e) {
            error_log("Plan update error: " . $e->getMessage());
            $this->logSubscriptionAction($subscriptionId, 'plan_update_error', "Plan güncelleme hatası: " . $e->getMessage(), []);
            throw $e;
        }
    }
    
    /**
     * Abonelik Doğrulama (Payment ID ile)
     */
    public function verifySubscription($payment_id, $payment_token = null) {
        try {
            $sql = "SELECT * FROM subscriptions WHERE payment_id = ? AND community_id = ?";
            $params = [$payment_id, $this->communityId];
            
            if ($payment_token) {
                $sql .= " AND payment_token = ?";
                $params[] = $payment_token;
            }
            
            $stmt = $this->db->prepare($sql);
            for ($i = 0; $i < count($params); $i++) {
                $stmt->bindValue($i + 1, $params[$i], \SQLITE3_TEXT);
            }
            $result = $stmt->execute();
            $subscription = $result->fetchArray(\SQLITE3_ASSOC);
            
            if (!$subscription) {
                return ['success' => false, 'message' => 'Abonelik kaydı bulunamadı'];
            }
            
            // Expiry kontrolü
            if ($subscription['expires_at'] && strtotime($subscription['expires_at']) < time() && $subscription['payment_status'] === 'pending') {
                // Expired abonelikleri otomatik iptal et
                $update_stmt = $this->db->prepare("UPDATE subscriptions SET payment_status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE id = ?");
                $update_stmt->bindValue(1, $subscription['id'], \SQLITE3_INTEGER);
                $update_stmt->execute();
                $this->logSubscriptionAction($subscription['id'], 'subscription_expired', 'Abonelik süresi doldu', $subscription);
                return ['success' => false, 'message' => 'Abonelik süresi dolmuş', 'subscription' => $subscription];
            }
            
            return ['success' => true, 'subscription' => $subscription];
        } catch (\Exception $e) {
            error_log("Subscription verification error: " . $e->getMessage());
            return ['success' => false, 'message' => 'Abonelik doğrulama hatası: ' . $e->getMessage()];
        }
    }
    
    /**
     * Abonelik Loglama
     */
    private function logSubscriptionAction($subscription_id, $log_type, $log_message, $log_data = []) {
        try {
            $stmt = $this->db->prepare("INSERT INTO subscription_logs (subscription_id, community_id, log_type, log_message, log_data, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?)");
            $stmt->bindValue(1, $subscription_id, \SQLITE3_INTEGER);
            $stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(3, $log_type, \SQLITE3_TEXT);
            $stmt->bindValue(4, $log_message, \SQLITE3_TEXT);
            $stmt->bindValue(5, json_encode($log_data), \SQLITE3_TEXT);
            $stmt->bindValue(6, $_SERVER['REMOTE_ADDR'] ?? 'unknown', \SQLITE3_TEXT);
            $stmt->bindValue(7, $_SERVER['HTTP_USER_AGENT'] ?? 'unknown', \SQLITE3_TEXT);
            $stmt->execute();
        } catch (\Exception $e) {
            error_log("Subscription log error: " . $e->getMessage());
        }
    }
    
    /**
     * Süresi Dolmuş Abonelikleri Temizle
     */
    public function cleanupExpiredSubscriptions() {
        try {
            $stmt = $this->db->prepare("UPDATE subscriptions SET payment_status = 'expired', updated_at = CURRENT_TIMESTAMP WHERE payment_status = 'pending' AND expires_at IS NOT NULL AND expires_at < datetime('now') AND community_id = ?");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->execute();
            
            $expired_count = $this->db->changes();
            
            if ($expired_count > 0) {
                $this->logSubscriptionAction(null, 'cleanup_expired', "{$expired_count} adet süresi dolmuş abonelik temizlendi", []);
            }
            
            return ['success' => true, 'expired_count' => $expired_count];
        } catch (\Exception $e) {
            error_log("Cleanup expired subscriptions error: " . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Abonelik Bildirimi Gönder
     */
    private function sendSubscriptionNotification($subscription_id) {
        try {
            $stmt = $this->db->prepare("SELECT * FROM subscriptions WHERE id = ? AND community_id = ?");
            $stmt->bindValue(1, $subscription_id, \SQLITE3_INTEGER);
            $stmt->bindValue(2, $this->communityId, \SQLITE3_TEXT);
            $result = $stmt->execute();
            $subscription = $result->fetchArray(\SQLITE3_ASSOC);
            
            if (!$subscription || $subscription['notification_sent']) {
                return ['success' => false, 'message' => 'Bildirim zaten gönderilmiş'];
            }
            
            // Email gönder (community admin'e)
            // Communication modülünü yükle
            if (function_exists('load_module')) {
                load_module('communication');
            }
            
            // Bildirim gönderildi olarak işaretle
            $update_stmt = $this->db->prepare("UPDATE subscriptions SET notification_sent = 1 WHERE id = ?");
            $update_stmt->bindValue(1, $subscription_id, \SQLITE3_INTEGER);
            $update_stmt->execute();
            
            $this->logSubscriptionAction($subscription_id, 'notification_sent', 'Abonelik bildirimi gönderildi', []);
            
            return ['success' => true, 'message' => 'Bildirim gönderildi'];
        } catch (\Exception $e) {
            error_log("Subscription notification error: " . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Kalan gün sayısını hesapla - Standart sürüm için sınırsız
     */
    public function getRemainingDays() {
        $subscription = $this->getSubscription();
        if (!$subscription || !$subscription['end_date']) {
            return 0;
        }
        
        // Standart sürüm sınırsız
        if (($subscription['tier'] ?? 'standard') === 'standard') {
            return 999999; // Sınırsız gösterimi için çok büyük sayı
        }
        
        $endDate = new \DateTime($subscription['end_date']);
        $now = new \DateTime();
        
        if ($endDate < $now) {
            return 0;
        }
        
        $diff = $now->diff($endDate);
        return $diff->days;
    }
    
    /**
     * Abonelik durumunu kontrol et ve güncelle (Expired, Active, etc.)
     */
    public function checkAndUpdateSubscriptionStatus() {
        try {
            // Süresi dolmuş paid abonelikleri kontrol et
            $expired_stmt = $this->db->prepare("
                UPDATE subscriptions 
                SET is_active = 0, 
                    payment_status = 'expired',
                    updated_at = CURRENT_TIMESTAMP
                WHERE community_id = ? 
                AND tier IN ('professional', 'business')
                AND payment_status = 'success'
                AND is_active = 1
                AND end_date < datetime('now')
            ");
            $expired_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $expired_stmt->execute();
            $expired_count = $this->db->changes();
            
            if ($expired_count > 0) {
                $this->logSubscriptionAction(null, 'subscriptions_expired', "{$expired_count} adet abonelik süresi doldu", []);
            }
            
            // Standart aboneliği her zaman aktif yap
            $standard_stmt = $this->db->prepare("
                UPDATE subscriptions 
                SET is_active = 1, 
                    payment_status = 'success',
                    updated_at = CURRENT_TIMESTAMP
                WHERE community_id = ? 
                AND tier = 'standard'
            ");
            $standard_stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $standard_stmt->execute();
            
            return ['success' => true, 'expired_count' => $expired_count];
        } catch (\Exception $e) {
            error_log("Subscription status check error: " . $e->getMessage());
            return ['success' => false, 'message' => $e->getMessage()];
        }
    }
    
    /**
     * Paket limitlerini getir
     */
    public static function getPackageLimits($tier) {
        $limits = [
            'standard' => [
                'max_members' => -1, // Sınırsız
                'max_events_per_month' => -1, // Sınırsız
                'max_board_members' => -1, // Sınırsız
                'max_campaigns' => 3, // Kampanya limiti
                'max_products' => 2, // Market - maksimum 2 ürün
                'has_financial' => false, // Finans yönetimi yok
                'has_sms' => false, // SMS gönderimi yok
                'has_email' => true, // Mail Merkezi var (standart pakette de mevcut)
                'has_api' => false, // API erişimi yok
                'has_reports' => false, // Raporlar ve Analitik yok
                'max_storage_gb' => 1,
                'max_sms_per_month' => 0,
                'max_emails_per_month' => -1 // Sınırsız email
            ],
            'professional' => [
                'max_members' => -1, // Sınırsız
                'max_events_per_month' => -1, // Sınırsız
                'max_board_members' => -1, // Sınırsız
                'max_campaigns' => -1, // Sınırsız
                'max_products' => -1, // Sınırsız
                'has_financial' => false, // Finans yönetimi yok (sadece Business'ta)
                'has_sms' => false, // SMS gönderimi yok
                'has_email' => false, // Mail Merkezi yok (sadece Business'ta)
                'has_api' => false, // API erişimi yok
                'has_reports' => true, // Raporlar ve Analitik var
                'max_storage_gb' => 20,
                'max_sms_per_month' => 0,
                'max_emails_per_month' => -1 // Sınırsız
            ],
            'business' => [
                'max_members' => -1, // Sınırsız
                'max_events_per_month' => -1, // Sınırsız
                'max_board_members' => -1, // Sınırsız
                'max_campaigns' => -1, // Sınırsız
                'max_products' => -1, // Sınırsız
                'has_financial' => true, // Finans yönetimi var
                'has_sms' => true, // SMS gönderimi var (aylık 500 SMS hediye + ek paket)
                'has_email' => true, // Mail Merkezi var (sınırsız)
                'has_api' => false, // API erişimi yok
                'has_reports' => true, // Raporlar ve Analitik var
                'max_storage_gb' => 50,
                'max_sms_per_month' => 500, // Business plan'da standart 500 SMS hediye
                'max_emails_per_month' => -1 // Sınırsız
            ]
        ];
        
        return $limits[$tier] ?? $limits['standard'];
    }
    
    /**
     * Mevcut paket limitlerini getir
     */
    public function getCurrentLimits() {
        $currentTier = $this->getCurrentTier();
        return self::getPackageLimits($currentTier);
    }
    
    /**
     * Özellik erişim kontrolü
     */
    public function hasFeature($feature) {
        $limits = $this->getCurrentLimits();
        
        $featureMap = [
            'financial' => 'has_financial',
            'sms' => 'has_sms',
            'email' => 'has_email',
            'api' => 'has_api',
            'reports' => 'has_reports'
        ];
        
        if (isset($featureMap[$feature])) {
            return $limits[$featureMap[$feature]] ?? false;
        }
        
        return false;
    }
    
    /**
     * Limit kontrolü - Genel
     */
    public function checkLimit($limitType, $currentValue = null) {
        $limits = $this->getCurrentLimits();
        
        // Limit yoksa (sınırsız)
        if (!isset($limits[$limitType]) || $limits[$limitType] === -1) {
            return ['allowed' => true, 'limit' => -1, 'current' => $currentValue, 'remaining' => -1];
        }
        
        // Mevcut değer verilmemişse sadece limit bilgisini döndür
        if ($currentValue === null) {
            return ['allowed' => true, 'limit' => $limits[$limitType], 'current' => null, 'remaining' => $limits[$limitType]];
        }
        
        $limit = $limits[$limitType];
        $remaining = max(0, $limit - $currentValue);
        $allowed = $currentValue < $limit;
        
        return [
            'allowed' => $allowed,
            'limit' => $limit,
            'current' => $currentValue,
            'remaining' => $remaining
        ];
    }
    
    /**
     * Üye sayısı limit kontrolü
     */
    public function checkMemberLimit($currentMemberCount) {
        return $this->checkLimit('max_members', $currentMemberCount);
    }
    
    /**
     * Aylık etkinlik limit kontrolü
     */
    public function checkEventLimit($currentEventCountThisMonth) {
        return $this->checkLimit('max_events_per_month', $currentEventCountThisMonth);
    }
    
    /**
     * Yönetim kurulu limit kontrolü
     */
    public function checkBoardMemberLimit($currentBoardMemberCount) {
        return $this->checkLimit('max_board_members', $currentBoardMemberCount);
    }
    
    /**
     * Kampanya limit kontrolü
     */
    public function checkCampaignLimit($currentCampaignCount) {
        return $this->checkLimit('max_campaigns', $currentCampaignCount);
    }
    
    /**
     * Ürün limit kontrolü (Market)
     */
    public function checkProductLimit($currentProductCount) {
        return $this->checkLimit('max_products', $currentProductCount);
    }
    
    /**
     * SMS limit kontrolü
     */
    public function checkSmsLimit($currentSmsCountThisMonth) {
        $limits = $this->getCurrentLimits();
        
        // SMS özelliği yoksa
        if (!$limits['has_sms']) {
            return ['allowed' => false, 'limit' => 0, 'current' => $currentSmsCountThisMonth, 'remaining' => 0, 'message' => 'SMS gönderimi bu pakette mevcut değil. Business paketine yükseltin.'];
        }
        
        // Sınırsız SMS (eski sistem - artık kullanılmıyor, Business'ta 500 limit var)
        if ($limits['max_sms_per_month'] === -1) {
            return ['allowed' => true, 'limit' => -1, 'current' => $currentSmsCountThisMonth, 'remaining' => -1];
        }
        
        return $this->checkLimit('max_sms_per_month', $currentSmsCountThisMonth);
    }
    
    /**
     * SMS kullanımını kaydet (kaç kişiye gönderildiyse o kadar sayılır)
     */
    public function recordSmsUsage($recipientCount, $messageContent = null, $provider = null) {
        try {
            if ($recipientCount <= 0) {
                return false;
            }
            
            // Tabloyu oluştur (eğer yoksa)
            $this->createSubscriptionTable();
            
            $monthYear = date('Y-m');
            
            $stmt = $this->db->prepare("
                INSERT INTO sms_usage 
                (community_id, recipient_count, message_content, provider, month_year)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(2, $recipientCount, \SQLITE3_INTEGER);
            $stmt->bindValue(3, $messageContent, \SQLITE3_TEXT);
            $stmt->bindValue(4, $provider, \SQLITE3_TEXT);
            $stmt->bindValue(5, $monthYear, \SQLITE3_TEXT);
            
            return $stmt->execute() !== false;
        } catch (\Exception $e) {
            error_log("recordSmsUsage error: " . $e->getMessage());
            return false;
        }
    }
    
    /**
     * Bu ay kullanılan SMS sayısını getir (kaç kişiye gönderildiyse o kadar)
     */
    public function getCurrentMonthSmsUsage() {
        try {
            // Tabloyu oluştur (eğer yoksa)
            $this->createSubscriptionTable();
            
            $monthYear = date('Y-m');
            
            $stmt = $this->db->prepare("
                SELECT SUM(recipient_count) as total_usage
                FROM sms_usage
                WHERE community_id = ? AND month_year = ?
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(2, $monthYear, \SQLITE3_TEXT);
            
            $result = $stmt->execute();
            if (!$result) {
                return 0;
            }
            
            $row = $result->fetchArray(\SQLITE3_ASSOC);
            
            return (int)($row['total_usage'] ?? 0);
        } catch (\Exception $e) {
            error_log("getCurrentMonthSmsUsage error: " . $e->getMessage());
            return 0;
        }
    }
    
    /**
     * Topluluğa SMS kredisi tanımlar (superadmin işlemleri için)
     */
    public function addSmsCredits(int $credits, ?string $packageName = null, string $assignedBy = 'superadmin', ?string $notes = null): bool {
        if ($credits <= 0) {
            return false;
        }

        try {
            $this->createSubscriptionTable();

            $stmt = $this->db->prepare("
                INSERT INTO sms_credits (community_id, credits, package_name, assigned_by, notes)
                VALUES (?, ?, ?, ?, ?)
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $stmt->bindValue(2, $credits, \SQLITE3_INTEGER);
            $stmt->bindValue(3, $packageName, \SQLITE3_TEXT);
            $stmt->bindValue(4, $assignedBy, \SQLITE3_TEXT);
            $stmt->bindValue(5, $notes, \SQLITE3_TEXT);

            return $stmt->execute() !== false;
        } catch (\Exception $e) {
            error_log("addSmsCredits error: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Kullanılabilir SMS kredilerinin toplamını döndürür
     */
    public function getTotalSmsCredits(): int {
        try {
            $this->createSubscriptionTable();

            $stmt = $this->db->prepare("
                SELECT SUM(credits) as total_credits
                FROM sms_credits
                WHERE community_id = ?
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(\SQLITE3_ASSOC);

            return (int)($row['total_credits'] ?? 0);
        } catch (\Exception $e) {
            error_log("getTotalSmsCredits error: " . $e->getMessage());
            return 0;
        }
    }

    /**
     * Tahsis edilen SMS kredilerini kullanır.
     * Geriye karşılanamayan SMS adetini döndürür (0 ise krediler yeterliydi).
     */
    public function useSmsCredits(int $count): int {
        if ($count <= 0) {
            return 0;
        }

        $this->createSubscriptionTable();
        $remaining = $count;

        try {
            $this->db->exec('BEGIN IMMEDIATE');

            $stmt = $this->db->prepare("
                SELECT id, credits
                FROM sms_credits
                WHERE community_id = ? AND credits > 0
                ORDER BY assigned_at ASC, id ASC
            ");
            $stmt->bindValue(1, $this->communityId, \SQLITE3_TEXT);
            $result = $stmt->execute();

            while ($remaining > 0 && ($row = $result->fetchArray(\SQLITE3_ASSOC))) {
                $creditId = (int)$row['id'];
                $available = (int)$row['credits'];

                if ($available <= 0) {
                    continue;
                }

                if ($available >= $remaining) {
                    $newAmount = $available - $remaining;
                    $update = $this->db->prepare("UPDATE sms_credits SET credits = ? WHERE id = ?");
                    $update->bindValue(1, $newAmount, \SQLITE3_INTEGER);
                    $update->bindValue(2, $creditId, \SQLITE3_INTEGER);
                    $update->execute();
                    $remaining = 0;
                    break;
                }

                $update = $this->db->prepare("UPDATE sms_credits SET credits = 0 WHERE id = ?");
                $update->bindValue(1, $creditId, \SQLITE3_INTEGER);
                $update->execute();
                $remaining -= $available;
            }

            $this->db->exec('COMMIT');
        } catch (\Exception $e) {
            $this->db->exec('ROLLBACK');
            error_log("useSmsCredits error: " . $e->getMessage());
            return $count;
        }

        return $remaining;
    }
    
    /**
     * SMS gönderim öncesi limit kontrolü (kaç kişiye gönderilecekse o kadar kontrol edilir)
     */
    public function canSendSms($recipientCount) {
        try {
            if ($recipientCount <= 0) {
                return ['allowed' => false, 'message' => 'Alıcı sayısı geçersiz.'];
            }
            
            $limits = $this->getCurrentLimits();
            
            // SMS özelliği yoksa
            if (!$limits['has_sms']) {
                return ['allowed' => false, 'message' => 'SMS gönderimi bu pakette mevcut değil. Business paketine yükseltin.'];
            }
            
            // Sınırsız SMS (eski sistem - artık kullanılmıyor)
            if ($limits['max_sms_per_month'] === -1) {
                return ['allowed' => true, 'limit' => -1, 'current' => 0, 'remaining' => -1];
            }
            
            // RAPORLAR SEKMESİ İLE AYNI MANTIK: rate_limits tablosundan bu ayın SMS sayısını çek
            $db = $this->db;
            $month_start = date('Y-m-01');
            $month_end = date('Y-m-t');
            
            // rate_limits tablosunu oluştur (eğer yoksa)
            try {
                $db->exec("CREATE TABLE IF NOT EXISTS rate_limits (
                    id INTEGER PRIMARY KEY,
                    club_id INTEGER NOT NULL,
                    action_type TEXT NOT NULL,
                    action_count INTEGER DEFAULT 0,
                    hour_timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )");
            } catch (\Exception $e) {
                error_log("Rate limits table creation error: " . $e->getMessage());
            }
            
            // Bu ay gönderilen SMS sayısını hesapla (raporlar sekmesi ile aynı)
            // Her topluluk için ayrı veritabanı olduğu için club_id = 1 kullanıyoruz
            $club_id = defined('CLUB_ID') ? CLUB_ID : 1;
            $stmt = $db->prepare("SELECT SUM(action_count) as total FROM rate_limits 
                                  WHERE club_id = ? AND action_type = 'sms' 
                                  AND hour_timestamp >= ? AND hour_timestamp <= ?");
            $stmt->bindValue(1, $club_id, \SQLITE3_INTEGER);
            $stmt->bindValue(2, $month_start, \SQLITE3_TEXT);
            $stmt->bindValue(3, $month_end, \SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(\SQLITE3_ASSOC);
            $currentUsage = (int)($row['total'] ?? 0);
            
            $baseLimit = $limits['max_sms_per_month']; // Business plan için 500 SMS
            
            // Tahsis edilen SMS kredilerini ekle
            $smsCredits = $this->getTotalSmsCredits();
            $totalLimit = $baseLimit + $smsCredits; // 500 (Business) + tahsis edilen krediler
            
            $remaining = max(0, $totalLimit - $currentUsage);
            
            // Gönderilecek SMS sayısı kalan limiti aşıyorsa
            if ($recipientCount > $remaining) {
                return [
                    'allowed' => false,
                    'limit' => $totalLimit,
                    'current' => $currentUsage,
                    'remaining' => $remaining,
                    'requested' => $recipientCount,
                    'base_limit' => $baseLimit,
                    'credits' => $smsCredits,
                    'message' => "SMS limiti aşıldı. Mevcut limit: {$totalLimit} SMS/ay (500 hediye + {$smsCredits} kredi), Kullanılan: {$currentUsage} SMS, Kalan: {$remaining} SMS. Göndermek istediğiniz: {$recipientCount} SMS. Ek paket almanız gerekiyor."
                ];
            }
            
            return [
                'allowed' => true,
                'limit' => $totalLimit,
                'current' => $currentUsage,
                'remaining' => $remaining - $recipientCount,
                'requested' => $recipientCount
            ];
        } catch (\Exception $e) {
            error_log("canSendSms error: " . $e->getMessage());
            // Hata durumunda SMS gönderimine izin ver (güvenli taraf)
            return ['allowed' => true, 'limit' => -1, 'current' => 0, 'remaining' => -1, 'error' => $e->getMessage()];
        }
    }
    
    /**
     * Email limit kontrolü
     */
    public function checkEmailLimit($currentEmailCountThisMonth) {
        $limits = $this->getCurrentLimits();
        
        // Email özelliği yoksa
        if (!$limits['has_email']) {
            return ['allowed' => false, 'limit' => 0, 'current' => $currentEmailCountThisMonth, 'remaining' => 0, 'message' => 'Toplu email gönderimi bu pakette mevcut değil. Professional veya Business paketine yükseltin.'];
        }
        
        // Sınırsız email
        if ($limits['max_emails_per_month'] === -1) {
            return ['allowed' => true, 'limit' => -1, 'current' => $currentEmailCountThisMonth, 'remaining' => -1];
        }
        
        return $this->checkLimit('max_emails_per_month', $currentEmailCountThisMonth);
    }
    
    /**
     * Limit aşım mesajı oluştur
     */
    public function getLimitExceededMessage($limitType, $limitInfo) {
        $tierLabels = [
            'standard' => 'Standart',
            'professional' => 'Profesyonel',
            'business' => 'Business'
        ];
        
        $currentTier = $this->getCurrentTier();
        $tierLabel = $tierLabels[$currentTier] ?? 'Standart';
        
        $messages = [
            'max_members' => "Üye sayısı limitine ulaştınız. Maksimum {$limitInfo['limit']} üye ekleyebilirsiniz. Daha fazla üye için paket yükseltin.",
            'max_events_per_month' => "Aylık etkinlik limitine ulaştınız. Bu ay maksimum {$limitInfo['limit']} etkinlik oluşturabilirsiniz. Sınırsız etkinlik için paket yükseltin.",
            'max_board_members' => "Yönetim kurulu limitine ulaştınız. Maksimum {$limitInfo['limit']} yönetim kurulu üyesi ekleyebilirsiniz.",
            'max_campaigns' => "Kampanya özelliği {$tierLabel} pakette mevcut değil. Professional veya Business paketine yükseltin.",
            'max_products' => "Ürün sayısı limitine ulaştınız. Maksimum {$limitInfo['limit']} ürün ekleyebilirsiniz. Sınırsız ürün için paket yükseltin.",
            'has_financial' => "Finans yönetimi {$tierLabel} pakette mevcut değil. Professional veya Business paketine yükseltin.",
            'has_sms' => "SMS gönderimi {$tierLabel} pakette mevcut değil. Business paketine yükseltin.",
            'has_email' => "Toplu email gönderimi {$tierLabel} pakette mevcut değil. Professional veya Business paketine yükseltin.",
            'has_api' => "API erişimi şu anda hiçbir pakette sunulmuyor."
        ];
        
        return $messages[$limitType] ?? 'Limit aşıldı. Lütfen paket yükseltin.';
    }
    
    /**
     * Business paket alındığında NetGSM entegrasyonunu otomatik yap
     * Uyarı göstermez, sessizce entegre eder
     */
    public function autoIntegrateNetGSM() {
        try {
            // Superadmin config'den NetGSM bilgilerini al
            $superadminConfigPath = __DIR__ . '/../../superadmin/config.php';
            if (!file_exists($superadminConfigPath)) {
                return; // Config yoksa sessizce çık
            }
            
            $superadminConfig = require $superadminConfigPath;
            $netgsmConfig = $superadminConfig['netgsm'] ?? [];
            
            if (empty($netgsmConfig['user']) || empty($netgsmConfig['pass'])) {
                return; // NetGSM bilgileri yoksa sessizce çık
            }
            
            // NetGSM ayarlarını topluluk veritabanına kaydet
            $stmt = $this->db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
            $stmt->bindValue(1, 1, \SQLITE3_INTEGER);
            $stmt->bindValue(2, 'netgsm_username', \SQLITE3_TEXT);
            $stmt->bindValue(3, $netgsmConfig['user'], \SQLITE3_TEXT);
            $stmt->execute();
            
            $stmt = $this->db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
            $stmt->bindValue(1, 1, \SQLITE3_INTEGER);
            $stmt->bindValue(2, 'netgsm_password', \SQLITE3_TEXT);
            $stmt->bindValue(3, $netgsmConfig['pass'], \SQLITE3_TEXT);
            $stmt->execute();
            
            if (!empty($netgsmConfig['header'])) {
                $stmt = $this->db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
                $stmt->bindValue(1, 1, \SQLITE3_INTEGER);
                $stmt->bindValue(2, 'netgsm_header', \SQLITE3_TEXT);
                $stmt->bindValue(3, $netgsmConfig['header'], \SQLITE3_TEXT);
                $stmt->execute();
            }
            
            // NetGSM entegrasyonu aktif olarak işaretle
            $stmt = $this->db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
            $stmt->bindValue(1, 1, \SQLITE3_INTEGER);
            $stmt->bindValue(2, 'netgsm_enabled', \SQLITE3_TEXT);
            $stmt->bindValue(3, '1', \SQLITE3_TEXT);
            $stmt->execute();
            
        } catch (\Exception $e) {
            // NetGSM entegrasyonu hatası kritik değil, sessizce logla
            error_log("NetGSM auto-integration failed for Business package (Community: {$this->communityId}): " . $e->getMessage());
        }
    }
}

