<?php

if (!function_exists('tpl_validate_string')) {
    require_once __DIR__ . '/validation.php';
}
/**
 * Events Module - Lazy Loaded
 * Event yönetimi ile ilgili tüm fonksiyonlar
 */

// Import namespace'leri
use UniPanel\Core\Database;
use UniPanel\Core\ErrorHandler;
use UniPanel\Models\Event;

require_once __DIR__ . '/../partials/superadmin_guard.php';

function get_event_survey($event_id) {
    try {
        $db = get_db();
        // Anket bilgisini çek
        $survey_stmt = $db->prepare("SELECT * FROM event_surveys WHERE event_id = ? AND club_id = ? LIMIT 1");
        $survey_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
        $survey_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $survey_result = $survey_stmt->execute();
        $survey = $survey_result->fetchArray(SQLITE3_ASSOC);
        
        if (!$survey) {
            return null;
        }
        
        // Soruları çek
        $questions_stmt = $db->prepare("SELECT * FROM survey_questions WHERE survey_id = ? ORDER BY display_order ASC");
        $questions_stmt->bindValue(1, $survey['id'], SQLITE3_INTEGER);
        $questions_result = $questions_stmt->execute();
        $questions = [];
        
        while ($question = $questions_result->fetchArray(SQLITE3_ASSOC)) {
            // Her soru için seçenekleri çek
            $options_stmt = $db->prepare("SELECT * FROM survey_options WHERE question_id = ? ORDER BY display_order ASC");
            $options_stmt->bindValue(1, $question['id'], SQLITE3_INTEGER);
            $options_result = $options_stmt->execute();
            $options = [];
            
            while ($option = $options_result->fetchArray(SQLITE3_ASSOC)) {
                $options[] = $option;
            }
            
            $question['options'] = $options;
            $questions[] = $question;
        }
        
        $survey['questions'] = $questions;
        return $survey;
    } catch (Exception $e) {
        tpl_error_log("Anket çekme hatası: " . $e->getMessage());
        return null;
    }
}


function get_survey_results($db, $survey_id) {
    try {
        $results = [];
        
        // Anketi al
        $survey_stmt = $db->prepare("SELECT * FROM event_surveys WHERE id = ?");
        $survey_stmt->bindValue(1, $survey_id, SQLITE3_INTEGER);
        $survey_result = $survey_stmt->execute();
        $survey = $survey_result->fetchArray(SQLITE3_ASSOC);
        
        if (!$survey) {
            return null;
        }
        
        $results['survey'] = $survey;
        $results['questions'] = [];
        
        // Her soru için sonuçları al
        $questions_stmt = $db->prepare("SELECT * FROM survey_questions WHERE survey_id = ? ORDER BY display_order ASC");
        $questions_stmt->bindValue(1, $survey_id, SQLITE3_INTEGER);
        $questions_result = $questions_stmt->execute();
        
        while ($question = $questions_result->fetchArray(SQLITE3_ASSOC)) {
            $question_data = $question;
            $question_data['options'] = [];
            $question_data['total_responses'] = 0;
            
            // Seçenekleri ve cevap sayılarını al
            $options_stmt = $db->prepare("SELECT so.*, COUNT(sr.id) as response_count 
                FROM survey_options so
                LEFT JOIN survey_responses sr ON sr.option_id = so.id
                WHERE so.question_id = ?
                GROUP BY so.id
                ORDER BY so.display_order ASC");
            $options_stmt->bindValue(1, $question['id'], SQLITE3_INTEGER);
            $options_result = $options_stmt->execute();
            
            while ($option = $options_result->fetchArray(SQLITE3_ASSOC)) {
                $question_data['options'][] = $option;
                $question_data['total_responses'] += (int)$option['response_count'];
            }
            
            $results['questions'][] = $question_data;
        }
        
        // Toplam katılımcı sayısı
        $total_stmt = $db->prepare("SELECT COUNT(DISTINCT response_text) as total FROM survey_responses WHERE survey_id = ?");
        $total_stmt->bindValue(1, $survey_id, SQLITE3_INTEGER);
        $total_result = $total_stmt->execute();
        $total_row = $total_result->fetchArray(SQLITE3_ASSOC);
        $results['total_participants'] = (int)($total_row['total'] ?? 0);
        
        return $results;
    } catch (Exception $e) {
        tpl_error_log("Survey results error: " . $e->getMessage());
        return null;
    }
}

// --- GÜVENLİK KONTROLÜ (ZORUNLU GİRİŞ) ---

// Otomatik login kontrolü (DB_PATH artık tanımlı, get_db'ye gerek yok)
if (isset($_GET['auto_login']) && !isset($_SESSION['admin_id'])) {
    $token = $_GET['auto_login'];
    $decoded = base64_decode($token);
    $parts = explode(':', $decoded);
    
    if (count($parts) === 3) {
        list($community, $username, $timestamp) = $parts;
        
        // Token 1 saat içinde oluşturulmuş mu kontrol et
        if (time() - $timestamp < 3600) {
            try {
                // DB'yi manuel bağla
                $db_path_check = DB_PATH;
                if (!file_exists($db_path_check)) {
                    // DB yoksa login'e yönlendir, DB_PATH hatası oluşmaz
                    header("Location: login.php");
                    exit;
                }
                
                $db = new SQLite3($db_path_check);
                $db->enableExceptions(true);

                $stmt = $db->prepare("SELECT id, password_hash FROM admins WHERE username = ? AND club_id = 1");
                $stmt->bindValue(1, $username, SQLITE3_TEXT);
                $result = $stmt->execute();
                $admin = $result->fetchArray(SQLITE3_ASSOC);
                
                $db->close();

                if ($admin) {
                    // Otomatik giriş yap
                    $_SESSION['admin_id'] = $admin['id'];
                    $_SESSION['club_id'] = 1;
                    header("Location: index.php");
                    exit;
                }
            } catch (Exception $e) {
                // Hata durumunda (örn. admins tablosu yoksa) normal login'e yönlendir
            }
        }
    }
    
    // Otomatik login başarısız, normal login'e yönlendir
    header("Location: login.php");
    exit;
}

// Topluluk durumu kontrolü
if (isset($_SESSION['admin_id'])) {
    try {
        $db = get_db();
        $status = null;
        try {
            // Önce settings tablosunun var olup olmadığını kontrol et
            $table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='settings'");
            if ($table_check && $table_check->fetchArray()) {
                $status_stmt = @$db->prepare("SELECT setting_value FROM settings WHERE setting_key = 'status'");
                if ($status_stmt) {
                    $status_result = $status_stmt->execute();
                    if ($status_result) {
                        $status_row = $status_result->fetchArray(SQLITE3_ASSOC);
                        $status = $status_row ? $status_row['setting_value'] : null;
                    }
                }
            }
        } catch (Exception $e) {
            // Settings tablosu yoksa veya hata varsa null kullan
            $status = null;
        }
        if ($status === 'disabled') {
            // Topluluk kapatılmış, oturumu sil ve login sayfasına yönlendir
            session_unset();
            session_destroy();
            header("Location: login.php?error=disabled");
            exit;
        }
    } catch (Exception $e) {
        // Hata durumunda devam et
    }
}

// Eğer oturum açılmamışsa, kullanıcıyı login sayfasına yönlendir.
if (!isset($_SESSION['admin_id'])) {
    header("Location: login.php");
    exit;
}

// --- KİMLİK DOĞRULAMA & YÖNETİM İŞLEVLERİ (Devamı) ---

/**
 * Yönetici çıkış işlemini gerçekleştirir.
 */

function get_events() {
    $cache = get_cache();
    
    // Cache key'ini topluluk bazlı yap (DB_PATH'den hash oluştur)
    $cache_key = 'events_list_' . md5(DB_PATH);
    
    // Try to get from cache (10 minutes TTL)
    return $cache->remember($cache_key, 600, function() {
    try {
        $database = Database::getInstance(DB_PATH);
        $eventModel = new Event($database->getDb(), CLUB_ID);
        return $eventModel->getAll();
    } catch (\Exception $e) {
        ErrorHandler::error("Etkinlikler getirilemedi: " . $e->getMessage(), 500);
        return [];
    }
    });
}


function get_event_by_id($id) {
    try {
        $database = Database::getInstance(DB_PATH);
        $db = $database->getDb();
        
        // Events tablosuna eksik kolonları ekle
        ensure_events_table_columns($db);
        
        $eventModel = new Event($db, CLUB_ID);
        return $eventModel->getById($id);
    } catch (\Exception $e) {
        ErrorHandler::error("Etkinlik getirilemedi: " . $e->getMessage(), 500);
        return null;
    }
}


function handle_file_upload($file, $subfolder, $allowed_extensions, $max_size) {
    try {
        // Klasör oluştur
        $upload_dir = community_path('assets/' . $subfolder);
        if (!is_dir($upload_dir)) {
            mkdir($upload_dir, 0755, true);
            // Güvenlik: Klasör izinleri 0755 (rwxr-xr-x)
            chmod($upload_dir, 0755);
        }
        
        // Klasör yazılabilir mi kontrol et
        if (!is_writable($upload_dir)) {
            // Güvenlik: 0755 izni yeterli olmalı, eğer yazılamıyorsa owner problemi var
            chmod($upload_dir, 0755);
        }
        
        // Dosya bilgilerini al
        $file_extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));
        $file_size = $file['size'];
        
        // GÜVENLİK: Uzantı kontrolü
        if (!in_array($file_extension, $allowed_extensions)) {
            throw new Exception('Geçersiz dosya uzantısı. İzin verilen: ' . implode(', ', $allowed_extensions));
        }
        
        // GÜVENLİK: Gerçek boyut kontrolü (kullanıcı manipüle edemez)
        if (!file_exists($file['tmp_name'])) {
            throw new Exception('Geçici dosya bulunamadı');
        }
        $real_size = filesize($file['tmp_name']);
        if ($real_size > $max_size) {
            throw new Exception('Dosya boyutu çok büyük. Maksimum: ' . round($max_size / (1024 * 1024), 1) . 'MB');
        }
        
        // GÜVENLİK: MIME type kontrolü - Gerçek dosya tipini kontrol et
        $finfo = finfo_open(FILEINFO_MIME_TYPE);
        $mime_type = finfo_file($finfo, $file['tmp_name']);
        finfo_close($finfo);
        
        // İzin verilen MIME type'lar
        $image_mimes = ['image/jpeg', 'image/png', 'image/gif', 'image/webp'];
        $video_mimes = ['video/mp4', 'video/quicktime', 'video/x-msvideo', 'video/x-ms-wmv'];
        $allowed_mimes = array_merge($image_mimes, $video_mimes);
        
        if (!in_array($mime_type, $allowed_mimes)) {
            tpl_error_log("MIME type güvenlik hatası: $mime_type (dosya: {$file['name']})");
            throw new Exception('Geçersiz dosya tipi. Sadece resim ve video dosyaları yüklenebilir.');
        }
        
        // GÜVENLİK: Resim dosyası ise ek kontrol (PHP dosyası maskeli gelmesini engelle)
        if (in_array($file_extension, ['jpg', 'jpeg', 'png', 'gif', 'webp'])) {
            $image_info = @getimagesize($file['tmp_name']);
            if ($image_info === false) {
                throw new Exception('Dosya geçerli bir resim dosyası değil');
            }
            // MIME type ile uzantı uyumu
            $extension_mime_map = [
                'jpg' => 'image/jpeg',
                'jpeg' => 'image/jpeg',
                'png' => 'image/png',
                'gif' => 'image/gif',
                'webp' => 'image/webp'
            ];
            if (isset($extension_mime_map[$file_extension]) && $mime_type !== $extension_mime_map[$file_extension]) {
                throw new Exception('Dosya uzantısı ve içeriği uyuşmuyor (güvenlik ihlali)');
            }
        }
        
        // GÜVENLİK: Dosya adını temizle (sadece alfanumerik)
        $safe_filename = preg_replace('/[^a-zA-Z0-9_-]/', '', pathinfo($file['name'], PATHINFO_FILENAME));
        $filename = ($safe_filename ?: 'file') . '_' . uniqid() . '_' . time() . '.' . $file_extension;
        $file_path = $upload_dir . $filename;
        
        // Dosyayı taşı
        if (move_uploaded_file($file['tmp_name'], $file_path)) {
            // GÜVENLİK: Dosya izinlerini ayarla (execute iznini kaldır)
            chmod($file_path, 0644);
            return 'assets/' . $subfolder . $filename;
        } else {
            throw new Exception('Dosya yüklenirken hata oluştu');
        }
    } catch (Exception $e) {
        tpl_error_log("File upload error: " . $e->getMessage());
        $_SESSION['error'] = 'Dosya yükleme hatası: ' . $e->getMessage();
        return '';
    }
}

/**
 * events tablosuna eksik kolonları ekler
 */

function ensure_events_table_columns($db) {
    try {
        // Önce events tablosunun var olup olmadığını kontrol et
        $table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='events'");
        if (!$table_check || !$table_check->fetchArray()) {
            // Tablo yoksa fonksiyondan çık
            return;
        }
        
        // Mevcut kolonları kontrol et
        $table_info = @$db->query("PRAGMA table_info(events)");
        if (!$table_info) {
            return;
        }
        
        $columns = [];
        while ($row = $table_info->fetchArray(SQLITE3_ASSOC)) {
            $columns[] = $row['name'];
        }
        
        // Eksik kolonları ekle
        $required_columns = [
            'image_path' => 'TEXT',
            'video_path' => 'TEXT',
            'category' => 'TEXT DEFAULT "Genel"',
            'status' => 'TEXT DEFAULT "planlanıyor"',
            'priority' => 'TEXT DEFAULT "normal"',
            'capacity' => 'INTEGER',
            'registration_required' => 'INTEGER DEFAULT 0',
            'registration_deadline' => 'TEXT',
            'start_datetime' => 'TEXT',
            'end_datetime' => 'TEXT',
            'organizer' => 'TEXT',
            'contact_email' => 'TEXT',
            'contact_phone' => 'TEXT',
            'tags' => 'TEXT',
            'visibility' => 'TEXT DEFAULT "public"',
            'featured' => 'INTEGER DEFAULT 0',
            'external_link' => 'TEXT',
            'cost' => 'REAL DEFAULT 0',
            'max_attendees' => 'INTEGER',
            'min_attendees' => 'INTEGER'
        ];
        
        foreach ($required_columns as $column => $definition) {
            if (!in_array($column, $columns)) {
                try {
                    @$db->exec("ALTER TABLE events ADD COLUMN $column $definition");
                } catch (Exception $e) {
                    // Kolon zaten varsa veya eklenemezse devam et
                    tpl_error_log("Kolon eklenemedi: $column - " . $e->getMessage());
                }
            }
        }
    } catch (Exception $e) {
        tpl_error_log("Events tablosu güncellenirken hata: " . $e->getMessage());
    }
}


function add_event($db, $post) {
    try {
        // Paket limit kontrolü - Aylık etkinlik limiti
        if (!function_exists('require_subscription_feature')) {
            require_once __DIR__ . '/../../lib/general/subscription_guard.php';
        }
        
        // Bu ay oluşturulan etkinlik sayısını hesapla
        $currentCount = null;
        try {
            $firstDayOfMonth = date('Y-m-01');
            $stmt = $db->prepare("SELECT COUNT(*) as count FROM events WHERE club_id = ? AND created_at >= ?");
            $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
            $stmt->bindValue(2, $firstDayOfMonth, SQLITE3_TEXT);
            $result = $stmt->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            $currentCount = (int)($row['count'] ?? 0);
        } catch (Exception $e) {
            $currentCount = 0;
        }
        
        if (!require_subscription_feature('max_events_per_month', null, $currentCount + 1)) {
            // Sayfa gösterildi ve çıkış yapıldı
            return;
        }
        
        // events tablosuna eksik kolonları ekle
        ensure_events_table_columns($db);
        
        try {
            $title = tpl_validate_string($post['title'] ?? '', [
                'field' => 'Etkinlik başlığı',
                'min' => 3,
                'max' => 180,
            ]);
            $date = tpl_validate_date($post['date'] ?? '', 'Y-m-d', ['field' => 'Başlangıç tarihi']);
            $time = tpl_validate_time($post['time'] ?? '', ['field' => 'Başlangıç saati']);
            $location = tpl_validate_string($post['location'] ?? '', [
                'field' => 'Konum',
                'allow_empty' => true,
                'min' => 2,
                'max' => 255,
            ]);
            $category = tpl_validate_string($post['category'] ?? 'Genel', [
                'field' => 'Kategori',
                'min' => 2,
                'max' => 50,
            ]);
            $description = tpl_validate_string($post['description'] ?? '', [
                'field' => 'Açıklama',
                'allow_empty' => true,
                'max' => 5000,
            ]);
            $organizer = tpl_validate_string($post['organizer'] ?? '', [
                'field' => 'Organizatör',
                'allow_empty' => true,
                'max' => 255,
            ]);
            $contact_email = tpl_validate_email($post['contact_email'] ?? '', [
                'field' => 'İletişim e-postası',
                'allow_empty' => true,
            ]);
            $contact_phone = tpl_validate_phone($post['contact_phone'] ?? '', [
                'field' => 'İletişim telefonu',
                'allow_empty' => true,
            ]);
            $external_link = tpl_validate_url($post['external_link'] ?? '', [
                'field' => 'Dış bağlantı',
                'allow_empty' => true,
            ]);
            $cost = tpl_validate_float($post['cost'] ?? null, [
                'field' => 'Ücret',
                'allow_empty' => true,
                'min' => 0,
            ]);
            $capacity = tpl_validate_int($post['capacity'] ?? null, [
                'field' => 'Kapasite',
                'allow_empty' => true,
                'min' => 0,
            ]);
            $max_attendees = tpl_validate_int($post['max_attendees'] ?? null, [
                'field' => 'Maksimum katılımcı',
                'allow_empty' => true,
                'min' => 0,
            ]);
            $min_attendees = tpl_validate_int($post['min_attendees'] ?? null, [
                'field' => 'Minimum katılımcı',
                'allow_empty' => true,
                'min' => 0,
            ]);
            // registration_deadline datetime-local formatında gelebilir (Y-m-d\TH:i)
            $registration_deadline_raw = trim($post['registration_deadline'] ?? '');
            $registration_deadline = '';
            if ($registration_deadline_raw !== '') {
                // datetime-local formatını parse et (Y-m-d\TH:i veya Y-m-d H:i)
                if (preg_match('/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/', $registration_deadline_raw, $matches)) {
                    $registration_deadline = $matches[1]; // Sadece tarih kısmını al
                } else {
                    // Sadece tarih formatıysa direkt kullan
                    $registration_deadline = tpl_validate_date($registration_deadline_raw, 'Y-m-d', [
                        'field' => 'Kayıt bitiş tarihi',
                        'allow_empty' => false,
                    ]);
                }
            }
            $end_date = tpl_validate_date($post['end_date'] ?? '', 'Y-m-d', [
                'field' => 'Bitiş tarihi',
                'allow_empty' => true,
            ]);
            $end_time = tpl_validate_time($post['end_time'] ?? '', [
                'field' => 'Bitiş saati',
                'allow_empty' => true,
            ]);
        } catch (TplValidationException $validationException) {
            $_SESSION['error'] = $validationException->getMessage();
            return;
        }
        
        // Bitiş tarihi kontrolü
        if ($end_date !== '' && $date !== '' && strtotime($end_date) < strtotime($date)) {
            throw new Exception('Bitiş tarihi başlangıç tarihinden önce olamaz.');
        }
        
        // Maksimum/Minimum katılımcı kontrolü
        if ($max_attendees !== null && $min_attendees !== null && $max_attendees < $min_attendees) {
            throw new Exception('Maksimum katılımcı sayısı minimumdan küçük olamaz.');
        }
        
        // Dosya yükleme işlemleri
        $image_path = '';
        $video_path = '';
        
        // Görsel yükleme
        if (isset($_FILES['event_image']) && $_FILES['event_image']['error'] === UPLOAD_ERR_OK) {
            $image_path = handle_file_upload($_FILES['event_image'], 'images/events/', ['jpg', 'jpeg', 'png', 'gif'], 5 * 1024 * 1024); // 5MB
        }
        
        // Video yükleme
        if (isset($_FILES['event_video']) && $_FILES['event_video']['error'] === UPLOAD_ERR_OK) {
            $video_path = handle_file_upload($_FILES['event_video'], 'videos/events/', ['mp4', 'avi', 'mov', 'wmv'], 50 * 1024 * 1024); // 50MB
        }
        
        // Tarih/saat birleştirme
        $start_datetime = null;
        $end_datetime = null;
        if ($date !== '' && $time !== '') {
            $start_datetime = $date . ' ' . $time . ':00';
        }
        if ($end_date !== '' && $end_time !== '') {
            $end_datetime = $end_date . ' ' . $end_time . ':00';
        }
        
        // Tags'i JSON'a çevir
        $tags = '';
        if (!empty($post['tags'])) {
            $tags_array = array_map('trim', explode(',', $post['tags']));
            $tags = json_encode($tags_array);
        }
        
        $stmt = $db->prepare("INSERT INTO events (
            club_id, title, date, time, location, description, image_path, video_path,
            category, status, priority, capacity, registration_required, registration_deadline,
            start_datetime, end_datetime, organizer, contact_email, contact_phone, tags,
            visibility, featured, external_link, cost, max_attendees, min_attendees
        ) VALUES (
            :club_id, :title, :date, :time, :location, :description, :image_path, :video_path,
            :category, :status, :priority, :capacity, :registration_required, :registration_deadline,
            :start_datetime, :end_datetime, :organizer, :contact_email, :contact_phone, :tags,
            :visibility, :featured, :external_link, :cost, :max_attendees, :min_attendees
        )");
        
        $stmt->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(':title', $title, SQLITE3_TEXT);
        $stmt->bindValue(':date', $date, SQLITE3_TEXT);
        $stmt->bindValue(':time', $time, SQLITE3_TEXT);
        $stmt->bindValue(':location', $location, SQLITE3_TEXT);
        $stmt->bindValue(':description', $description, SQLITE3_TEXT);
        $stmt->bindValue(':image_path', $image_path, SQLITE3_TEXT);
        $stmt->bindValue(':video_path', $video_path, SQLITE3_TEXT);
        $stmt->bindValue(':category', $category, SQLITE3_TEXT);
        $stmt->bindValue(':status', $post['status'] ?? 'planlanıyor', SQLITE3_TEXT);
        $stmt->bindValue(':priority', $post['priority'] ?? 'normal', SQLITE3_TEXT);
        $stmt->bindValue(':capacity', $capacity, $capacity === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':registration_required', isset($post['registration_required']) ? 1 : 0, SQLITE3_INTEGER);
        $stmt->bindValue(':registration_deadline', $registration_deadline, SQLITE3_TEXT);
        $stmt->bindValue(':start_datetime', $start_datetime, SQLITE3_TEXT);
        $stmt->bindValue(':end_datetime', $end_datetime, SQLITE3_TEXT);
        $stmt->bindValue(':organizer', $organizer, SQLITE3_TEXT);
        $stmt->bindValue(':contact_email', $contact_email, SQLITE3_TEXT);
        $stmt->bindValue(':contact_phone', $contact_phone, SQLITE3_TEXT);
        $stmt->bindValue(':tags', $tags, SQLITE3_TEXT);
        $stmt->bindValue(':visibility', $post['visibility'] ?? 'public', SQLITE3_TEXT);
        $stmt->bindValue(':featured', isset($post['featured']) ? 1 : 0, SQLITE3_INTEGER);
        $stmt->bindValue(':external_link', $external_link, SQLITE3_TEXT);
        $stmt->bindValue(':cost', $cost !== null ? $cost : 0, SQLITE3_FLOAT);
        $stmt->bindValue(':max_attendees', $max_attendees, $max_attendees === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':min_attendees', $min_attendees, $min_attendees === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->execute();
        $event_id = $db->lastInsertRowID();
        
        // Log kaydet
        if (isset($_SESSION['admin_id']) && isset($_SESSION['admin_username'])) {
            logToSuperAdmin('admin_action', [
                'user_id' => $_SESSION['admin_id'],
                'username' => $_SESSION['admin_username'],
                'action_type' => 'event_create',
                'action_description' => 'Yeni etkinlik oluşturuldu: ' . trim($post['title']),
                'additional_data' => [
                    'event_id' => $event_id,
                    'event_title' => trim($post['title']),
                    'category' => $post['category'] ?? '',
                    'status' => $post['status'] ?? '',
                    'location' => $post['location'] ?? '',
                    'date' => $post['date'] ?? '',
                    'time' => $post['time'] ?? '',
                    'organizer' => $post['organizer'] ?? '',
                    'cost' => $post['cost'] ?? 0,
                    'capacity' => $post['capacity'] ?? null
                ]
            ]);
        }
        
        // Eğer anket oluşturulması isteniyorsa
        if (isset($post['create_survey_with_event']) && $post['create_survey_with_event'] == '1' && !empty(trim($post['survey_title'] ?? ''))) {
            try {
                $survey_title = trim($post['survey_title']);
                $survey_description = trim($post['survey_description'] ?? '');
                
                // Anket oluştur
                $survey_stmt = $db->prepare("INSERT INTO event_surveys (event_id, club_id, title, description) VALUES (?, ?, ?, ?)");
                if ($survey_stmt) {
                    $survey_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                    $survey_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                    $survey_stmt->bindValue(3, $survey_title, SQLITE3_TEXT);
                    $survey_stmt->bindValue(4, $survey_description, SQLITE3_TEXT);
                    $survey_stmt->execute();
                    
                    // Etkinliği has_survey olarak işaretle
                    $update_stmt = $db->prepare("UPDATE events SET has_survey = 1 WHERE id = ? AND club_id = ?");
                    if ($update_stmt) {
                        $update_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                        $update_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                        $update_stmt->execute();
                    }
                }
            } catch (Exception $e) {
                tpl_error_log("Anket oluşturma hatası (etkinlik ekleme sırasında): " . $e->getMessage());
                // Anket oluşturulamasa bile etkinlik başarılı sayılır
            }
        }
        
        // Cache'i temizle
        clear_entity_cache('events');
        
        // Yeni etkinlik oluşturulduğunda push notification gönder
        try {
            sendEventNotificationToMembers($db, $event_id, $title, $date, $time, $location);
        } catch (Exception $e) {
            // Notification hatası kritik değil, sadece logla
            tpl_error_log("Event notification gönderim hatası: " . $e->getMessage());
        }
        
        // Form verilerini temizle (JavaScript için)
        $_SESSION['clear_form_data'] = true;
        $_SESSION['event_added_successfully'] = true;
        
        $_SESSION['message'] = "Etkinlik başarıyla eklendi." . (isset($post['create_survey_with_event']) && $post['create_survey_with_event'] == '1' ? " Anket de oluşturuldu." : "");
    } catch (Exception $e) {
        $_SESSION['error'] = "Etkinlik eklenirken hata: " . $e->getMessage();
        tpl_error_log("Etkinlik ekleme hatası: " . $e->getMessage() . " - Stack trace: " . $e->getTraceAsString());
    }
}


function update_event($db, $post) {
    try {
        // events tablosuna eksik kolonları ekle
        ensure_events_table_columns($db);
        
        try {
            $event_id = tpl_validate_int($post['id'] ?? null, [
                'field' => 'Etkinlik ID',
                'min' => 1,
            ]);
            $title = tpl_validate_string($post['title'] ?? '', [
                'field' => 'Etkinlik başlığı',
                'min' => 3,
                'max' => 180,
            ]);
            $date = tpl_validate_date($post['date'] ?? '', 'Y-m-d', ['field' => 'Başlangıç tarihi']);
            $time = tpl_validate_time($post['time'] ?? '', ['field' => 'Başlangıç saati']);
            $location = tpl_validate_string($post['location'] ?? '', [
                'field' => 'Konum',
                'min' => 2,
                'max' => 255,
            ]);
            $category = tpl_validate_string($post['category'] ?? 'Genel', [
                'field' => 'Kategori',
                'min' => 2,
                'max' => 50,
            ]);
            $description = tpl_validate_string($post['description'] ?? '', [
                'field' => 'Açıklama',
                'allow_empty' => true,
                'max' => 5000,
            ]);
            $organizer = tpl_validate_string($post['organizer'] ?? '', [
                'field' => 'Organizatör',
                'allow_empty' => true,
                'max' => 255,
            ]);
            $contact_email = tpl_validate_email($post['contact_email'] ?? '', [
                'field' => 'İletişim e-postası',
                'allow_empty' => true,
            ]);
            $contact_phone = tpl_validate_phone($post['contact_phone'] ?? '', [
                'field' => 'İletişim telefonu',
                'allow_empty' => true,
            ]);
            $external_link = tpl_validate_url($post['external_link'] ?? '', [
                'field' => 'Dış bağlantı',
                'allow_empty' => true,
            ]);
            $cost = tpl_validate_float($post['cost'] ?? null, [
                'field' => 'Ücret',
                'allow_empty' => true,
                'min' => 0,
            ]);
            $capacity = tpl_validate_int($post['capacity'] ?? null, [
                'field' => 'Kapasite',
                'allow_empty' => true,
                'min' => 0,
                'max' => 10000,
            ]);
            $max_attendees = tpl_validate_int($post['max_attendees'] ?? null, [
                'field' => 'Maksimum katılımcı',
                'allow_empty' => true,
                'min' => 0,
            ]);
            $min_attendees = tpl_validate_int($post['min_attendees'] ?? null, [
                'field' => 'Minimum katılımcı',
                'allow_empty' => true,
                'min' => 0,
            ]);
            // registration_deadline datetime-local formatında gelebilir (Y-m-d\TH:i)
            $registration_deadline_raw = trim($post['registration_deadline'] ?? '');
            $registration_deadline = '';
            if ($registration_deadline_raw !== '') {
                // datetime-local formatını parse et (Y-m-d\TH:i veya Y-m-d H:i)
                if (preg_match('/^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2})/', $registration_deadline_raw, $matches)) {
                    $registration_deadline = $matches[1]; // Sadece tarih kısmını al
                } else {
                    // Sadece tarih formatıysa direkt kullan
                    $registration_deadline = tpl_validate_date($registration_deadline_raw, 'Y-m-d', [
                        'field' => 'Kayıt bitiş tarihi',
                        'allow_empty' => false,
                    ]);
                }
            }
            $end_date = tpl_validate_date($post['end_date'] ?? '', 'Y-m-d', [
                'field' => 'Bitiş tarihi',
                'allow_empty' => true,
            ]);
            $end_time = tpl_validate_time($post['end_time'] ?? '', [
                'field' => 'Bitiş saati',
                'allow_empty' => true,
            ]);
        } catch (TplValidationException $validationException) {
            $_SESSION['error'] = $validationException->getMessage();
            return;
        }
        
        $event_datetime = strtotime($date . ' ' . ($time ?: '00:00'));
        
        if ($end_date !== '' && $date !== '') {
            $end_datetime = strtotime($end_date . ' ' . ($end_time ?: '23:59'));
            if ($end_datetime < $event_datetime) {
                throw new Exception('Bitiş tarihi/saati başlangıç tarihi/saatinden önce olamaz.');
            }
        }
        
        if ($capacity !== null && $capacity > 0) {
            $rsvp_count_stmt = $db->prepare("SELECT COUNT(*) as count FROM event_rsvp WHERE event_id = :event_id AND rsvp_status = 'attending'");
            if ($rsvp_count_stmt) {
                $rsvp_count_stmt->bindValue(':event_id', $event_id, SQLITE3_INTEGER);
                $rsvp_count_result = $rsvp_count_stmt->execute();
                if ($rsvp_count_result) {
                    $rsvp_count_row = $rsvp_count_result->fetchArray(SQLITE3_ASSOC);
                    $current_rsvp_count = (int)($rsvp_count_row['count'] ?? 0);
                    if ($capacity < $current_rsvp_count) {
                        throw new Exception("Kapasite mevcut katılımcı sayısından ($current_rsvp_count) küçük olamaz!");
                    }
                }
            }
        }
        
        if ($max_attendees !== null && $min_attendees !== null && $max_attendees < $min_attendees) {
            throw new Exception('Maksimum katılımcı sayısı minimumdan küçük olamaz.');
        }
        if ($max_attendees !== null && $capacity !== null && $capacity > 0 && $max_attendees > $capacity) {
            throw new Exception('Maksimum katılımcı sayısı kapasiteden fazla olamaz.');
        }
        
        if ($registration_deadline !== '' && $event_datetime !== false) {
            $deadline = strtotime($registration_deadline);
            if ($deadline > $event_datetime) {
                throw new Exception('Kayıt son tarihi etkinlik tarihinden sonra olamaz.');
            }
        }
        
        // Dosya yükleme işlemleri (sadece yeni dosya yüklenirse)
        $image_path = null;
        $video_path = null;
        
        // Görsel yükleme
        if (isset($_FILES['event_image']) && $_FILES['event_image']['error'] === UPLOAD_ERR_OK) {
            $image_path = handle_file_upload($_FILES['event_image'], 'images/events/', ['jpg', 'jpeg', 'png', 'gif'], 5 * 1024 * 1024);
        }
        
        // Video yükleme
        if (isset($_FILES['event_video']) && $_FILES['event_video']['error'] === UPLOAD_ERR_OK) {
            $video_path = handle_file_upload($_FILES['event_video'], 'videos/events/', ['mp4', 'avi', 'mov', 'wmv'], 50 * 1024 * 1024);
        }
        
        // Tarih/saat birleştirme
        $start_datetime = null;
        $end_datetime = null;
        if ($date !== '' && $time !== '') {
            $start_datetime = $date . ' ' . $time . ':00';
        }
        if ($end_date !== '' && $end_time !== '') {
            $end_datetime = $end_date . ' ' . $end_time . ':00';
        }
        
        // Tags'i JSON'a çevir
        $tags = '';
        if (!empty($post['tags'])) {
            $tags_array = array_map('trim', explode(',', $post['tags']));
            $tags = json_encode($tags_array);
        }
        
        // Eğer yeni dosya yüklenmediyse, mevcut dosyaları koru
        if ($image_path === null) {
            $current = $db->prepare("SELECT image_path FROM events WHERE id = :id AND club_id = :club_id");
            $current->bindValue(':id', $event_id, SQLITE3_INTEGER);
            $current->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
            $result = $current->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            $image_path = $row['image_path'] ?? '';
        }
        
        if ($video_path === null) {
            $current = $db->prepare("SELECT video_path FROM events WHERE id = :id AND club_id = :club_id");
            $current->bindValue(':id', $event_id, SQLITE3_INTEGER);
            $current->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
            $result = $current->execute();
            $row = $result->fetchArray(SQLITE3_ASSOC);
            $video_path = $row['video_path'] ?? '';
        }
        
        $stmt = $db->prepare("UPDATE events SET 
            title = :title, date = :date, time = :time, location = :location, description = :description,
            image_path = :image_path, video_path = :video_path,
            category = :category, status = :status, priority = :priority, capacity = :capacity,
            registration_required = :registration_required, registration_deadline = :registration_deadline,
            start_datetime = :start_datetime, end_datetime = :end_datetime, organizer = :organizer,
            contact_email = :contact_email, contact_phone = :contact_phone, tags = :tags,
            visibility = :visibility, featured = :featured, external_link = :external_link,
            cost = :cost, max_attendees = :max_attendees, min_attendees = :min_attendees,
            updated_at = CURRENT_TIMESTAMP
            WHERE id = :id AND club_id = :club_id");
        
        $stmt->bindValue(':title', $title, SQLITE3_TEXT);
        $stmt->bindValue(':date', $date, SQLITE3_TEXT);
        $stmt->bindValue(':time', $time, SQLITE3_TEXT);
        $stmt->bindValue(':location', $location, SQLITE3_TEXT);
        $stmt->bindValue(':description', $description, SQLITE3_TEXT);
        $stmt->bindValue(':image_path', $image_path, SQLITE3_TEXT);
        $stmt->bindValue(':video_path', $video_path, SQLITE3_TEXT);
        $stmt->bindValue(':category', $category, SQLITE3_TEXT);
        $stmt->bindValue(':status', $post['status'] ?? 'planlanıyor', SQLITE3_TEXT);
        $stmt->bindValue(':priority', $post['priority'] ?? 'normal', SQLITE3_TEXT);
        $stmt->bindValue(':capacity', $capacity, $capacity === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':registration_required', isset($post['registration_required']) ? 1 : 0, SQLITE3_INTEGER);
        $stmt->bindValue(':registration_deadline', $registration_deadline, SQLITE3_TEXT);
        $stmt->bindValue(':start_datetime', $start_datetime, SQLITE3_TEXT);
        $stmt->bindValue(':end_datetime', $end_datetime, SQLITE3_TEXT);
        $stmt->bindValue(':organizer', $organizer, SQLITE3_TEXT);
        $stmt->bindValue(':contact_email', $contact_email, SQLITE3_TEXT);
        $stmt->bindValue(':contact_phone', $contact_phone, SQLITE3_TEXT);
        $stmt->bindValue(':tags', $tags, SQLITE3_TEXT);
        $stmt->bindValue(':visibility', $post['visibility'] ?? 'public', SQLITE3_TEXT);
        $stmt->bindValue(':featured', isset($post['featured']) ? 1 : 0, SQLITE3_INTEGER);
        $stmt->bindValue(':external_link', $external_link, SQLITE3_TEXT);
        $stmt->bindValue(':cost', $cost !== null ? $cost : 0, SQLITE3_FLOAT);
        $stmt->bindValue(':max_attendees', $max_attendees, $max_attendees === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':min_attendees', $min_attendees, $min_attendees === null ? SQLITE3_NULL : SQLITE3_INTEGER);
        $stmt->bindValue(':id', $event_id, SQLITE3_INTEGER);
        $stmt->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
        $stmt->execute();
        
        // Log kaydet
        if (isset($_SESSION['admin_id']) && isset($_SESSION['admin_username'])) {
            $event_stmt = $db->prepare("SELECT title FROM events WHERE id = ? AND club_id = ?");
            $event_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
            $event_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
            $event_title = $event_stmt->execute()->fetchArray(SQLITE3_ASSOC)['title'] ?? null;
            logToSuperAdmin('admin_action', [
                'user_id' => $_SESSION['admin_id'],
                'username' => $_SESSION['admin_username'],
                'action_type' => 'event_update',
                'action_description' => 'Etkinlik güncellendi: ' . ($event_title ?: 'ID: ' . $event_id),
                'additional_data' => [
                    'event_id' => $event_id,
                    'event_title' => $event_title ?: 'ID: ' . $event_id,
                    'category' => $category,
                    'status' => $post['status'] ?? '',
                    'location' => $location,
                    'date' => $date,
                    'time' => $time,
                    'organizer' => $organizer,
                    'cost' => $cost ?? 0,
                    'capacity' => $capacity
                ]
            ]);
        }
        
        // Cache'i temizle
        clear_entity_cache('events');
        
        $_SESSION['message'] = "Etkinlik başarıyla güncellendi.";
    } catch (Exception $e) {
        $_SESSION['error'] = "Etkinlik güncellenirken hata: " . $e->getMessage();
    }
}


function delete_event($db, $id) {
    // Gerçek hayat senaryosu: Etkinlik silinmeden önce RSVP kayıtlarını kontrol et
    try {
        // Önce etkinliğin bilgilerini al
        $stmt = $db->prepare("SELECT id, title, image_path, video_path, date, time FROM events WHERE id = :id AND club_id = :club_id");
        $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $stmt->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $event = $result->fetchArray(SQLITE3_ASSOC);
        
        if (!$event) {
            throw new Exception('Etkinlik bulunamadı.');
        }
        
        // RSVP kayıtlarını kontrol et - Gerçek hayat senaryosu
        $rsvp_check = $db->prepare("SELECT COUNT(*) as count FROM event_rsvp WHERE event_id = :event_id");
        if ($rsvp_check) {
            $rsvp_check->bindValue(':event_id', $id, SQLITE3_INTEGER);
            $rsvp_result = $rsvp_check->execute();
            if ($rsvp_result) {
                $rsvp_row = $rsvp_result->fetchArray(SQLITE3_ASSOC);
                $rsvp_count = (int)($rsvp_row['count'] ?? 0);
                if ($rsvp_count > 0) {
                    // RSVP kayıtları var - uyarı ver ama silmeye devam et (CASCADE ile otomatik silinir)
                    tpl_error_log("Event deletion warning: Event has $rsvp_count RSVP records (ID: $id, Title: " . ($event['title'] ?? 'Unknown') . ")");
                }
            }
        }
        
        // Gelecekteki etkinlik kontrolü - Gerçek hayat senaryosu
        if (!empty($event['date']) && !empty($event['time'])) {
            $event_datetime = strtotime($event['date'] . ' ' . $event['time']);
            if ($event_datetime > time()) {
                // Gelecekteki etkinlik - uyarı ver
                tpl_error_log("Event deletion warning: Deleting future event (ID: $id, Date: " . $event['date'] . ")");
            }
        }
        
        // İlişkili fotoğrafları al ve sil
        $images_stmt = $db->prepare("SELECT image_path FROM event_images WHERE event_id = :event_id");
        $images_stmt->bindValue(':event_id', $id, SQLITE3_INTEGER);
        $images_result = $images_stmt->execute();
        while ($image = $images_result->fetchArray(SQLITE3_ASSOC)) {
            $file_path = community_path($image['image_path']);
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
        
        // İlişkili videoları al ve sil
        $videos_stmt = $db->prepare("SELECT video_path FROM event_videos WHERE event_id = :event_id");
        $videos_stmt->bindValue(':event_id', $id, SQLITE3_INTEGER);
        $videos_result = $videos_stmt->execute();
        while ($video = $videos_result->fetchArray(SQLITE3_ASSOC)) {
            $file_path = community_path($video['video_path']);
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
        
        // Ana etkinlik görseli ve videosu
        if ($event && !empty($event['image_path'])) {
            $file_path = community_path($event['image_path']);
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
        if ($event && !empty($event['video_path'])) {
            $file_path = community_path($event['video_path']);
            if (file_exists($file_path)) {
                unlink($file_path);
            }
        }
        
        // Log kaydet (silmeden önce)
        if (isset($_SESSION['admin_id']) && isset($_SESSION['admin_username'])) {
            $event_title = $event ? ($event['title'] ?? 'ID: ' . $id) : 'ID: ' . $id;
            logToSuperAdmin('admin_action', [
                'user_id' => $_SESSION['admin_id'],
                'username' => $_SESSION['admin_username'],
                'action_type' => 'event_delete',
                'action_description' => 'Etkinlik silindi: ' . $event_title,
                'additional_data' => ['event_id' => $id]
            ]);
        }
        
        // Veritabanından sil (CASCADE ile ilişkili kayıtlar otomatik silinir)
        $delete_stmt = $db->prepare("DELETE FROM events WHERE id = :id AND club_id = :club_id");
        $delete_stmt->bindValue(':id', $id, SQLITE3_INTEGER);
        $delete_stmt->bindValue(':club_id', CLUB_ID, SQLITE3_INTEGER);
        $delete_stmt->execute();
        
        // Cache'i temizle
        clear_entity_cache('events');
        
        $_SESSION['message'] = "Etkinlik ve ilişkili tüm dosyalar başarıyla silindi.";
    } catch (Exception $e) {
        $_SESSION['error'] = "Etkinlik silinirken hata: " . $e->getMessage();
    }
}

// Etkinlik Medya İşlemleri

function handle_upload_event_media($db, $post, $files) {
    try {
        $event_id = (int)($post['event_id'] ?? 0);
        if (!$event_id) {
            echo json_encode(['success' => false, 'message' => 'Geçersiz etkinlik ID']);
            return;
        }
        
        $uploaded_count = 0;
        $errors = [];
        
        // Fotoğrafları yükle
        if (isset($files['event_images']) && is_array($files['event_images']['name'])) {
            foreach ($files['event_images']['name'] as $key => $name) {
                // Hata kontrolü
                if (!isset($files['event_images']['error'][$key])) {
                    continue;
                }
                
                if ($files['event_images']['error'][$key] === UPLOAD_ERR_OK) {
                    $file = [
                        'name' => $files['event_images']['name'][$key] ?? '',
                        'type' => $files['event_images']['type'][$key] ?? '',
                        'tmp_name' => $files['event_images']['tmp_name'][$key] ?? '',
                        'error' => $files['event_images']['error'][$key] ?? UPLOAD_ERR_NO_FILE,
                        'size' => $files['event_images']['size'][$key] ?? 0
                    ];
                    
                    // Dosya adı kontrolü
                    if (empty($file['name'])) {
                        continue;
                    }
                    
                    try {
                        $image_path = handle_file_upload($file, 'images/events/', ['jpg', 'jpeg', 'png', 'gif'], 5 * 1024 * 1024);
                        
                        if (!empty($image_path)) {
                            $stmt = $db->prepare("INSERT INTO event_images (event_id, club_id, image_path) VALUES (?, ?, ?)");
                            $stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                            $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                            $stmt->bindValue(3, $image_path, SQLITE3_TEXT);
                            $stmt->execute();
                            $uploaded_count++;
                        } else {
                            $errors[] = $name . ': Dosya yüklenemedi';
                        }
                    } catch (Exception $e) {
                        $errors[] = $name . ': ' . $e->getMessage();
                    }
                } else {
                    $error_msg = 'Bilinmeyen hata';
                    switch ($files['event_images']['error'][$key]) {
                        case UPLOAD_ERR_INI_SIZE:
                        case UPLOAD_ERR_FORM_SIZE:
                            $error_msg = 'Dosya boyutu çok büyük';
                            break;
                        case UPLOAD_ERR_PARTIAL:
                            $error_msg = 'Dosya kısmen yüklendi';
                            break;
                        case UPLOAD_ERR_NO_FILE:
                            $error_msg = 'Dosya seçilmedi';
                            break;
                        case UPLOAD_ERR_NO_TMP_DIR:
                            $error_msg = 'Geçici klasör bulunamadı';
                            break;
                        case UPLOAD_ERR_CANT_WRITE:
                            $error_msg = 'Dosya yazılamadı';
                            break;
                        case UPLOAD_ERR_EXTENSION:
                            $error_msg = 'Dosya yükleme uzantı hatası';
                            break;
                    }
                    $errors[] = ($name ? $name : 'Fotoğraf') . ': ' . $error_msg;
                }
            }
        }
        
        // Videoları yükle
        if (isset($files['event_videos']) && is_array($files['event_videos']['name'])) {
            foreach ($files['event_videos']['name'] as $key => $name) {
                // Hata kontrolü
                if (!isset($files['event_videos']['error'][$key])) {
                    continue;
                }
                
                if ($files['event_videos']['error'][$key] === UPLOAD_ERR_OK) {
                    $file = [
                        'name' => $files['event_videos']['name'][$key] ?? '',
                        'type' => $files['event_videos']['type'][$key] ?? '',
                        'tmp_name' => $files['event_videos']['tmp_name'][$key] ?? '',
                        'error' => $files['event_videos']['error'][$key] ?? UPLOAD_ERR_NO_FILE,
                        'size' => $files['event_videos']['size'][$key] ?? 0
                    ];
                    
                    // Dosya adı kontrolü
                    if (empty($file['name'])) {
                        continue;
                    }
                    
                    try {
                        $video_path = handle_file_upload($file, 'videos/events/', ['mp4', 'avi', 'mov', 'wmv'], 50 * 1024 * 1024);
                        
                        if (!empty($video_path)) {
                            $stmt = $db->prepare("INSERT INTO event_videos (event_id, club_id, video_path) VALUES (?, ?, ?)");
                            $stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
                            $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                            $stmt->bindValue(3, $video_path, SQLITE3_TEXT);
                            $stmt->execute();
                            $uploaded_count++;
                        } else {
                            $errors[] = $name . ': Dosya yüklenemedi';
                        }
                    } catch (Exception $e) {
                        $errors[] = $name . ': ' . $e->getMessage();
                    }
                } else {
                    $error_msg = 'Bilinmeyen hata';
                    switch ($files['event_videos']['error'][$key]) {
                        case UPLOAD_ERR_INI_SIZE:
                        case UPLOAD_ERR_FORM_SIZE:
                            $error_msg = 'Dosya boyutu çok büyük';
                            break;
                        case UPLOAD_ERR_PARTIAL:
                            $error_msg = 'Dosya kısmen yüklendi';
                            break;
                        case UPLOAD_ERR_NO_FILE:
                            $error_msg = 'Dosya seçilmedi';
                            break;
                        case UPLOAD_ERR_NO_TMP_DIR:
                            $error_msg = 'Geçici klasör bulunamadı';
                            break;
                        case UPLOAD_ERR_CANT_WRITE:
                            $error_msg = 'Dosya yazılamadı';
                            break;
                        case UPLOAD_ERR_EXTENSION:
                            $error_msg = 'Dosya yükleme uzantı hatası';
                            break;
                    }
                    $errors[] = ($name ? $name : 'Video') . ': ' . $error_msg;
                }
            }
        }
        
        if ($uploaded_count > 0) {
            echo json_encode(['success' => true, 'message' => "{$uploaded_count} dosya başarıyla yüklendi", 'errors' => $errors]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Yüklenecek dosya bulunamadı', 'errors' => $errors]);
        }
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Hata: ' . $e->getMessage()]);
    }
}


function handle_delete_event_image($db, $image_id) {
    try {
        // Önce dosya yolunu al
        $stmt = $db->prepare("SELECT image_path FROM event_images WHERE id = ? AND club_id = ?");
        $stmt->bindValue(1, $image_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($row && $row['image_path'] && file_exists($row['image_path'])) {
            unlink($row['image_path']);
        }
        
        // Veritabanından sil
        $stmt = $db->prepare("DELETE FROM event_images WHERE id = ? AND club_id = ?");
        $stmt->bindValue(1, $image_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo json_encode(['success' => true, 'message' => 'Fotoğraf silindi']);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Hata: ' . $e->getMessage()]);
    }
}


function handle_delete_event_video($db, $video_id) {
    try {
        // Önce dosya yolunu al
        $stmt = $db->prepare("SELECT video_path FROM event_videos WHERE id = ? AND club_id = ?");
        $stmt->bindValue(1, $video_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        
        if ($row && $row['video_path'] && file_exists($row['video_path'])) {
            unlink($row['video_path']);
        }
        
        // Veritabanından sil
        $stmt = $db->prepare("DELETE FROM event_videos WHERE id = ? AND club_id = ?");
        $stmt->bindValue(1, $video_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $stmt->execute();
        
        echo json_encode(['success' => true, 'message' => 'Video silindi']);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Hata: ' . $e->getMessage()]);
    }
}


function get_event_media_json($db, $event_id) {
    try {
        // Fotoğrafları çek
        $images_stmt = $db->prepare("SELECT id, image_path FROM event_images WHERE event_id = ? AND club_id = ? ORDER BY uploaded_at DESC");
        $images_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
        $images_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $images_result = $images_stmt->execute();
        $images = [];
        while ($row = $images_result->fetchArray(SQLITE3_ASSOC)) {
            $images[] = $row;
        }
        
        // Videoları çek
        $videos_stmt = $db->prepare("SELECT id, video_path FROM event_videos WHERE event_id = ? AND club_id = ? ORDER BY uploaded_at DESC");
        $videos_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
        $videos_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $videos_result = $videos_stmt->execute();
        $videos = [];
        while ($row = $videos_result->fetchArray(SQLITE3_ASSOC)) {
            $videos[] = $row;
        }
        
        echo json_encode(['success' => true, 'images' => $images, 'videos' => $videos]);
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'Hata: ' . $e->getMessage()]);
    }
}

// Anket İşlemleri

function handle_create_survey($db, $post) {
    // Tüm output buffer'ı temizle
    if (ob_get_level()) {
        ob_clean();
    }
    
    try {
        $event_id = (int)($post['event_id'] ?? 0);
        $title = trim($post['survey_title'] ?? '');
        $description = trim($post['survey_description'] ?? '');
        
        if (!$event_id || !$title) {
            echo json_encode(['success' => false, 'message' => 'Etkinlik ID ve anket başlığı gerekli']);
            return;
        }
        
        // Anket oluştur
        $stmt = $db->prepare("INSERT INTO event_surveys (event_id, club_id, title, description) VALUES (?, ?, ?, ?)");
        if (!$stmt) {
            throw new Exception("SQLite3 prepare hatası: " . $db->lastErrorMsg());
        }
        $stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(3, $title, SQLITE3_TEXT);
        $stmt->bindValue(4, $description, SQLITE3_TEXT);
        $result = $stmt->execute();
        if (!$result) {
            throw new Exception("SQLite3 execute hatası: " . $db->lastErrorMsg());
        }
        $survey_id = $db->lastInsertRowID();
        
        // Etkinliği has_survey olarak işaretle
        $update_stmt = $db->prepare("UPDATE events SET has_survey = 1 WHERE id = ? AND club_id = ?");
        if (!$update_stmt) {
            throw new Exception("SQLite3 prepare hatası (update): " . $db->lastErrorMsg());
        }
        $update_stmt->bindValue(1, $event_id, SQLITE3_INTEGER);
        $update_stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $update_result = $update_stmt->execute();
        if (!$update_result) {
            throw new Exception("SQLite3 execute hatası (update): " . $db->lastErrorMsg());
        }
        
        // Soruları ekle - questions[] array'i kontrol et
        $questions = [];
        if (isset($post['questions']) && is_array($post['questions'])) {
            $questions = $post['questions'];
        } else {
            // Form'dan tek tek al - regex yerine strpos ve substr kullan
            foreach ($post as $key => $value) {
                if (is_string($key) && strpos($key, 'questions[') === 0) {
                    // questions[0] formatını parse et - regex olmadan
                    $start = strpos($key, '[');
                    $end = strpos($key, ']');
                    if ($start !== false && $end !== false && $end > $start) {
                        $index_str = substr($key, $start + 1, $end - $start - 1);
                        if (is_numeric($index_str)) {
                            $questions[(int)$index_str] = is_string($value) ? trim($value) : '';
                        }
                    }
                }
            }
        }
        
        // Soruları ekle
        if (!empty($questions)) {
            ksort($questions); // Index'lere göre sırala
            foreach ($questions as $index => $question_text) {
                $question_text = trim($question_text);
                if (!empty($question_text)) {
                    $q_stmt = $db->prepare("INSERT INTO survey_questions (survey_id, question_text, display_order) VALUES (?, ?, ?)");
                    if (!$q_stmt) {
                        throw new Exception("SQLite3 prepare hatası (question): " . $db->lastErrorMsg());
                    }
                    $q_stmt->bindValue(1, $survey_id, SQLITE3_INTEGER);
                    $q_stmt->bindValue(2, $question_text, SQLITE3_TEXT);
                    $q_stmt->bindValue(3, (int)$index, SQLITE3_INTEGER);
                    $q_result = $q_stmt->execute();
                    if (!$q_result) {
                        throw new Exception("SQLite3 execute hatası (question): " . $db->lastErrorMsg());
                    }
                    $question_id = $db->lastInsertRowID();
                    
                    // Seçenekleri ekle - options_X[] array'lerini kontrol et
                    $question_num = $index + 1; // JavaScript'te questionNum + 1 kullanıyoruz
                    $option_key = 'options_' . $question_num;
                    $options = [];
                    
                    // options_X[] array'ini kontrol et
                    if (isset($post[$option_key]) && is_array($post[$option_key])) {
                        $options = $post[$option_key];
                    } else {
                        // Form'dan tek tek al - regex yerine string işlemleri kullan
                        $prefix = 'options_' . $question_num . '[';
                        foreach ($post as $key => $value) {
                            if (is_string($key) && strpos($key, $prefix) === 0) {
                                // options_X[Y] formatını parse et - regex olmadan
                                $start = strpos($key, '[');
                                $end = strpos($key, ']');
                                if ($start !== false && $end !== false && $end > $start) {
                                    $opt_index_str = substr($key, $start + 1, $end - $start - 1);
                                    if (is_numeric($opt_index_str)) {
                                        $options[(int)$opt_index_str] = is_string($value) ? trim($value) : '';
                                    }
                                }
                            }
                        }
                    }
                    
                    // Seçenekleri ekle
                    if (!empty($options)) {
                        ksort($options); // Index'lere göre sırala
                        foreach ($options as $opt_index => $option_text) {
                            $option_text = trim($option_text);
                            if (!empty($option_text)) {
                                $o_stmt = $db->prepare("INSERT INTO survey_options (question_id, option_text, display_order) VALUES (?, ?, ?)");
                                if (!$o_stmt) {
                                    throw new Exception("SQLite3 prepare hatası (option): " . $db->lastErrorMsg());
                                }
                                $o_stmt->bindValue(1, $question_id, SQLITE3_INTEGER);
                                $o_stmt->bindValue(2, $option_text, SQLITE3_TEXT);
                                $o_stmt->bindValue(3, (int)$opt_index, SQLITE3_INTEGER);
                                $o_result = $o_stmt->execute();
                                if (!$o_result) {
                                    throw new Exception("SQLite3 execute hatası (option): " . $db->lastErrorMsg());
                                }
                            }
                        }
                    }
                }
            }
        }
        
        echo json_encode(['success' => true, 'message' => 'Anket başarıyla oluşturuldu', 'survey_id' => $survey_id]);
    } catch (Exception $e) {
        tpl_error_log("Anket oluşturma hatası: " . $e->getMessage());
        tpl_error_log("POST data: " . print_r($_POST, true));
        echo json_encode(['success' => false, 'message' => 'Hata: ' . $e->getMessage()]);
    }
}

/**
 * Yeni etkinlik oluşturulduğunda üyelere push notification gönder
 */
function sendEventNotificationToMembers($db, $event_id, $event_title, $event_date, $event_time, $event_location) {
    try {
        // Superadmin veritabanından device token'ları al
        $superadminDbPath = __DIR__ . '/../../unipanel.sqlite';
        if (!file_exists($superadminDbPath)) {
            return; // Veritabanı yoksa sessizce çık
        }
        
        $superadminDb = new SQLite3($superadminDbPath);
        $superadminDb->exec('PRAGMA journal_mode = WAL');
        
        // Topluluk ID'sini al
        $db_path = $db->filename;
        $community_id = basename(dirname($db_path));
        
        // Bu topluluğa kayıtlı device token'ları al
        $tokens_query = $superadminDb->prepare("SELECT device_token, platform, user_id FROM device_tokens WHERE community_id = ? OR community_id IS NULL OR community_id = ''");
        $tokens_query->bindValue(1, $community_id, SQLITE3_TEXT);
        $tokens_result = $tokens_query->execute();
        
        $device_tokens = [];
        while ($row = $tokens_result->fetchArray(SQLITE3_ASSOC)) {
            $device_tokens[] = $row;
        }
        
        if (empty($device_tokens)) {
            $superadminDb->close();
            return; // Token yoksa çık
        }
        
        // Notification gönder (Firebase Cloud Messaging veya APNs)
        // Bu kısım Firebase/APNs entegrasyonu gerektirir
        // Şimdilik sadece log kaydı yapıyoruz, gerçek entegrasyon için ayrı bir servis gerekli
        
        $notification_data = [
            'type' => 'event',
            'related_id' => (string)$event_id,
            'community_id' => $community_id,
            'event_title' => $event_title,
            'event_date' => $event_date,
            'event_time' => $event_time,
            'event_location' => $event_location ?? ''
        ];
        
        // Notification queue'ya ekle (async işlem için)
        $queue_db = new SQLite3($superadminDbPath);
        $queue_db->exec('PRAGMA journal_mode = WAL');
        $queue_db->exec("CREATE TABLE IF NOT EXISTS notification_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            device_token TEXT NOT NULL,
            platform TEXT NOT NULL,
            notification_type TEXT NOT NULL,
            title TEXT NOT NULL,
            body TEXT NOT NULL,
            data TEXT,
            status TEXT DEFAULT 'pending',
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
            sent_at DATETIME
        )");
        
        $title = "Yeni Etkinlik: " . $event_title;
        $body = $event_date . ($event_time ? " " . $event_time : "") . ($event_location ? " - " . $event_location : "");
        
        foreach ($device_tokens as $token_data) {
            $insert_queue = $queue_db->prepare("INSERT INTO notification_queue (device_token, platform, notification_type, title, body, data) VALUES (?, ?, ?, ?, ?, ?)");
            $insert_queue->bindValue(1, $token_data['device_token'], SQLITE3_TEXT);
            $insert_queue->bindValue(2, $token_data['platform'], SQLITE3_TEXT);
            $insert_queue->bindValue(3, 'event', SQLITE3_TEXT);
            $insert_queue->bindValue(4, $title, SQLITE3_TEXT);
            $insert_queue->bindValue(5, $body, SQLITE3_TEXT);
            $insert_queue->bindValue(6, json_encode($notification_data, JSON_UNESCAPED_UNICODE), SQLITE3_TEXT);
            $insert_queue->execute();
        }
        
        $queue_db->close();
        $superadminDb->close();
        
        // Background job ile notification gönderilecek (cron job veya queue worker)
        // Şimdilik sadece queue'ya ekledik
        
    } catch (Exception $e) {
        tpl_error_log("Event notification gönderme hatası: " . $e->getMessage());
    }
}


