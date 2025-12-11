<?php
/**
 * Export/Import Module - Lazy Loaded
 */

function export_members_csv() {
    $db = get_db();
    $filename = 'uyeler_' . date('Y-m-d_His') . '.csv';
    
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $output = fopen('php://output', 'w');
    
    // BOM ekle (Excel için UTF-8 desteği)
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // Başlık satırı - Tüm alanları dahil et
    fputcsv($output, [
        'Ad Soyad',
        'E-posta',
        'Öğrenci No',
        'Telefon',
        'Kayıt Tarihi',
        'Bölüm',
        'Sınıf',
        'Doğum Tarihi',
        'Adres',
        'Notlar'
    ], ';');
    
    // Veriler - Tüm kolonları çek
    $stmt = $db->prepare("SELECT 
        full_name, 
        email, 
        student_id, 
        phone_number, 
        registration_date,
        department,
        class_year,
        birth_date,
        address,
        notes
    FROM members WHERE club_id = ? ORDER BY full_name");
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        fputcsv($output, [
            $row['full_name'] ?? '',
            $row['email'] ?? '',
            $row['student_id'] ?? '',
            $row['phone_number'] ?? '',
            $row['registration_date'] ?? '',
            $row['department'] ?? '',
            $row['class_year'] ?? '',
            $row['birth_date'] ?? '',
            $row['address'] ?? '',
            $row['notes'] ?? ''
        ], ';');
    }
    
    fclose($output);
    exit;
}


function export_members_excel() {
    $db = get_db();
    $filename = 'uyeler_' . date('Y-m-d_His') . '.xls';
    
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    echo '<html><head><meta charset="UTF-8"></head><body>';
    echo '<table border="1">';
    echo '<tr style="background-color: #4472C4; color: white; font-weight: bold;">';
    echo '<th>Ad Soyad</th><th>E-posta</th><th>Öğrenci No</th><th>Telefon</th><th>Kayıt Tarihi</th><th>Bölüm</th><th>Sınıf</th><th>Doğum Tarihi</th><th>Adres</th><th>Notlar</th>';
    echo '</tr>';
    
    $stmt = $db->prepare("SELECT 
        full_name, 
        email, 
        student_id, 
        phone_number, 
        registration_date,
        department,
        class_year,
        birth_date,
        address,
        notes
    FROM members WHERE club_id = ? ORDER BY full_name");
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        echo '<tr>';
        echo '<td>' . htmlspecialchars($row['full_name'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['email'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['student_id'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['phone_number'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['registration_date'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['department'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['class_year'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['birth_date'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['address'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['notes'] ?? '') . '</td>';
        echo '</tr>';
    }
    
    echo '</table></body></html>';
    exit;
}


function export_events_csv() {
    $db = get_db();
    
    // Events tablosuna eksik kolonları ekle
    ensure_events_table_columns($db);
    
    $filename = 'etkinlikler_' . date('Y-m-d_His') . '.csv';
    
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $output = fopen('php://output', 'w');
    
    // BOM ekle
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // Başlık satırı
    fputcsv($output, ['Başlık', 'Tarih', 'Saat', 'Konum', 'Kategori', 'Durum', 'Açıklama'], ';');
    
    // Veriler
    $stmt = $db->prepare("SELECT title, date, time, location, category, status, description FROM events WHERE club_id = ? ORDER BY date DESC, time DESC");
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        fputcsv($output, [
            $row['title'] ?? '',
            $row['date'] ?? '',
            $row['time'] ?? '',
            $row['location'] ?? '',
            $row['category'] ?? 'Genel',
            $row['status'] ?? 'planlanıyor',
            strip_tags($row['description'] ?? '')
        ], ';');
    }
    
    fclose($output);
    exit;
}


function export_events_excel() {
    $db = get_db();
    
    // Events tablosuna eksik kolonları ekle
    ensure_events_table_columns($db);
    
    $filename = 'etkinlikler_' . date('Y-m-d_His') . '.xls';
    
    header('Content-Type: application/vnd.ms-excel; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    echo '<html><head><meta charset="UTF-8"></head><body>';
    echo '<table border="1">';
    echo '<tr style="background-color: #4472C4; color: white; font-weight: bold;">';
    echo '<th>Başlık</th><th>Tarih</th><th>Saat</th><th>Konum</th><th>Kategori</th><th>Durum</th><th>Açıklama</th>';
    echo '</tr>';
    
    $stmt = $db->prepare("SELECT title, date, time, location, category, status, description FROM events WHERE club_id = ? ORDER BY date DESC, time DESC");
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $result = $stmt->execute();
    
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        echo '<tr>';
        echo '<td>' . htmlspecialchars($row['title'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['date'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['time'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['location'] ?? '') . '</td>';
        echo '<td>' . htmlspecialchars($row['category'] ?? 'Genel') . '</td>';
        echo '<td>' . htmlspecialchars($row['status'] ?? 'planlanıyor') . '</td>';
        echo '<td>' . htmlspecialchars(strip_tags($row['description'] ?? '')) . '</td>';
        echo '</tr>';
    }
    
    echo '</table></body></html>';
    exit;
}


function import_members_csv($file_path) {
    $db = get_db();
    $imported = 0;
    $updated = 0;
    $errors = [];
    
    // Güvenlik: Path validation - sadece geçici upload klasöründen dosya kabul et
    $real_file_path = realpath($file_path);
    if ($real_file_path === false || !file_exists($file_path)) {
        return ['success' => false, 'message' => 'Dosya bulunamadı'];
    }
    
    // Güvenlik: Dosya gerçekten geçici klasör içinde mi kontrol et
    $temp_dir = sys_get_temp_dir();
    $real_temp_dir = realpath($temp_dir);
    if ($real_temp_dir && strpos($real_file_path, $real_temp_dir) !== 0) {
        // Alternatif: community path içinde olabilir (upload edilmiş dosya)
        $real_community_path = realpath(community_path(''));
        if (!$real_community_path || strpos($real_file_path, $real_community_path) !== 0) {
            return ['success' => false, 'message' => 'Geçersiz dosya yolu'];
        }
    }
    
    // Eksik kolonları ekle
    $members_columns = $db->query("PRAGMA table_info(members)");
    $existing_columns = [];
    while ($col = $members_columns->fetchArray(SQLITE3_ASSOC)) {
        $existing_columns[] = $col['name'];
    }
    
    $required_columns = ['department', 'class_year', 'birth_date', 'address', 'notes'];
    foreach ($required_columns as $col) {
        if (!in_array($col, $existing_columns)) {
            try {
                $db->exec("ALTER TABLE members ADD COLUMN $col TEXT");
            } catch (Exception $e) {}
        }
    }
    
    $handle = fopen($file_path, 'r');
    if ($handle === false) {
        return ['success' => false, 'message' => 'Dosya açılamadı'];
    }
    
    // İlk satırı oku (başlık) - Esnek başlık desteği
    $header = fgetcsv($handle, 2000, ';');
    if ($header === false) {
        fclose($handle);
        return ['success' => false, 'message' => 'Dosya formatı geçersiz'];
    }
    
    // Başlık indekslerini bul (büyük/küçük harf duyarsız)
    $header_map = [];
    foreach ($header as $idx => $h) {
        $h_lower = mb_strtolower(trim($h));
        if (in_array($h_lower, ['ad soyad', 'adsoyad', 'isim', 'name', 'full_name'])) {
            $header_map['full_name'] = $idx;
        } elseif (in_array($h_lower, ['e-posta', 'eposta', 'email', 'e-mail', 'mail'])) {
            $header_map['email'] = $idx;
        } elseif (in_array($h_lower, ['öğrenci no', 'ogrenci no', 'student_id', 'student id', 'numara', 'no'])) {
            $header_map['student_id'] = $idx;
        } elseif (in_array($h_lower, ['telefon', 'phone', 'phone_number', 'tel', 'gsm'])) {
            $header_map['phone_number'] = $idx;
        } elseif (in_array($h_lower, ['kayıt tarihi', 'kayit tarihi', 'registration_date', 'registration date', 'tarih', 'date'])) {
            $header_map['registration_date'] = $idx;
        } elseif (in_array($h_lower, ['bölüm', 'bolum', 'department', 'fakülte', 'fakulte'])) {
            $header_map['department'] = $idx;
        } elseif (in_array($h_lower, ['sınıf', 'sinif', 'class', 'class_year', 'class year', 'sınıf yılı'])) {
            $header_map['class_year'] = $idx;
        } elseif (in_array($h_lower, ['doğum tarihi', 'dogum tarihi', 'birth_date', 'birth date', 'doğum'])) {
            $header_map['birth_date'] = $idx;
        } elseif (in_array($h_lower, ['adres', 'address'])) {
            $header_map['address'] = $idx;
        } elseif (in_array($h_lower, ['notlar', 'not', 'notes', 'açıklama', 'aciklama'])) {
            $header_map['notes'] = $idx;
        }
    }
    
    // Zorunlu alanları kontrol et
    if (!isset($header_map['full_name']) || !isset($header_map['email'])) {
        fclose($handle);
        return ['success' => false, 'message' => 'Dosyada "Ad Soyad" ve "E-posta" kolonları bulunamadı'];
    }
    
    $line_number = 1;
    while (($data = fgetcsv($handle, 2000, ';')) !== false) {
        $line_number++;
        
        // Boş satırları atla
        if (count(array_filter($data)) === 0) {
            continue;
        }
        
        // Verileri al
        $full_name = isset($header_map['full_name']) ? trim($data[$header_map['full_name']] ?? '') : '';
        $email = isset($header_map['email']) ? trim($data[$header_map['email']] ?? '') : '';
        $student_id = isset($header_map['student_id']) ? trim($data[$header_map['student_id']] ?? '') : '';
        $phone_number = isset($header_map['phone_number']) ? trim($data[$header_map['phone_number']] ?? '') : '';
        $registration_date = isset($header_map['registration_date']) ? trim($data[$header_map['registration_date']] ?? '') : date('Y-m-d');
        $department = isset($header_map['department']) ? trim($data[$header_map['department']] ?? '') : '';
        $class_year = isset($header_map['class_year']) ? trim($data[$header_map['class_year']] ?? '') : '';
        $birth_date = isset($header_map['birth_date']) ? trim($data[$header_map['birth_date']] ?? '') : '';
        $address = isset($header_map['address']) ? trim($data[$header_map['address']] ?? '') : '';
        $notes = isset($header_map['notes']) ? trim($data[$header_map['notes']] ?? '') : '';
        
        // Validasyon
        if (empty($full_name) || empty($email)) {
            $errors[] = "Satır $line_number: Ad Soyad ve E-posta zorunludur";
            continue;
        }
        
        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            $errors[] = "Satır $line_number: Geçersiz e-posta adresi: $email";
            continue;
        }
        
        // Tarih formatını düzelt
        if (!empty($registration_date) && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $registration_date)) {
            $timestamp = strtotime($registration_date);
            if ($timestamp !== false) {
                $registration_date = date('Y-m-d', $timestamp);
            } else {
                $registration_date = date('Y-m-d');
            }
        }
        
        if (!empty($birth_date) && !preg_match('/^\d{4}-\d{2}-\d{2}$/', $birth_date)) {
            $timestamp = strtotime($birth_date);
            if ($timestamp !== false) {
                $birth_date = date('Y-m-d', $timestamp);
            } else {
                $birth_date = '';
            }
        }
        
        // E-posta zaten var mı kontrol et
        $check_stmt = $db->prepare("SELECT id FROM members WHERE club_id = ? AND email = ?");
        $check_stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
        $check_stmt->bindValue(2, $email, SQLITE3_TEXT);
        $check_result = $check_stmt->execute();
        $existing = $check_result->fetchArray();
        
        if ($existing) {
            // Güncelle
            $stmt = $db->prepare("UPDATE members SET 
                full_name = ?, 
                student_id = ?, 
                phone_number = ?, 
                registration_date = ?,
                department = ?,
                class_year = ?,
                birth_date = ?,
                address = ?,
                notes = ?
            WHERE club_id = ? AND email = ?");
            $stmt->bindValue(1, $full_name, SQLITE3_TEXT);
            $stmt->bindValue(2, $student_id, SQLITE3_TEXT);
            $stmt->bindValue(3, $phone_number, SQLITE3_TEXT);
            $stmt->bindValue(4, $registration_date, SQLITE3_TEXT);
            $stmt->bindValue(5, $department, SQLITE3_TEXT);
            $stmt->bindValue(6, $class_year, SQLITE3_TEXT);
            $stmt->bindValue(7, $birth_date, SQLITE3_TEXT);
            $stmt->bindValue(8, $address, SQLITE3_TEXT);
            $stmt->bindValue(9, $notes, SQLITE3_TEXT);
            $stmt->bindValue(10, CLUB_ID, SQLITE3_INTEGER);
            $stmt->bindValue(11, $email, SQLITE3_TEXT);
            
            if ($stmt->execute()) {
                $updated++;
                clear_entity_cache('members');
            } else {
                $errors[] = "Satır $line_number: Güncelleme hatası";
            }
        } else {
            // Yeni ekle
            $stmt = $db->prepare("INSERT INTO members (
                club_id, full_name, email, student_id, phone_number, registration_date,
                department, class_year, birth_date, address, notes
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)");
            $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
            $stmt->bindValue(2, $full_name, SQLITE3_TEXT);
            $stmt->bindValue(3, $email, SQLITE3_TEXT);
            $stmt->bindValue(4, $student_id, SQLITE3_TEXT);
            $stmt->bindValue(5, $phone_number, SQLITE3_TEXT);
            $stmt->bindValue(6, $registration_date, SQLITE3_TEXT);
            $stmt->bindValue(7, $department, SQLITE3_TEXT);
            $stmt->bindValue(8, $class_year, SQLITE3_TEXT);
            $stmt->bindValue(9, $birth_date, SQLITE3_TEXT);
            $stmt->bindValue(10, $address, SQLITE3_TEXT);
            $stmt->bindValue(11, $notes, SQLITE3_TEXT);
            
            if ($stmt->execute()) {
                $imported++;
                clear_entity_cache('members');
            } else {
                $errors[] = "Satır $line_number: Veritabanı hatası: " . $db->lastErrorMsg();
            }
        }
    }
    
    fclose($handle);
    
    $total = $imported + $updated;
    $message = "$total işlem tamamlandı";
    if ($imported > 0) $message .= " ($imported yeni üye eklendi)";
    if ($updated > 0) $message .= " ($updated üye güncellendi)";
    if (count($errors) > 0) $message .= ". " . count($errors) . " hata oluştu.";
    
    return [
        'success' => true,
        'imported' => $imported,
        'updated' => $updated,
        'errors' => $errors,
        'message' => $message
    ];
}


function import_events_csv($file_path) {
    $db = get_db();
    $imported = 0;
    $errors = [];
    
    // Güvenlik: Path validation - sadece geçici upload klasöründen dosya kabul et
    $real_file_path = realpath($file_path);
    if ($real_file_path === false || !file_exists($file_path)) {
        return ['success' => false, 'message' => 'Dosya bulunamadı'];
    }
    
    // Güvenlik: Dosya gerçekten geçici klasör içinde mi kontrol et
    $temp_dir = sys_get_temp_dir();
    $real_temp_dir = realpath($temp_dir);
    if ($real_temp_dir && strpos($real_file_path, $real_temp_dir) !== 0) {
        // Alternatif: community path içinde olabilir (upload edilmiş dosya)
        $real_community_path = realpath(community_path(''));
        if (!$real_community_path || strpos($real_file_path, $real_community_path) !== 0) {
            return ['success' => false, 'message' => 'Geçersiz dosya yolu'];
        }
    }
    
    $handle = fopen($file_path, 'r');
    if ($handle === false) {
        return ['success' => false, 'message' => 'Dosya açılamadı'];
    }
    
    // İlk satırı atla (başlık)
    $header = fgetcsv($handle, 1000, ';');
    if ($header === false) {
        fclose($handle);
        return ['success' => false, 'message' => 'Dosya formatı geçersiz'];
    }
    
    $line_number = 1;
    while (($data = fgetcsv($handle, 1000, ';')) !== false) {
        $line_number++;
        
        if (count($data) < 3) {
            $errors[] = "Satır $line_number: Yetersiz veri";
            continue;
        }
        
        $title = trim($data[0] ?? '');
        $date = trim($data[1] ?? '');
        $time = trim($data[2] ?? '12:00');
        $location = trim($data[3] ?? '');
        $category = trim($data[4] ?? 'Genel');
        $status = trim($data[5] ?? 'planlanıyor');
        $description = trim($data[6] ?? '');
        
        if (empty($title) || empty($date) || empty($time)) {
            $errors[] = "Satır $line_number: Başlık, Tarih ve Saat zorunludur";
            continue;
        }
        
        // Etkinlik ekle
        $stmt = $db->prepare("INSERT INTO events (club_id, title, date, time, location, category, status, description) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(2, $title, SQLITE3_TEXT);
        $stmt->bindValue(3, $date, SQLITE3_TEXT);
        $stmt->bindValue(4, $time, SQLITE3_TEXT);
        $stmt->bindValue(5, $location, SQLITE3_TEXT);
        $stmt->bindValue(6, $category, SQLITE3_TEXT);
        $stmt->bindValue(7, $status, SQLITE3_TEXT);
        $stmt->bindValue(8, $description, SQLITE3_TEXT);
        
        if ($stmt->execute()) {
            $imported++;
            clear_entity_cache('events');
        } else {
            $errors[] = "Satır $line_number: Veritabanı hatası";
        }
    }
    
    fclose($handle);
    
    return [
        'success' => true,
        'imported' => $imported,
        'errors' => $errors,
        'message' => "$imported etkinlik başarıyla eklendi. " . (count($errors) > 0 ? count($errors) . " hata oluştu." : "")
    ];
}


function download_sample_members_csv() {
    $filename = 'ornek_uyeler.csv';
    
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $output = fopen('php://output', 'w');
    
    // BOM ekle (Excel için UTF-8 desteği)
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // Başlık satırı - Tüm alanları dahil et
    fputcsv($output, [
        'Ad Soyad',
        'E-posta',
        'Öğrenci No',
        'Telefon',
        'Kayıt Tarihi',
        'Bölüm',
        'Sınıf',
        'Doğum Tarihi',
        'Adres',
        'Notlar'
    ], ';');
    
    // Örnek veriler - Tüm alanları doldur
    $examples = [
        [
            'Ahmet Yılmaz',
            'ahmet.yilmaz@university.edu.tr',
            '2021001',
            '05551234567',
            date('Y-m-d'),
            'Bilgisayar Mühendisliği',
            '3',
            '2000-05-15',
            'İstanbul, Kadıköy',
            'Aktif üye, etkinliklere katılıyor'
        ],
        [
            'Ayşe Demir',
            'ayse.demir@university.edu.tr',
            '2021002',
            '05559876543',
            date('Y-m-d'),
            'Elektrik-Elektronik Mühendisliği',
            '2',
            '2001-08-20',
            'Ankara, Çankaya',
            'Yeni üye'
        ],
        [
            'Mehmet Kaya',
            'mehmet.kaya@university.edu.tr',
            '2021003',
            '05555555555',
            date('Y-m-d'),
            'Endüstri Mühendisliği',
            '4',
            '1999-12-10',
            'İzmir, Bornova',
            'Yönetim kurulu üyesi'
        ],
    ];
    
    foreach ($examples as $row) {
        fputcsv($output, $row, ';');
    }
    
    fclose($output);
    exit;
}


function download_sample_events_csv() {
    $filename = 'ornek_etkinlikler.csv';
    
    header('Content-Type: text/csv; charset=utf-8');
    header('Content-Disposition: attachment; filename="' . $filename . '"');
    header('Pragma: no-cache');
    header('Expires: 0');
    
    $output = fopen('php://output', 'w');
    
    // BOM ekle
    fprintf($output, chr(0xEF).chr(0xBB).chr(0xBF));
    
    // Başlık satırı
    fputcsv($output, ['Başlık', 'Tarih', 'Saat', 'Konum', 'Kategori', 'Durum', 'Açıklama'], ';');
    
    // Örnek veriler
    $examples = [
        ['Yeni Dönem Tanışma Toplantısı', date('Y-m-d', strtotime('+7 days')), '14:00', 'Konferans Salonu', 'Toplantı', 'planlanıyor', 'Yeni dönem için tanışma ve bilgilendirme toplantısı'],
        ['Teknoloji Semineri', date('Y-m-d', strtotime('+14 days')), '16:00', 'Amfi 1', 'Seminer', 'planlanıyor', 'Güncel teknoloji trendleri hakkında seminer'],
        ['Sosyal Etkinlik', date('Y-m-d', strtotime('+21 days')), '18:00', 'Kampüs Bahçesi', 'Sosyal', 'planlanıyor', 'Üyeler arası kaynaşma etkinliği'],
    ];
    
    foreach ($examples as $row) {
        fputcsv($output, $row, ';');
    }
    
    fclose($output);
    exit;
}


function generate_pdf_report() {
    $db = get_db();
    $club_name = get_club_name($db);
    
    // Deneme süresi bilgilerini al
    $trial_start_date = get_setting('trial_start_date', date('Y-m-d'));
    $trial_start_timestamp = strtotime($trial_start_date);
    $current_timestamp = time();
    $days_passed = floor(($current_timestamp - $trial_start_timestamp) / (60 * 60 * 24));
    $days_remaining = max(0, 365 - $days_passed);
    $trial_end_date = date('Y-m-d', strtotime($trial_start_date . ' +365 days'));
    $stats = get_stats();
    $attendance_monthly = get_event_attendance_monthly();
    $member_growth = get_member_growth();
    
    // Basit HTML to PDF (tarayıcı print özelliği kullanılabilir)
    $html = '<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <title>UniPanel Rapor - ' . htmlspecialchars($club_name) . '</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #1a202c; border-bottom: 3px solid #6366f1; padding-bottom: 10px; }
        h2 { color: #2d3748; margin-top: 30px; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { border: 1px solid #e2e8f0; padding: 12px; text-align: left; }
        th { background-color: #6366f1; color: white; font-weight: bold; }
        .stat-box { display: inline-block; margin: 10px; padding: 15px; background: #f7fafc; border: 1px solid #e2e8f0; border-radius: 8px; }
        .stat-value { font-size: 24px; font-weight: bold; color: #6366f1; }
        .stat-label { color: #718096; font-size: 14px; }
    </style>
</head>
<body>
    <h1>📊 ' . htmlspecialchars($club_name) . ' - Rapor</h1>
    <p><strong>Rapor Tarihi:</strong> ' . date('d.m.Y H:i') . '</p>
    
    <h2>📈 Genel İstatistikler</h2>
    <div class="stat-box">
        <div class="stat-value">' . $stats['total_members'] . '</div>
        <div class="stat-label">Toplam Üye</div>
    </div>
    <div class="stat-box">
        <div class="stat-value">' . $stats['total_events'] . '</div>
        <div class="stat-label">Toplam Etkinlik</div>
    </div>
    <div class="stat-box">
        <div class="stat-value">' . $stats['upcoming_events'] . '</div>
        <div class="stat-label">Yaklaşan Etkinlik</div>
    </div>
    <div class="stat-box">
        <div class="stat-value">' . $stats['board_members'] . '</div>
        <div class="stat-label">Yönetim Kurulu</div>
    </div>
    
    <h2>📅 Son 12 Ay Etkinlik Katılımı</h2>
    <table>
        <tr><th>Ay</th><th>Katılım Sayısı</th></tr>';
    
    foreach ($attendance_monthly as $month_data) {
        $html .= '<tr><td>' . htmlspecialchars($month_data['month']) . '</td><td>' . $month_data['count'] . '</td></tr>';
    }
    
    $html .= '</table>
    
    <h2>👥 Son 12 Ay Üye Büyümesi</h2>
    <table>
        <tr><th>Ay</th><th>Yeni Üye</th></tr>';
    
    foreach ($member_growth as $growth_data) {
        $html .= '<tr><td>' . htmlspecialchars($growth_data['month']) . '</td><td>' . $growth_data['count'] . '</td></tr>';
    }
    
    $html .= '</table>
    
    <p style="margin-top: 40px; color: #718096; font-size: 12px;">
        Bu rapor UniPanel tarafından otomatik olarak oluşturulmuştur.<br>
        ' . htmlspecialchars($club_name) . ' - ' . date('Y') . '
    </p>
</body>
</html>';
    
    header('Content-Type: text/html; charset=utf-8');
    header('Content-Disposition: inline; filename="rapor_' . date('Y-m-d_His') . '.html"');
    echo $html;
    exit;
}

// Finans Yönetimi Fonksiyonları

