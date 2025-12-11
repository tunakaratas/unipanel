<?php

if (!function_exists('tpl_validate_string')) {
    require_once __DIR__ . '/validation.php';
}
/**
 * Communication Module - Lazy Loaded
 */

/**
 * Load credentials from config file
 * Returns SMTP and NetGSM credentials
 */
function load_credentials() {
    static $credentials = null;
    
    if ($credentials === null) {
        // Define PROJECT_ROOT if not already defined (for login page compatibility)
        if (!defined('PROJECT_ROOT')) {
            // Detect project root from current file location
            $current_dir = __DIR__;
            // Go up from templates/functions/ to project root
            $project_root = dirname(dirname($current_dir));
            define('PROJECT_ROOT', $project_root);
        }
        
        $config_path = PROJECT_ROOT . '/config/credentials.php';
        
        if (file_exists($config_path)) {
            $credentials = require $config_path;
        } else {
            // Fallback to empty arrays if config doesn't exist
            $credentials = [
                'smtp' => [
                    'host' => '',
                    'port' => 587,
                    'username' => '',
                    'password' => '',
                    'from_email' => '',
                    'from_name' => '',
                    'encryption' => 'tls'
                ],
                'netgsm' => [
                    'username' => '',
                    'password' => '',
                    'msgheader' => ''
                ]
            ];
        }
    }
    
    return $credentials;
}

/**
 * Get SMTP credential value
 */
function get_smtp_credential($key, $default = '') {
    $creds = load_credentials();
    return $creds['smtp'][$key] ?? $default;
}

/**
 * Get NetGSM credential value
 */
function get_netgsm_credential($key, $default = '') {
    try {
        // SMS özelliği kontrolü - hata durumunda devam et (superadmin için gerekli olabilir)
        $isAllowed = true;
        if (!function_exists('has_subscription_feature')) {
            require_once __DIR__ . '/../../lib/general/subscription_helper.php';
        }
        if (defined('COMMUNITY_ID') && COMMUNITY_ID) {
            try {
                $isAllowed = has_subscription_feature('sms');
            } catch (Throwable $e) {
                // Hata durumunda devam et (superadmin için gerekli olabilir)
                $isAllowed = true; // Superadmin için her zaman true
                tpl_error_log('NetGSM credential subscription check error: ' . $e->getMessage());
            }
        }
        
        if (!$isAllowed) {
            tpl_error_log('NetGSM credential access denied - SMS feature not available');
            return $default;
        }

        // Öncelik 1: Superadmin config'den oku
        $superadminConfigPath = dirname(__DIR__, 2) . '/superadmin/config.php';
        if (file_exists($superadminConfigPath)) {
            try {
                $superadminConfig = require $superadminConfigPath;
                if (isset($superadminConfig['netgsm']) && is_array($superadminConfig['netgsm'])) {
                    $netgsmConfig = $superadminConfig['netgsm'];
                    // Key mapping: username -> user, password -> pass, msgheader -> header
                    $mapping = [
                        'username' => 'user',
                        'password' => 'pass',
                        'msgheader' => 'header'
                    ];
                    $superadminKey = $mapping[$key] ?? $key;
                    if (isset($netgsmConfig[$superadminKey]) && !empty($netgsmConfig[$superadminKey])) {
                        $value = trim((string)$netgsmConfig[$superadminKey]);
                        if (!empty($value)) {
                            tpl_error_log('NetGSM credential loaded from superadmin config: ' . $key . ' = ' . (strlen($value) > 0 ? 'SET (' . strlen($value) . ' chars)' : 'EMPTY'));
                            return $value;
                        }
                    }
                }
            } catch (Throwable $e) {
                // Hata durumunda devam et
                tpl_error_log('Superadmin config okuma hatası: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
            }
        }

        // Öncelik 2: config/credentials.php'den oku
        try {
            $creds = load_credentials();
            if (isset($creds['netgsm']) && is_array($creds['netgsm']) && isset($creds['netgsm'][$key])) {
                $value = trim((string)($creds['netgsm'][$key] ?? ''));
                if (!empty($value)) {
                    tpl_error_log('NetGSM credential loaded from credentials.php: ' . $key . ' = ' . (strlen($value) > 0 ? 'SET (' . strlen($value) . ' chars)' : 'EMPTY'));
                    return $value;
                }
            }
        } catch (Throwable $e) {
            tpl_error_log('Credentials.php okuma hatası: ' . $e->getMessage());
        }
        
        tpl_error_log('NetGSM credential not found: ' . $key . ' (returning default)');
        return $default;
    } catch (Throwable $e) {
        tpl_error_log('NetGSM credential get error: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
        error_log('NetGSM credential get error: ' . $e->getMessage());
        return $default;
    }
}


function save_smtp_settings($post) {
    try {
        $db = get_db();
		$fields = [
			'smtp_username',
			'smtp_password',
			'smtp_host',
			'smtp_port',
			'smtp_secure',
			'smtp_from_email',
			'smtp_from_name',
		];

		$anyProvided = false;
		foreach ($fields as $key) {
			if (isset($post[$key]) && $post[$key] !== '') {
				$anyProvided = true;
				$stmt = $db->prepare("INSERT OR REPLACE INTO settings (club_id, setting_key, setting_value) VALUES (?, ?, ?)");
        $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
				$stmt->bindValue(2, $key, SQLITE3_TEXT);
				$stmt->bindValue(3, trim((string)$post[$key]), SQLITE3_TEXT);
        $stmt->execute();
			}
		}

		if (!$anyProvided) {
			echo "HATA: Kaydedilecek SMTP alanı bulunamadı.";
			exit;
		}
        
        echo "BAŞARILI: SMTP ayarları kaydedildi!";
    } catch (Exception $e) {
        echo "HATA: " . $e->getMessage();
    }
    exit;
}


function send_test_email() {
    try {
        // Veritabanından SMTP ayarlarını al
        $smtp_username = get_setting('smtp_username', '');
        $smtp_password = get_setting('smtp_password', '');
        $smtp_host = get_setting('smtp_host', '');
        $smtp_port = get_setting('smtp_port', '587');
        $smtp_secure = get_setting('smtp_secure', 'tls');
        $smtp_from_email = get_setting('smtp_from_email', $smtp_username);
        $smtp_from_name = get_setting('smtp_from_name', get_setting('club_name', 'Topluluk'));
        
        // Eğer veritabanında yoksa config dosyasından al (fallback)
        if (empty($smtp_username)) {
            $smtp_username = get_smtp_credential('username');
        }
        if (empty($smtp_password)) {
            $smtp_password = get_smtp_credential('password');
        }
        if (empty($smtp_host)) {
            $smtp_host = get_smtp_credential('host', 'ms7.guzel.net.tr');
        }
        if (empty($smtp_port)) {
            $smtp_port = get_smtp_credential('port', '587');
        }
        if (empty($smtp_secure)) {
            $smtp_secure = get_smtp_credential('encryption', 'tls');
        }
        if (empty($smtp_from_email)) {
            $smtp_from_email = get_smtp_credential('from_email', $smtp_username);
        }
        if (empty($smtp_from_name)) {
            $smtp_from_name = get_smtp_credential('from_name', get_setting('club_name', 'Topluluk'));
        }
        
        $requested_to = '';
        if (!empty($_POST['test_email'])) {
            $candidate = trim((string)$_POST['test_email']);
            if (filter_var($candidate, FILTER_VALIDATE_EMAIL)) {
                $requested_to = $candidate;
            }
        }

        $configured_recipient = get_setting('smtp_test_recipient', '');
        if ($configured_recipient && !filter_var($configured_recipient, FILTER_VALIDATE_EMAIL)) {
            $configured_recipient = '';
        }

        $to = $requested_to
            ?: $configured_recipient
            ?: ($smtp_from_email && filter_var($smtp_from_email, FILTER_VALIDATE_EMAIL) ? $smtp_from_email : '');

        if (empty($to)) {
            $fallbackUser = $smtp_username && filter_var($smtp_username, FILTER_VALIDATE_EMAIL) ? $smtp_username : '';
            if ($fallbackUser) {
                $to = $fallbackUser;
            }
        }

        if (empty($to) || !filter_var($to, FILTER_VALIDATE_EMAIL)) {
            echo "HATA: Test e-postası göndermek için geçerli bir alıcı adresi bulunamadı. Lütfen 'Gönderen E-posta' alanını doldurun veya geçerli bir adres girin.";
            exit;
        }
        
        $subject = 'SMTP TEST - ' . date('Y-m-d H:i:s');
        $message = 'Bu bir test mailidir. SMTP ayarlarınız çalışıyor gibi görünüyor.';
        
        // Debug bilgilerini ekrana yazdır
        $debug_info = "=== MAIL DEBUG ===\n";
        $debug_info .= "TO: $to\n";
        $debug_info .= "SUBJECT: $subject\n";
        $debug_info .= "FROM: $smtp_from_email\n";
        $debug_info .= "FROM NAME: $smtp_from_name\n";
        $debug_info .= "SMTP HOST: $smtp_host\n";
        $debug_info .= "SMTP PORT: $smtp_port\n";
        $debug_info .= "SMTP SECURE: $smtp_secure\n";
        
        // SMTP ayarları ile mail gönder
        $mail_sent = send_smtp_mail($to, $subject, $message, $smtp_from_name, $smtp_from_email, [
            'host' => $smtp_host,
            'port' => (int)$smtp_port,
            'secure' => $smtp_secure,
            'username' => $smtp_username,
            'password' => $smtp_password,
        ]);
        
        // Son error log'ları kontrol et
        $error_log_file = ini_get('error_log');
        $last_errors = '';
        if ($error_log_file && file_exists($error_log_file)) {
            $lines = file($error_log_file);
            $last_errors = implode("\n", array_slice($lines, -10)); // Son 10 satır
        }
        
        if ($mail_sent) {
            echo "BAŞARILI: Test maili gönderildi! $to adresine kontrol edin.\n\nDEBUG:\n$debug_info";
        } else {
            $error_details = "HATA: Test maili gönderilemedi!\n\n";
            $error_details .= "DEBUG BİLGİLERİ:\n$debug_info\n\n";
            $error_details .= "OLASI SORUNLAR:\n";
            $error_details .= "1. SMTP sunucusuna bağlanılamıyor olabilir\n";
            $error_details .= "2. Kullanıcı adı veya şifre yanlış olabilir\n";
            $error_details .= "3. Port veya şifreleme tipi yanlış olabilir\n";
            $error_details .= "4. Firewall veya güvenlik duvarı engelliyor olabilir\n\n";
            if (!empty($last_errors)) {
                $error_details .= "SON HATA LOGLARI:\n" . $last_errors . "\n";
            }
            $error_details .= "\nLütfen error.log dosyasını kontrol edin: " . ($error_log_file ?: 'PHP error_log ayarı kontrol edin');
            echo $error_details;
        }
    } catch (Exception $e) {
        echo "HATA: " . $e->getMessage() . "\n\nStack Trace:\n" . $e->getTraceAsString();
    }
    exit;
}


function test_smtp_connection($post) {
    $username = $post['smtp_username'] ?? '';
    $password = $post['smtp_password'] ?? '';
    $host = $post['smtp_host'] ?? get_smtp_credential('host', 'smtp.gmail.com');
    $port = (int)($post['smtp_port'] ?? get_smtp_credential('port', 587));
    $secure = strtolower(trim($post['smtp_secure'] ?? get_smtp_credential('encryption', 'tls')));
    
    if (empty($username) || empty($password) || empty($host)) {
        echo "HATA: SMTP host, kullanıcı adı ve şifre zorunludur!";
        exit;
    }
    
    $to = $username;
    $subject = "SMTP Test - " . date('Y-m-d H:i:s');
    $message = "Bu bir test mailidir. SMTP ayarları çalışıyor!";
    
    $fromEmail = $post['smtp_from_email'] ?? get_smtp_credential('from_email', $username);
    $fromName = $post['smtp_from_name'] ?? get_smtp_credential('from_name', get_setting('club_name', 'Topluluk'));

    // Önce mevcut ayarla dene; olmazsa TLS:587 ve SSL:465 fallback yap
    $ok = send_smtp_mail($to, $subject, $message, $fromName, $fromEmail, [
        'host' => $host ?: 'mail.guzel.net.tr',
        'port' => $port ?: 587,
        'secure' => $secure ?: 'tls',
        'username' => $username,
        'password' => $password,
    ]);

    if (!$ok) {
        // Aynı host üzerinde TLS 587 denemesi
        $ok = send_smtp_mail($to, $subject, $message, $fromName, $fromEmail, [
            'host' => $host ?: 'mail.guzel.net.tr',
            'port' => 587,
            'secure' => 'tls',
            'username' => $username,
            'password' => $password,
        ]);
    }
    if (!$ok) {
        // SSL 465 fallback
        $ok = send_smtp_mail($to, $subject, $message, $fromName, $fromEmail, [
            'host' => $host ?: 'mail.guzel.net.tr',
            'port' => 465,
            'secure' => 'ssl',
            'username' => $username,
            'password' => $password,
        ]);
    }

    echo $ok ? "BAŞARILI: Test maili gönderildi!" : "HATA: Test maili gönderilemedi! Ayrıntılar için error.log'a bakın.";
    exit;
}

// Email kuyruğuna ekleme fonksiyonu

function handle_send_email($post) {
    try {
        $db = get_db();
        
        // Paket kontrolü - Email gönderimi için Professional paketi gerekli
        if (!function_exists('require_subscription_feature')) {
            require_once __DIR__ . '/../../lib/general/subscription_guard.php';
        }
        
        if (!require_subscription_feature('email', 'professional')) {
            // Sayfa gösterildi ve çıkış yapıldı
            return;
        }
        
        // Email tablolarını oluştur
        ensure_email_tables($db);
        
        $club_name = get_setting('club_name', 'Topluluk');
        
        // SMTP ayarlarını al - önce veritabanından, yoksa config'den
        $smtp_username = get_setting('smtp_username', '') ?: get_smtp_credential('username');
        $smtp_password = get_setting('smtp_password', '') ?: get_smtp_credential('password');
        $smtp_host = get_setting('smtp_host', '') ?: get_smtp_credential('host', 'ms7.guzel.net.tr');
        $smtp_port = (int)(get_setting('smtp_port', '587') ?: get_smtp_credential('port', 587));
        $smtp_secure = strtolower(trim(get_setting('smtp_secure', 'tls') ?: get_smtp_credential('encryption', 'tls')));
        
        // Güvenlik: Hardcoded credentials kaldırıldı
        if (empty($smtp_username) || empty($smtp_password)) {
            tpl_error_log('SMTP credentials not configured. Email sending disabled. Please configure SMTP settings in admin panel.');
            // SMTP ayarları boşsa email gönderilemez
            return false;
        }
        
        // Alıcıları belirle
        $recipients = [];
        if (!empty($post['selected_emails_json'])) {
            $decodedEmails = json_decode($post['selected_emails_json'], true);
            if (is_array($decodedEmails)) {
                $recipients = array_merge($recipients, $decodedEmails);
            }
        }
        if (isset($post['selected_emails']) && is_array($post['selected_emails'])) {
            $recipients = array_merge($recipients, $post['selected_emails']);
        }
        if (isset($post['recipients']) && $post['recipients'] === 'Tüm Üyeler') {
            $allContacts = get_email_member_contacts();
            foreach ($allContacts as $contact) {
                if (is_array($contact) && !empty($contact['email'])) {
                    $recipients[] = $contact['email'];
                } elseif (is_string($contact) && trim($contact) !== '') {
                    $recipients[] = $contact;
                }
            }
        }

        $recipients = array_values(array_unique(array_filter(array_map(function($email) {
            return trim((string)$email);
        }, $recipients))));
        
        if (empty($recipients)) {
            $_SESSION['error'] = "Alıcı seçilmedi!";
            return;
        }
        
        try {
            $subject = tpl_validate_string($post['email_subject'] ?? '', [
                'field' => 'E-posta konusu',
                'min' => 3,
                'max' => 180,
            ]);
            $message = tpl_validate_string($post['email_body'] ?? '', [
                'field' => 'E-posta içeriği',
                'min' => 10,
                'max' => 20000,
                'strip_tags' => false,
            ]);
        } catch (TplValidationException $validationException) {
            $_SESSION['error'] = $validationException->getMessage();
            return;
        }
        
        $fromEmail = get_setting('smtp_from_email', '') ?: get_smtp_credential('from_email', $smtp_username);
        $fromName = get_setting('smtp_from_name', '') ?: get_smtp_credential('from_name', $club_name);
        
        // Email içeriğini validate et
        $content_validation = validate_email_content($subject, $message);
        if (!$content_validation['valid']) {
            $_SESSION['error'] = "Email içeriği geçersiz: " . implode(', ', $content_validation['errors']);
            return;
        }
        
        // Geçerli email adreslerini filtrele ve validate et
        $valid_recipients = [];
        $invalid_emails = [];
        foreach ($recipients as $email) {
            $validation = validate_and_normalize_email($email);
            if ($validation['valid']) {
                $valid_recipients[] = $validation['email'];
            } else {
                $invalid_emails[] = $email . ' (' . $validation['error'] . ')';
            }
        }
        
        if (empty($valid_recipients)) {
            $error_msg = "Geçerli e-posta adresi bulunamadı!";
            if (!empty($invalid_emails)) {
                $error_msg .= " Geçersiz adresler: " . implode(', ', array_slice($invalid_emails, 0, 5));
            }
            $_SESSION['error'] = $error_msg;
            return;
        }
        
        // Duplicate email kontrolü (aynı kampanyada aynı email'e tekrar gönderilmesini önle)
        // Not: Bu kontrol kampanya oluşturulduktan sonra yapılacak
        
        // Kampanya oluştur
        $campaign_id = create_email_campaign($db, $subject, $message, $fromName, $fromEmail, count($valid_recipients));
        
        // Email gönderimini logla
        if (isset($_SESSION['admin_id']) && isset($_SESSION['admin_username'])) {
            logToSuperAdmin('admin_action', [
                'user_id' => $_SESSION['admin_id'],
                'username' => $_SESSION['admin_username'],
                'action_type' => 'email_send',
                'action_description' => 'E-posta kampanyası oluşturuldu: ' . $subject . ' (' . count($valid_recipients) . ' alıcı)',
                'additional_data' => [
                    'campaign_id' => $campaign_id,
                    'subject' => $subject,
                    'recipient_count' => count($valid_recipients),
                    'recipients' => array_slice($valid_recipients, 0, 10), // İlk 10 alıcı
                    'message_preview' => mb_substr(strip_tags($message), 0, 200) . (mb_strlen(strip_tags($message)) > 200 ? '...' : ''),
                    'message_full' => $message, // Tam mesaj içeriği
                    'from_email' => $fromEmail,
                    'from_name' => $fromName
                ]
            ]);
        }
        
        $member_name_map = get_member_names_for_emails($valid_recipients);
        
        // Tüm alıcıları kuyruğa ekle
        $queue_count = 0;
        $queue_entries = [];
        foreach ($valid_recipients as $email) {
            $member_name = $member_name_map[strtolower($email)] ?? null;
            $personalized = personalize_email_content($subject, $message, $member_name, $email, $club_name);
            $queue_id = add_email_to_queue($db, $campaign_id, $email, $personalized['subject'], $personalized['message'], $fromName, $fromEmail, $member_name);
            if ($queue_id) {
                $queue_count++;
                $queue_entries[] = [
                    'id' => $queue_id,
                    'email' => $email,
                    'subject' => $personalized['subject'],
                    'message' => $personalized['message'],
                    'recipient_name' => $member_name
                ];
            }
        }
        
        // HEMEN GÖNDER: İlk batch'i hemen gönder
        $first_batch = array_slice($queue_entries, 0, min(20, count($queue_entries)));
        $batch_result = send_smtp_mail_batch($first_batch, $subject, $message, $fromName, $fromEmail, [
            'host' => $smtp_host ?: 'ms7.guzel.net.tr',
            'port' => $smtp_port ?: 587,
            'secure' => $smtp_secure ?: 'tls',
            'username' => $smtp_username,
            'password' => $smtp_password,
        ]);
        
        $immediate_sent = $batch_result['sent'];
        $immediate_failed = $batch_result['failed'];
        $success_ids = $batch_result['success_ids'] ?? [];
        
        // Gönderilen mailleri işaretle
        if (!empty($success_ids)) {
            // Check if email_queue table exists
            $queue_table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='email_queue'");
            if ($queue_table_check && $queue_table_check->fetchArray()) {
                $placeholders = implode(',', array_fill(0, count($success_ids), '?'));
                $stmt = @$db->prepare("UPDATE email_queue SET status = 'sent', sent_at = datetime('now') WHERE campaign_id = ? AND club_id = ? AND id IN ($placeholders)");
                if ($stmt) {
                    $stmt->bindValue(1, $campaign_id, SQLITE3_INTEGER);
                    $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                    foreach ($success_ids as $index => $queue_id) {
                        $stmt->bindValue($index + 3, $queue_id, SQLITE3_INTEGER);
                    }
                    $stmt->execute();
                }
            }
            
            // Kampanya sayacını güncelle
            $campaigns_table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='email_campaigns'");
            if ($campaigns_table_check && $campaigns_table_check->fetchArray()) {
                $stmt = @$db->prepare("UPDATE email_campaigns SET sent_count = sent_count + ?, status = 'processing', started_at = datetime('now') WHERE id = ?");
                if ($stmt) {
                    $stmt->bindValue(1, count($success_ids), SQLITE3_INTEGER);
                    $stmt->bindValue(2, $campaign_id, SQLITE3_INTEGER);
                    $stmt->execute();
                }
            }
        }
        
        // Background worker'ı tetikle (kalan mailler için)
        trigger_email_queue_processor();
        
        $_SESSION['message'] = "📧 E-posta gönderimi başladı! İlk batch: $immediate_sent gönderildi, $queue_count toplam kuyruğa eklendi. Kalan mailler arka planda gönderiliyor...";
        $_SESSION['email_campaign_id'] = $campaign_id;
        
    } catch (Exception $e) {
        $_SESSION['error'] = "Mail gönderme hatası: " . $e->getMessage();
        tpl_error_log('handle_send_email exception: ' . $e->getMessage());
    }
}

// Background worker'ı tetikle (non-blocking)

function handle_send_email_ajax($post) {
    ob_clean();
    try {
        $db = get_db();
        
        // Email tablolarını oluştur
        ensure_email_tables($db);
        
        $club_name = get_setting('club_name', 'Topluluk');
        
        // SMTP ayarlarını al - önce veritabanından, yoksa config'den
        $smtp_username = get_setting('smtp_username', '') ?: get_smtp_credential('username');
        $smtp_password = get_setting('smtp_password', '') ?: get_smtp_credential('password');
        $smtp_host = get_setting('smtp_host', '') ?: get_smtp_credential('host', 'ms7.guzel.net.tr');
        $smtp_port = (int)(get_setting('smtp_port', '587') ?: get_smtp_credential('port', 587));
        $smtp_secure = strtolower(trim(get_setting('smtp_secure', 'tls') ?: get_smtp_credential('encryption', 'tls')));
        
        // Güvenlik: Hardcoded credentials kaldırıldı
        if (empty($smtp_username) || empty($smtp_password)) {
            tpl_error_log('SMTP credentials not configured. Email sending disabled. Please configure SMTP settings in admin panel.');
            // SMTP ayarları boşsa email gönderilemez
            return false;
        }
        
        // Alıcıları belirle
        $recipients = [];
        if (!empty($post['selected_emails_json'])) {
            $decodedEmails = json_decode($post['selected_emails_json'], true);
            if (is_array($decodedEmails)) {
                $recipients = array_merge($recipients, $decodedEmails);
            }
        }
        if (isset($post['selected_emails']) && is_array($post['selected_emails'])) {
            $recipients = array_merge($recipients, $post['selected_emails']);
        }
        if (isset($post['recipients']) && $post['recipients'] === 'Tüm Üyeler') {
            $allContacts = get_email_member_contacts();
            foreach ($allContacts as $contact) {
                if (is_array($contact) && !empty($contact['email'])) {
                    $recipients[] = $contact['email'];
                } elseif (is_string($contact) && trim($contact) !== '') {
                    $recipients[] = $contact;
                }
            }
        }

        $recipients = array_values(array_unique(array_filter(array_map(function($email) {
            return trim((string)$email);
        }, $recipients))));
        
        if (empty($recipients)) {
            echo json_encode(['success' => false, 'message' => 'Alıcı seçilmedi!']);
            exit;
        }
        
        $subject = $post['email_subject'] ?? 'Konu Belirtilmedi';
        $message = $post['email_body'] ?? '';
        
        if (empty($subject) || empty($message)) {
            echo json_encode(['success' => false, 'message' => 'Konu ve mesaj alanları zorunludur!']);
            exit;
        }
        
        $fromEmail = get_setting('smtp_from_email', '') ?: get_smtp_credential('from_email', $smtp_username);
        $fromName = get_setting('smtp_from_name', '') ?: get_smtp_credential('from_name', $club_name);
        
        // Email içeriğini validate et
        $content_validation = validate_email_content($subject, $message);
        if (!$content_validation['valid']) {
            echo json_encode(['success' => false, 'message' => 'Email içeriği geçersiz: ' . implode(', ', $content_validation['errors'])]);
            exit;
        }
        
        // Geçerli email adreslerini filtrele ve validate et
        $valid_recipients = [];
        $invalid_emails = [];
        foreach ($recipients as $email) {
            $validation = validate_and_normalize_email($email);
            if ($validation['valid']) {
                $valid_recipients[] = $validation['email'];
            } else {
                $invalid_emails[] = $email . ' (' . $validation['error'] . ')';
            }
        }
        
        if (empty($valid_recipients)) {
            $error_msg = "Geçerli e-posta adresi bulunamadı!";
            if (!empty($invalid_emails)) {
                $error_msg .= " Geçersiz adresler: " . implode(', ', array_slice($invalid_emails, 0, 5));
            }
            echo json_encode(['success' => false, 'message' => $error_msg]);
            exit;
        }
        
        // Kampanya oluştur
        $campaign_id = create_email_campaign($db, $subject, $message, $fromName, $fromEmail, count($valid_recipients));
        
        // Email gönderimini logla (AJAX için)
        if (isset($_SESSION['admin_id']) && isset($_SESSION['admin_username'])) {
            logToSuperAdmin('admin_action', [
                'user_id' => $_SESSION['admin_id'],
                'username' => $_SESSION['admin_username'],
                'action_type' => 'email_send',
                'action_description' => 'E-posta kampanyası oluşturuldu (AJAX): ' . $subject . ' (' . count($valid_recipients) . ' alıcı)',
                'additional_data' => [
                    'campaign_id' => $campaign_id,
                    'subject' => $subject,
                    'recipient_count' => count($valid_recipients),
                    'recipients' => array_slice($valid_recipients, 0, 10),
                    'message_preview' => mb_substr(strip_tags($message), 0, 200) . (mb_strlen(strip_tags($message)) > 200 ? '...' : ''),
                    'message_full' => $message,
                    'from_email' => $fromEmail,
                    'from_name' => $fromName
                ]
            ]);
        }
        
        $member_name_map = get_member_names_for_emails($valid_recipients);
        
        // Tüm alıcıları kuyruğa ekle
        $queue_count = 0;
        $queue_entries = [];
        foreach ($valid_recipients as $email) {
            $member_name = $member_name_map[strtolower($email)] ?? null;
            $personalized = personalize_email_content($subject, $message, $member_name, $email, $club_name);
            $queue_id = add_email_to_queue($db, $campaign_id, $email, $personalized['subject'], $personalized['message'], $fromName, $fromEmail, $member_name);
            if ($queue_id) {
                $queue_count++;
                $queue_entries[] = [
                    'id' => $queue_id,
                    'email' => $email,
                    'subject' => $personalized['subject'],
                    'message' => $personalized['message'],
                    'recipient_name' => $member_name
                ];
            }
        }
        
        // HEMEN GÖNDER: İlk batch'i hemen gönder (kullanıcı beklemesin)
        $first_batch = array_slice($queue_entries, 0, min(20, count($queue_entries)));
        $batch_result = send_smtp_mail_batch($first_batch, $subject, $message, $fromName, $fromEmail, [
            'host' => $smtp_host ?: 'ms7.guzel.net.tr',
            'port' => $smtp_port ?: 587,
            'secure' => $smtp_secure ?: 'tls',
            'username' => $smtp_username,
            'password' => $smtp_password,
        ]);
        
        $immediate_sent = $batch_result['sent'];
        $immediate_failed = $batch_result['failed'];
        $success_ids = $batch_result['success_ids'] ?? [];
        
        // Gönderilen mailleri işaretle
        if (!empty($success_ids)) {
            // Check if email_queue table exists
            $queue_table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='email_queue'");
            if ($queue_table_check && $queue_table_check->fetchArray()) {
                $placeholders = implode(',', array_fill(0, count($success_ids), '?'));
                $stmt = @$db->prepare("UPDATE email_queue SET status = 'sent', sent_at = datetime('now') WHERE campaign_id = ? AND club_id = ? AND id IN ($placeholders)");
                if ($stmt) {
                    $stmt->bindValue(1, $campaign_id, SQLITE3_INTEGER);
                    $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
                    foreach ($success_ids as $index => $queue_id) {
                        $stmt->bindValue($index + 3, $queue_id, SQLITE3_INTEGER);
                    }
                    $stmt->execute();
                }
            }
            
            // Kampanya sayacını güncelle
            $campaigns_table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='email_campaigns'");
            if ($campaigns_table_check && $campaigns_table_check->fetchArray()) {
                $stmt = @$db->prepare("UPDATE email_campaigns SET sent_count = sent_count + ?, status = 'processing', started_at = datetime('now') WHERE id = ?");
                if ($stmt) {
                    $stmt->bindValue(1, count($success_ids), SQLITE3_INTEGER);
                    $stmt->bindValue(2, $campaign_id, SQLITE3_INTEGER);
                    $stmt->execute();
                }
            }
        }
        
        // Background worker'ı tetikle (kalan mailler için)
        trigger_email_queue_processor();
        
        echo json_encode([
            'success' => true,
            'message' => "📧 E-posta gönderimi başladı! İlk batch: $immediate_sent gönderildi, $queue_count toplam kuyruğa eklendi. Kalan mailler arka planda gönderiliyor...",
            'campaign_id' => $campaign_id,
            'total' => $queue_count,
            'sent' => $immediate_sent,
            'failed' => $immediate_failed
        ]);
        
    } catch (Exception $e) {
        echo json_encode(['success' => false, 'message' => 'E-posta gönderme hatası: ' . $e->getMessage()]);
        tpl_error_log('Email send error: ' . $e->getMessage());
    }
    exit;
}


function get_member_names_for_emails(array $emails) {
    $normalized = [];
    foreach ($emails as $email) {
        $trimmed = strtolower(trim((string)$email));
        if ($trimmed !== '') {
            $normalized[$trimmed] = true;
        }
    }
    
    if (empty($normalized)) {
        return [];
    }
    
    $db = get_db();
    $placeholders = implode(',', array_fill(0, count($normalized), '?'));
    $query = "SELECT LOWER(email) AS email_key, full_name FROM members WHERE club_id = ? AND LOWER(email) IN ($placeholders)";
    $stmt = $db->prepare($query);
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $index = 2;
    foreach (array_keys($normalized) as $emailKey) {
        $stmt->bindValue($index++, $emailKey, SQLITE3_TEXT);
    }
    
    $result = $stmt->execute();
    $map = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $map[$row['email_key']] = trim((string)($row['full_name'] ?? ''));
    }
    
    return $map;
}

function personalize_email_content($subject, $message, ?string $member_name, string $member_email, string $club_name) {
    $display_name = trim((string)$member_name);
    if ($display_name === '') {
        $display_name = 'Üyemiz';
    }
    
    $first_name = $display_name;
    if (strpos($display_name, ' ') !== false) {
        $first_name = trim(strtok($display_name, ' '));
    }
    
    $replacements = [
        '{{member_name}}' => $display_name,
        '{{uye_adi}}' => $display_name,
        '{{member_first_name}}' => $first_name,
        '{{member_email}}' => $member_email,
        '{{club_name}}' => $club_name,
    ];
    
    return [
        'subject' => strtr($subject, $replacements),
        'message' => strtr($message, $replacements),
    ];
}

function normalize_phone_number(string $phone): string {
    // Boş kontrolü
    if (empty(trim($phone))) {
        return '';
    }
    
    // Tüm özel karakterleri kaldır (sadece rakamlar)
    $digits = preg_replace('/\D+/', '', $phone);
    if ($digits === null || empty($digits)) {
        return '';
    }
    
    // Türkiye telefon numarası formatlarını normalize et - 5428055983 formatına çevir
    // 0090... formatı (00905428055983 -> 5428055983)
    if (strlen($digits) == 13 && substr($digits, 0, 3) == '009') {
        $digits = substr($digits, 3);
    }
    // +90 veya 90 ile başlayan formatlar (905428055983 -> 5428055983)
    if (strlen($digits) == 12 && substr($digits, 0, 2) == '90') {
        $digits = substr($digits, 2);
    }
    // 0 ile başlayan formatlar (05428055983 -> 5428055983)
    if (strlen($digits) == 11 && substr($digits, 0, 1) == '0') {
        $digits = substr($digits, 1);
    }
    // 10 haneli ve 5 ile başlayan format (5428055983) - ZATEN DOĞRU FORMAT
    if (strlen($digits) == 10 && substr($digits, 0, 1) == '5') {
        // Zaten doğru format - direkt döndür
        return $digits;
    }
    
    // Eğer hala 10 haneli değilse ve 5 ile başlamıyorsa, son 10 haneyi al
    if (strlen($digits) > 10) {
        $digits = substr($digits, -10);
    }
    
    // Son kontrol: 10 haneli ve 5 ile başlamalı
    if (strlen($digits) == 10 && substr($digits, 0, 1) == '5') {
        return $digits;
    }
    
    return $digits;
}

function get_member_names_for_phones(array $phones) {
    $normalized = [];
    foreach ($phones as $phone) {
        $norm = normalize_phone_number((string)$phone);
        if ($norm !== '') {
            $normalized[$norm] = true;
        }
    }
    
    if (empty($normalized)) {
        return [];
    }
    
    $db = get_db();
    
    // Check if members table exists
    $table_check = @$db->query("SELECT name FROM sqlite_master WHERE type='table' AND name='members'");
    if (!$table_check || !$table_check->fetchArray()) {
        return [];
    }
    
    $stmt = @$db->prepare("SELECT full_name, phone_number FROM members WHERE club_id = ?");
    if (!$stmt) {
        return [];
    }
    $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
    $result = $stmt->execute();
    if (!$result) {
        return [];
    }
    
    $map = [];
    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
        $normDb = normalize_phone_number((string)($row['phone_number'] ?? ''));
        if ($normDb !== '' && isset($normalized[$normDb])) {
            $map[$normDb] = trim((string)($row['full_name'] ?? ''));
        }
    }
    
    return $map;
}

function personalize_sms_message(string $message, ?string $member_name, string $member_phone, string $club_name) {
    $display_name = trim((string)$member_name);
    if ($display_name === '') {
        $display_name = 'Üyemiz';
    }
    
    $first_name = $display_name;
    if (strpos($display_name, ' ') !== false) {
        $first_name = trim(strtok($display_name, ' '));
    }
    
    $replacements = [
        '{{member_name}}' => $display_name,
        '{{uye_adi}}' => $display_name,
        '{{member_first_name}}' => $first_name,
        '{{member_phone}}' => $member_phone,
        '{{club_name}}' => $club_name,
    ];
    
    return strtr($message, $replacements);
}

function get_email_template($subject, $message, $from_name, $from_email, $partner_logos_html = '') {
    // Mesaj HTML mi kontrol et
    $is_html = (strip_tags($message) !== $message);
    $message_content = $is_html ? $message : nl2br(htmlspecialchars($message));
    
    // Minimal renk paleti - tek renk uyumu
    $primary_color = '#6366f1'; // Indigo
    $primary_light = '#818cf8';
    $primary_lighter = '#e0e7ff';
    $bg_color = '#ffffff';
    $text_primary = '#1e293b';
    $text_secondary = '#475569';
    $text_muted = '#94a3b8';
    $border_color = '#e2e8f0';
    
    // Doğrulama kodu kontrolü (6 haneli sayı)
    $is_verification_code = preg_match('/\b\d{6}\b/', $message);
    $verification_code = '';
    if ($is_verification_code) {
        preg_match('/\b(\d{6})\b/', $message, $matches);
        if (!empty($matches[1])) {
            $verification_code = $matches[1];
        }
    }

    // Doğrulama kodu için özel içerik
    $code_display = '';
    if ($verification_code && strlen($verification_code) == 6) {
        $code_digits = str_split($verification_code);
        $code_display = '<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:32px 0;">
            <tr>
                <td align="center">
                    <table role="presentation" cellpadding="0" cellspacing="12" border="0">
                        <tr>';
        foreach ($code_digits as $digit) {
            $code_display .= '<td style="width:56px;height:56px;background-color:' . $primary_lighter . ';border:2px solid ' . $primary_color . ';border-radius:12px;text-align:center;vertical-align:middle;">
                <span style="font-size:28px;font-weight:700;color:' . $primary_color . ';font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;line-height:52px;display:block;">' . $digit . '</span>
            </td>';
        }
        $code_display .= '</tr>
                    </table>
                </td>
            </tr>
        </table>';
        
        // Mesaj içeriğinden kodu çıkar (kod kutularda gösterilecek)
        $message_content = preg_replace('/\b\d{6}\b/', '', $message_content);
        $message_content = preg_replace('/doğrulama kodunuz:\s*/i', '', $message_content);
        $message_content = trim($message_content);
    }

    return "<!DOCTYPE html>
<html lang='tr'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <meta http-equiv='X-UA-Compatible' content='IE=edge'>
    <title>" . htmlspecialchars($subject) . "</title>
    <!--[if mso]>
    <style type='text/css'>
        body, table, td {font-family: Arial, Helvetica, sans-serif !important;}
    </style>
    <![endif]-->
    <style type='text/css'>
        @media only screen and (max-width: 600px) {
            .email-container { width: 100% !important; max-width: 100% !important; }
            .email-content { padding: 32px 24px !important; }
        }
    </style>
</head>
<body style='margin:0;padding:0;background-color:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;-webkit-font-smoothing:antialiased;-moz-osx-font-smoothing:grayscale;'>
    <!-- Preheader -->
    <div style='display:none;font-size:1px;color:#fefefe;line-height:1px;max-height:0px;opacity:0;overflow:hidden;'>" . htmlspecialchars(substr(strip_tags($message), 0, 100)) . "...</div>
    
    <table role='presentation' width='100%' cellpadding='0' cellspacing='0' border='0' style='background-color:#f8fafc;padding:40px 20px;'>
        <tr>
            <td align='center'>
                <!-- Tek Kutu - Tüm İçerik -->
                <table role='presentation' class='email-container' width='560' cellpadding='0' cellspacing='0' border='0' style='max-width:560px;background-color:" . $bg_color . ";border-radius:20px;box-shadow:0 2px 12px rgba(99,102,241,0.08);overflow:hidden;'>
                    
                    <!-- Minimal Header -->
                    <tr>
                        <td style='background-color:" . $primary_color . ";padding:32px 40px;text-align:center;'>
                            <h1 style='margin:0;color:#ffffff;font-size:22px;font-weight:600;letter-spacing:-0.3px;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>" . htmlspecialchars($from_name) . "</h1>
                        </td>
                    </tr>
                    
                    <!-- İçerik -->
                    <tr>
                        <td class='email-content' style='padding:40px;background-color:" . $bg_color . ";'>
                            
                            <!-- Başlık -->
                            <h2 style='margin:0 0 24px 0;color:" . $text_primary . ";font-size:20px;font-weight:600;letter-spacing:-0.2px;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>" . htmlspecialchars($subject) . "</h2>
                            
                            <!-- Mesaj İçeriği -->
                            " . (!empty($message_content) ? "<div style='font-size:15px;line-height:1.7;color:" . $text_secondary . ";margin-bottom:" . ($verification_code ? "32" : "0") . "px;font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>" . $message_content . "</div>" : "") . "
                            
                            <!-- Doğrulama Kodu (6 Kutulu) -->
                            " . ($code_display ? $code_display . "<p style='margin:24px 0 0 0;text-align:center;font-size:13px;color:" . $text_muted . ";font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>Bu kod 10 dakika geçerlidir</p>" : "") . "
                            
                            " . (!$verification_code && !empty($from_email) ? "
                            <!-- İletişim -->
                            <div style='margin-top:32px;padding:20px;background-color:" . $primary_lighter . ";border-radius:12px;text-align:center;'>
                                <p style='margin:0;font-size:14px;color:" . $text_secondary . ";font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>
                                    <a href='mailto:" . htmlspecialchars($from_email) . "' style='color:" . $primary_color . ";text-decoration:none;font-weight:600;'>" . htmlspecialchars($from_email) . "</a>
                                </p>
                            </div>
                            " : "") . "
                            
                        </td>
                    </tr>
                    
                    <!-- Minimal Footer -->
                    <tr>
                        <td style='background-color:#f8fafc;padding:24px 40px;text-align:center;border-top:1px solid " . $border_color . ";'>
                            <p style='margin:0;font-size:12px;color:" . $text_muted . ";font-family:-apple-system,BlinkMacSystemFont,\"Segoe UI\",Roboto,\"Helvetica Neue\",Arial,sans-serif;'>
                                © " . date('Y') . " " . htmlspecialchars($from_name) . " - Tüm hakları saklıdır
                            </p>
                        </td>
                    </tr>
                    
                </table>
                
            </td>
        </tr>
    </table>
</body>
</html>";
}

function send_smtp_mail_batch($recipients, $subject, $message, $from_name, $from_email, $config = []) {
    // from_email parametresi boşsa veya yanlışsa, veritabanından al
    if (empty($from_email) || stripos($from_email, 'tun4aa') !== false || stripos($from_email, 'gmail.com') !== false) {
        $from_email = get_setting('smtp_from_email', '') ?: ($config['username'] ?? get_setting('smtp_username', '') ?: 'admin@foursoftware.com.tr');
    }
    // from_name parametresi boşsa, veritabanından al
    if (empty($from_name)) {
        $from_name = get_setting('smtp_from_name', '') ?: get_setting('club_name', 'Topluluk');
    }
    
    $sent_count = 0;
    $failed_count = 0;
    $success_emails = [];
    $failed_emails = [];
    $success_ids = [];
    $failed_ids = [];
    
    $recipient_entries = [];
    foreach ($recipients as $recipient) {
        if (is_array($recipient)) {
            $email = $recipient['email'] ?? $recipient['recipient_email'] ?? null;
            $recipient_id = isset($recipient['id']) ? (int)$recipient['id'] : null;
            $custom_subject = isset($recipient['subject']) && $recipient['subject'] !== '' ? $recipient['subject'] : null;
            $custom_message = isset($recipient['message']) && $recipient['message'] !== '' ? $recipient['message'] : null;
        } else {
            $email = $recipient;
            $recipient_id = null;
            $custom_subject = null;
            $custom_message = null;
        }
        $recipient_entries[] = [
            'email' => $email,
            'id' => $recipient_id,
            'subject' => $custom_subject,
            'message' => $custom_message
        ];
    }
    
    if (empty($recipient_entries)) {
        return [
            'sent' => 0,
            'failed' => 0,
            'success_recipients' => [],
            'failed_recipients' => [],
            'success_ids' => [],
            'failed_ids' => [],
        ];
    }
    
    $recipient_total = count($recipient_entries);
    $all_emails = [];
    $all_ids = [];
    foreach ($recipient_entries as $entry) {
        if (!empty($entry['email'])) {
            $all_emails[] = $entry['email'];
        }
        if (!empty($entry['id'])) {
            $all_ids[] = (int)$entry['id'];
        }
    }
    
    $buildEarlyFailure = function() use ($recipient_total, $all_emails, $all_ids) {
        return [
            'sent' => 0,
            'failed' => $recipient_total,
            'success_recipients' => [],
            'failed_recipients' => $all_emails,
            'success_ids' => [],
            'failed_ids' => $all_ids,
        ];
    };
    
    try {
        // Önce config'den al, yoksa veritabanından al, yoksa fallback
        $host = $config['host'] ?? get_setting('smtp_host', '') ?: get_smtp_credential('host', 'ms7.guzel.net.tr');
        $port = (int)($config['port'] ?? get_setting('smtp_port', '587') ?: get_smtp_credential('port', 587));
        $secure = strtolower($config['secure'] ?? get_setting('smtp_secure', 'tls') ?: get_smtp_credential('encryption', 'tls'));
        $username = $config['username'] ?? get_setting('smtp_username', '') ?: get_smtp_credential('username');
        $password = $config['password'] ?? get_setting('smtp_password', '') ?: get_smtp_credential('password');

        if (!$host || !$port || !$username || !$password) {
            tpl_error_log('SMTP config eksik (batch): host=' . ($host ?: 'EMPTY') . ', port=' . ($port ?: 'EMPTY') . ', username=' . ($username ? 'SET' : 'EMPTY') . ', password=' . ($password ? 'SET' : 'EMPTY'));
            return $buildEarlyFailure();
        }

        $transport = $secure === 'ssl' ? 'ssl://' : '';
        $timeout = 30;

        $fp = @stream_socket_client(($transport ?: '') . $host . ':' . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
        ]));
        
        if (!$fp) {
            tpl_error_log("SMTP bağlanamadı (batch): $errstr ($errno) - host: $host, port: $port, secure: $secure");
            return $buildEarlyFailure();
        }

        $read = function() use ($fp) {
            $data = '';
            while ($str = fgets($fp, 515)) {
                $data .= $str;
                if (substr($str, 3, 1) === ' ') break;
            }
            return $data;
        };

        $write = function($cmd) use ($fp) {
            fputs($fp, $cmd . "\r\n");
        };

        // SMTP handshake
        $read(); // banner
        $write('EHLO localhost');
        $ehlo = $read();
        if (strpos($ehlo, '250') !== 0) {
            tpl_error_log('SMTP EHLO başarısız: ' . trim($ehlo));
            fclose($fp);
            return $buildEarlyFailure();
        }

        if ($secure === 'tls' && stripos($ehlo, 'STARTTLS') !== false) {
            $write('STARTTLS');
            $resp = $read();
            if (strpos($resp, '220') !== 0) {
                tpl_error_log('STARTTLS başarısız: ' . $resp);
                fclose($fp);
                return $buildEarlyFailure();
            }
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                tpl_error_log('TLS şifreleme açılamadı');
                fclose($fp);
                return $buildEarlyFailure();
            }
            $write('EHLO localhost');
            $ehlo2 = $read();
            if (strpos($ehlo2, '250') !== 0) {
                tpl_error_log('SMTP EHLO (TLS sonrası) başarısız: ' . trim($ehlo2));
                fclose($fp);
                return $buildEarlyFailure();
            }
        }

        // Authentication
        $write('AUTH LOGIN');
        $auth1 = $read();
        if (strpos($auth1, '334') !== 0) {
            tpl_error_log('SMTP AUTH aşaması 1 başarısız: ' . trim($auth1));
            fclose($fp);
            return $buildEarlyFailure();
        }
        $write(base64_encode($username));
        $auth2 = $read();
        if (strpos($auth2, '334') !== 0) {
            tpl_error_log('SMTP AUTH aşaması 2 başarısız: ' . trim($auth2));
            fclose($fp);
            return $buildEarlyFailure();
        }
        $write(base64_encode($password));
        $authResp = $read();
        if (strpos($authResp, '235') !== 0) {
            tpl_error_log('SMTP kimlik doğrulama başarısız: ' . $authResp);
            fclose($fp);
            return $buildEarlyFailure();
        }

        $partner_logos_html = '';
        try {
            $db_logo = get_db();
            $partner_logos_stmt = $db_logo->prepare("SELECT logo_path FROM partner_logos WHERE club_id = ? ORDER BY created_at DESC LIMIT 4");
            $partner_logos_stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
            $partner_logos_result = $partner_logos_stmt->execute();
            $partner_logos_count = 0;
            while ($partner_row = $partner_logos_result->fetchArray(SQLITE3_ASSOC)) {
                if ($partner_logos_count >= 4) break;
                $logo_path = $partner_row['logo_path'];
                if (strpos($logo_path, 'assets/images/partner-logos/') === 0 && strpos($logo_path, '..') === false) {
                    $partner_logo_path = community_path($logo_path);
                    $real_logo_path = realpath($partner_logo_path);
                    $real_community_path = realpath(community_path('assets/images/partner-logos'));
                    if ($real_logo_path && $real_community_path && strpos($real_logo_path, $real_community_path) === 0 && file_exists($partner_logo_path)) {
                        $partner_logo_data = base64_encode(file_get_contents($partner_logo_path));
                        $partner_logo_ext = pathinfo($logo_path, PATHINFO_EXTENSION);
                        $partner_logo_url = 'data:image/' . ($partner_logo_ext === 'png' ? 'png' : ($partner_logo_ext === 'jpg' || $partner_logo_ext === 'jpeg' ? 'jpeg' : 'png')) . ';base64,' . $partner_logo_data;
                        $partner_logos_html .= '<img src="' . htmlspecialchars($partner_logo_url, ENT_QUOTES) . '" alt="Partner Logo" style="height:45px;margin:12px 16px;vertical-align:middle;max-width:120px;object-fit:contain;opacity:0.85;">';
                        $partner_logos_count++;
                    }
                }
            }
        } catch (Exception $e) {
            tpl_error_log('Partner logo error (batch): ' . $e->getMessage());
        }
        
        // MAIL FROM her zaman from_email kullanmalı (SMTP sunucusu kullanıcı adı ile aynı olmalı)
        // Güzel Hosting için from_email kullanıcı adı ile aynı olmalı
        $envelopeFrom = $from_email;
        if (empty($envelopeFrom) || $envelopeFrom !== $username) {
            // Eğer from_email boşsa veya username ile eşleşmiyorsa, username kullan
            $envelopeFrom = $username;
        }
        
        foreach ($recipient_entries as $entry) {
            $to = $entry['email'];
            $recipient_id = $entry['id'];
            if (empty($to)) {
                $failed_count++;
                if ($recipient_id) {
                    $failed_ids[] = $recipient_id;
                }
                continue;
            }
            
            $individual_subject = $entry['subject'] ?? $subject;
            $individual_message = $entry['message'] ?? $message;
            $html_template = get_email_template($individual_subject, $individual_message, $from_name, $from_email, $partner_logos_html);
            
            try {
                $write('MAIL FROM: <' . $envelopeFrom . '>');
                $mf = $read();
                if (strpos($mf, '250') !== 0) {
                    tpl_error_log('MAIL FROM reddedildi: ' . trim($mf) . ' for ' . $to);
                    $failed_count++;
                    $failed_emails[] = $to;
                    if ($recipient_id) {
                        $failed_ids[] = $recipient_id;
                    }
                    continue;
                }
                
                $write('RCPT TO: <' . $to . '>');
                $rc = $read();
                if (strpos($rc, '250') !== 0 && strpos($rc, '251') !== 0) {
                    tpl_error_log('RCPT TO reddedildi: ' . trim($rc) . ' Alıcı: ' . $to);
                    $failed_count++;
                    $failed_emails[] = $to;
                    if ($recipient_id) {
                        $failed_ids[] = $recipient_id;
                    }
                    continue;
                }
                
                $write('DATA');
                $dt = $read();
                if (strpos($dt, '354') !== 0) {
                    tpl_error_log('DATA kabul edilmedi: ' . trim($dt) . ' for ' . $to);
                    $failed_count++;
                    $failed_emails[] = $to;
                    if ($recipient_id) {
                        $failed_ids[] = $recipient_id;
                    }
                    continue;
                }

                $headers = [];
                $headers[] = 'From: ' . sprintf('%s <%s>', $from_name, $from_email);
                $headers[] = 'To: ' . $to;
                $headers[] = 'Subject: ' . $individual_subject;
                $headers[] = 'MIME-Version: 1.0';
                $headers[] = 'Content-Type: text/html; charset=UTF-8';
                $headers[] = 'X-Mailer: UniFour';

                $data = implode("\r\n", $headers) . "\r\n\r\n" . $html_template . "\r\n.\r\n";
                $write($data);
                $resp = $read();
                
                if (strpos($resp, '250') === 0) {
                    $sent_count++;
                    $success_emails[] = $to;
                    if ($recipient_id) {
                        $success_ids[] = $recipient_id;
                    }
                    
                    // Delivery log kaydı oluştur
                    if ($recipient_id) {
                        $db_log = get_db();
                        log_email_delivery($db_log, $recipient_id, $to, 'sent', trim($resp), 'smtp');
                    }
                } else {
                    $error_msg = trim($resp);
                    tpl_error_log('Mail gönderilemedi: ' . $error_msg . ' for ' . $to);
                    $failed_count++;
                    $failed_emails[] = $to;
                    if ($recipient_id) {
                        $failed_ids[] = $recipient_id;
                        
                        // Bounce kaydı oluştur (hard bounce olarak işaretle)
                        if (strpos($error_msg, '550') === 0 || strpos($error_msg, '551') === 0 || strpos($error_msg, '552') === 0 || strpos($error_msg, '553') === 0) {
                            $db_log = get_db();
                            log_email_bounce($db_log, $recipient_id, $to, 'hard', $error_msg, $error_msg);
                        }
                        
                        // Delivery log kaydı oluştur
                        $db_log = get_db();
                        log_email_delivery($db_log, $recipient_id, $to, 'failed', $error_msg, 'smtp');
                    }
                }
    } catch (Exception $e) {
                tpl_error_log('Mail gönderme hatası (batch): ' . $e->getMessage() . ' for ' . $to);
                $failed_count++;
                $failed_emails[] = $to;
                if ($recipient_id) {
                    $failed_ids[] = $recipient_id;
                }
            }
        }
        
        $write('QUIT');
        $read();
        fclose($fp);
        
        return [
            'sent' => $sent_count,
            'failed' => $failed_count,
            'success_recipients' => $success_emails,
            'failed_recipients' => $failed_emails,
            'success_ids' => $success_ids,
            'failed_ids' => $failed_ids,
        ];
        
    } catch (Exception $e) {
        tpl_error_log('send_smtp_mail_batch exception: ' . $e->getMessage());
        if (isset($fp) && is_resource($fp)) {
            @fclose($fp);
        }
        
        foreach ($recipient_entries as $entry) {
            $to = $entry['email'];
            $recipient_id = $entry['id'];
            if ($to && !in_array($to, $success_emails, true) && !in_array($to, $failed_emails, true)) {
                $failed_emails[] = $to;
                $failed_count++;
            }
            if ($recipient_id && !in_array($recipient_id, $success_ids, true) && !in_array($recipient_id, $failed_ids, true)) {
                $failed_ids[] = $recipient_id;
            }
        }
        
        return [
            'sent' => $sent_count,
            'failed' => $failed_count,
            'success_recipients' => $success_emails,
            'failed_recipients' => $failed_emails,
            'success_ids' => $success_ids,
            'failed_ids' => $failed_ids,
        ];
    }
}


function send_smtp_mail($to, $subject, $message, $from_name, $from_email, $config = []) {
    try {
        // Önce config'den al, yoksa veritabanından al (get_setting varsa), yoksa fallback
        $get_setting_func = function_exists('get_setting') ? 'get_setting' : null;
        
        $host = $config['host'] ?? ($get_setting_func ? get_setting('smtp_host', '') : '') ?: get_smtp_credential('host', 'ms7.guzel.net.tr');
        $port = (int)($config['port'] ?? ($get_setting_func ? get_setting('smtp_port', '587') : '587') ?: get_smtp_credential('port', 587));
        $secure = strtolower($config['secure'] ?? ($get_setting_func ? get_setting('smtp_secure', 'tls') : 'tls') ?: get_smtp_credential('encryption', 'tls')); // tls | ssl | none
        $username = $config['username'] ?? ($get_setting_func ? get_setting('smtp_username', '') : '') ?: get_smtp_credential('username');
        $password = $config['password'] ?? ($get_setting_func ? get_setting('smtp_password', '') : '') ?: get_smtp_credential('password');
        $timeout = (int)($config['timeout'] ?? 30); // Configurable timeout

        // from_email parametresi boşsa veya yanlışsa, veritabanından al (get_setting varsa)
        if (empty($from_email) || stripos($from_email, 'tun4aa') !== false || stripos($from_email, 'gmail.com') !== false) {
            $from_email = ($get_setting_func ? get_setting('smtp_from_email', '') : '') ?: ($username ?: 'admin@foursoftware.com.tr');
        }
        // from_name parametresi boşsa, veritabanından al (get_setting varsa)
        if (empty($from_name)) {
            $from_name = ($get_setting_func ? get_setting('smtp_from_name', '') : '') ?: ($get_setting_func ? get_setting('club_name', 'Topluluk') : 'Topluluk');
        }

        if (!$host || !$port || !$username || !$password) {
            tpl_error_log('SMTP config eksik: host=' . ($host ?: 'EMPTY') . ', port=' . ($port ?: 'EMPTY') . ', username=' . ($username ? 'SET' : 'EMPTY') . ', password=' . ($password ? 'SET' : 'EMPTY'));
            return false;
        }

        tpl_error_log("SMTP Bağlanıyor: $host:$port ($secure) Timeout: $timeout");

        $transport = $secure === 'ssl' ? 'ssl://' : '';
        
        $fp = @stream_socket_client(($transport ?: '') . $host . ':' . $port, $errno, $errstr, $timeout, STREAM_CLIENT_CONNECT, stream_context_create([
            'ssl' => [
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
            ],
        ]));
        if (!$fp) {
            tpl_error_log("SMTP bağlanamadı: $errstr ($errno)");
            return false;
        }

        // Stream timeout ayarla
        stream_set_timeout($fp, $timeout);

        $read = function() use ($fp) {
            $data = '';
            while ($str = fgets($fp, 515)) {
                $data .= $str;
                if (substr($str, 3, 1) === ' ') break;
            }
            return $data;
        };

        $write = function($cmd) use ($fp) {
            fputs($fp, $cmd . "\r\n");
        };

        $read(); // banner
        $write('EHLO localhost');
        $ehlo = $read();
        if (strpos($ehlo, '250') !== 0) {
            tpl_error_log('SMTP EHLO başarısız: ' . trim($ehlo));
            fclose($fp);
            return false;
        }

        if ($secure === 'tls' && stripos($ehlo, 'STARTTLS') !== false) {
            $write('STARTTLS');
            $resp = $read();
            if (strpos($resp, '220') !== 0) {
                tpl_error_log('STARTTLS başarısız: ' . $resp);
                fclose($fp);
                return false;
            }
            if (!stream_socket_enable_crypto($fp, true, STREAM_CRYPTO_METHOD_TLS_CLIENT)) {
                tpl_error_log('TLS şifreleme açılamadı');
                fclose($fp);
                return false;
            }
            // TLS sonrası yeniden EHLO
            $write('EHLO localhost');
            $ehlo2 = $read();
            if (strpos($ehlo2, '250') !== 0) {
                tpl_error_log('SMTP EHLO (TLS sonrası) başarısız: ' . trim($ehlo2));
                fclose($fp);
                return false;
            }
        }

        $write('AUTH LOGIN');
        $auth1 = $read();
        if (strpos($auth1, '334') !== 0) {
            tpl_error_log('SMTP AUTH aşaması 1 başarısız: ' . trim($auth1));
            fclose($fp);
            return false;
        }
        $write(base64_encode($username));
        $auth2 = $read();
        if (strpos($auth2, '334') !== 0) {
            tpl_error_log('SMTP AUTH aşaması 2 başarısız: ' . trim($auth2));
            fclose($fp);
            return false;
        }
        $write(base64_encode($password));
        $authResp = $read();
        if (strpos($authResp, '235') !== 0) {
            tpl_error_log('SMTP kimlik doğrulama başarısız: ' . $authResp);
            fclose($fp);
            return false;
        }

        // MAIL FROM her zaman from_email kullanmalı (SMTP sunucusu kullanıcı adı ile aynı olmalı)
        // Güzel Hosting için from_email kullanıcı adı ile aynı olmalı
        $envelopeFrom = $from_email;
        if (empty($envelopeFrom) || $envelopeFrom !== $username) {
            // Eğer from_email boşsa veya username ile eşleşmiyorsa, username kullan
            $envelopeFrom = $username;
        }
        $write('MAIL FROM: <' . $envelopeFrom . '>');
        $mf = $read();
        if (strpos($mf, '250') !== 0) {
            tpl_error_log('MAIL FROM reddedildi: ' . trim($mf));
            fclose($fp);
            return false;
        }
        $write('RCPT TO: <' . $to . '>');
        $rc = $read();
        if (strpos($rc, '250') !== 0 && strpos($rc, '251') !== 0) {
            tpl_error_log('RCPT TO reddedildi: ' . trim($rc) . ' Alıcı: ' . $to);
            fclose($fp);
            return false;
        }
        $write('DATA');
        $dt = $read();
        if (strpos($dt, '354') !== 0) {
            tpl_error_log('DATA kabul edilmedi: ' . trim($dt));
            fclose($fp);
            return false;
        }

        // Partner logoları (en fazla 4 tane)
        $partner_logos_html = '';
        try {
            $db_logo = get_db();
            if ($db_logo && function_exists('CLUB_ID') && defined('CLUB_ID')) {
                $partner_logos_stmt = $db_logo->prepare("SELECT logo_path FROM partner_logos WHERE club_id = ? ORDER BY created_at DESC LIMIT 4");
                $partner_logos_stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
                $partner_logos_result = $partner_logos_stmt->execute();
                $partner_logos_count = 0;
                while ($partner_row = $partner_logos_result->fetchArray(SQLITE3_ASSOC)) {
                    if ($partner_logos_count >= 4) break;
                    // Güvenlik: Path validation
                    $logo_path = $partner_row['logo_path'];
                    if (strpos($logo_path, 'assets/images/partner-logos/') === 0 && strpos($logo_path, '..') === false) {
                        $partner_logo_path = community_path($logo_path);
                        // Güvenlik: Dosya gerçekten community path içinde mi kontrol et
                        $real_logo_path = realpath($partner_logo_path);
                        $real_community_path = realpath(community_path('assets/images/partner-logos'));
                        if ($real_logo_path && $real_community_path && strpos($real_logo_path, $real_community_path) === 0 && file_exists($partner_logo_path)) {
                            $partner_logo_data = base64_encode(file_get_contents($partner_logo_path));
                            $partner_logo_ext = pathinfo($logo_path, PATHINFO_EXTENSION);
                            $partner_logo_url = 'data:image/' . ($partner_logo_ext === 'png' ? 'png' : ($partner_logo_ext === 'jpg' || $partner_logo_ext === 'jpeg' ? 'jpeg' : 'png')) . ';base64,' . $partner_logo_data;
                            $partner_logos_html .= '<img src="' . htmlspecialchars($partner_logo_url, ENT_QUOTES) . '" alt="Partner Logo" style="height:45px;margin:12px 16px;vertical-align:middle;max-width:120px;object-fit:contain;opacity:0.85;filter:grayscale(0%);transition:all 0.3s ease;">';
                            $partner_logos_count++;
                        }
                    }
                }
            }
        } catch (Exception $e) {
            // Partner logoları opsiyonel, hata olsa bile devam et
            if (function_exists('tpl_error_log')) {
                tpl_error_log('Partner logo error: ' . $e->getMessage());
            }
        }
        
        // Headerları oluştur
        $headers = [];
        // Gravatar URL oluştur (e-posta adresinin MD5 hash'i)
        $gravatar_email = strtolower(trim($from_email));
        $gravatar_hash = md5($gravatar_email);
        $gravatar_url = "https://www.gravatar.com/avatar/{$gravatar_hash}?s=200&d=404";
        
        // Logo URL kontrolü (config'den veya Gravatar)
        $logo_url = get_smtp_credential('logo_url', '');
        if (empty($logo_url)) {
            // Gravatar kullan (eğer logo URL yoksa)
            // Not: Gravatar otomatik olarak e-posta istemcileri tarafından kullanılır
            // Burada sadece referans için ekliyoruz
        }
        
        $headers[] = 'From: ' . sprintf('%s <%s>', $from_name, $from_email);
        $headers[] = 'Reply-To: ' . $from_email;
        $headers[] = 'To: ' . $to;
        $headers[] = 'Subject: ' . $subject;
        $headers[] = 'MIME-Version: 1.0';
        $headers[] = 'Content-Type: text/html; charset=UTF-8';
        $headers[] = 'X-Mailer: UniFour';
        $headers[] = 'X-Auto-Response-Suppress: All';
        // Gravatar için referans (bazı istemciler destekler)
        if (!empty($logo_url)) {
            $headers[] = 'X-Profile-Image: ' . $logo_url;
        }

        // Batch ile aynı template'i kullan
        $html = get_email_template($subject, $message, $from_name, $from_email, $partner_logos_html);

        $data = implode("\r\n", $headers) . "\r\n\r\n" . $html . "\r\n.\r\n";
        $write($data);
        $resp = $read();
        
        // Yanıtı logla
        if (strpos($resp, '250') !== 0) {
            tpl_error_log('SMTP DATA gönderimi başarısız: ' . trim($resp) . ' (Alıcı: ' . $to . ')');
        }
        
        $write('QUIT');
        @fclose($fp);

        $success = strpos($resp, '250') === 0;
        if (!$success) {
            tpl_error_log('SMTP mail gönderimi başarısız. Sunucu yanıtı: ' . trim($resp));
        } else {
            tpl_error_log('SMTP mail gönderimi BAŞARILI. Alıcı: ' . $to);
        }
        return $success;
    } catch (Exception $e) {
        tpl_error_log('send_smtp_mail exception: ' . $e->getMessage());
        return false;
    }
}


function send_sms_twilio($to, $message, $from_number, $account_sid, $auth_token, $messaging_service_sid = '') {
    try {
        // Account SID ve Auth Token'ı temizle
        $account_sid = trim($account_sid);
        $auth_token = trim($auth_token);
        $from_number = trim($from_number);
        $messaging_service_sid = trim($messaging_service_sid);
        
        // Validasyon - Account SID AC ile başlamalı ve en az 32 karakter olmalı
        if (empty($account_sid)) {
            tpl_error_log('Twilio Account SID boş');
            return ['success' => false, 'error' => 'Account SID boş! Lütfen Ayarlar\'dan girin.'];
        }
        
        if (substr($account_sid, 0, 2) !== 'AC' && substr($account_sid, 0, 2) !== 'ac') {
            tpl_error_log('Twilio Account SID AC ile başlamıyor: ' . substr($account_sid, 0, 10));
            return ['success' => false, 'error' => 'Account SID AC ile başlamalı!'];
        }
        
        if (strlen($account_sid) < 32) {
            tpl_error_log('Twilio Account SID çok kısa: ' . strlen($account_sid) . ' karakter');
            return ['success' => false, 'error' => 'Account SID çok kısa! En az 32 karakter olmalı.'];
        }
        
        if (empty($auth_token) || strlen($auth_token) < 30) {
            tpl_error_log('Twilio Auth Token format hatası: Token çok kısa');
            return ['success' => false, 'error' => 'Auth Token formatı yanlış! Token çok kısa görünüyor.'];
        }
        
        // MessagingServiceSid varsa onu kullan, yoksa From Number kontrol et
        if (empty($messaging_service_sid)) {
            if (empty($from_number) || substr($from_number, 0, 1) != '+') {
                tpl_error_log('Twilio From Number format hatası: ' . $from_number);
                return ['success' => false, 'error' => 'From Number veya MessagingServiceSid gerekli! From Number + ile başlamalı (örn: +15551234567) veya MessagingServiceSid girin.'];
            }
        }
        
        // Telefon numarasını E.164 formatına çevir (Twilio için zorunlu)
        $original_to = $to;
        
        // Önce tüm özel karakterleri temizle (sadece rakamlar ve +)
        $to = preg_replace('/[^0-9+]/', '', trim($to));
        
        // Eğer zaten + ile başlıyorsa, sadece rakamları al ve tekrar + ekle
        if (substr($to, 0, 1) == '+') {
            $digits = preg_replace('/[^0-9]/', '', $to);
            // Eğer +90 ile başlıyorsa, sadece rakamları al
            if (substr($digits, 0, 2) == '90' && strlen($digits) == 12) {
                $to = '+' . $digits; // +905551234567 formatında
            } elseif (strlen($digits) >= 10) {
                $to = '+' . $digits;
            } else {
                // Geçersiz format
                tpl_error_log('Twilio: Geçersiz telefon numarası formatı (zaten + var ama geçersiz): ' . $original_to);
                return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_to . '. Türkiye numarası için +905551234567 formatında olmalı.'];
            }
        } else {
            // + yoksa, sadece rakamları al
            $digits = preg_replace('/[^0-9]/', '', $to);
            
            // Türk telefon numarası formatlarını kontrol et
            if (strlen($digits) == 10 && substr($digits, 0, 1) == '5') {
                // 10 haneli, 5 ile başlıyor: 5551234567 -> +905551234567
                $to = '+90' . $digits;
            } elseif (strlen($digits) == 11 && substr($digits, 0, 2) == '05') {
                // 11 haneli, 05 ile başlıyor: 05551234567 -> +905551234567
                $to = '+90' . substr($digits, 1);
            } elseif (strlen($digits) == 12 && substr($digits, 0, 2) == '90') {
                // 12 haneli, 90 ile başlıyor: 905551234567 -> +905551234567
                $to = '+' . $digits;
            } elseif (strlen($digits) == 13 && substr($digits, 0, 3) == '009') {
                // 13 haneli, 009 ile başlıyor: 00905551234567 -> +905551234567
                $to = '+' . substr($digits, 2);
            } else {
                // Geçersiz format
                tpl_error_log('Twilio: Geçersiz telefon numarası formatı: ' . $original_to . ' (digits: ' . $digits . ', length: ' . strlen($digits) . ')');
                return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_to . '. Türkiye numarası için 10 haneli olmalı (örn: 5551234567 veya +905551234567).'];
            }
        }
        
        // Final validasyon: E.164 formatı kontrolü (+ ile başlamalı, en az 10 rakam olmalı)
        if (substr($to, 0, 1) != '+' || strlen(preg_replace('/[^0-9]/', '', $to)) < 10) {
            tpl_error_log('Twilio: E.164 format validasyonu başarısız: ' . $to);
            return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_to . '. E.164 formatında olmalı (örn: +905551234567).'];
        }
        
        // MessagingServiceSid varsa onu kullan, yoksa From Number kullan
        if (!empty($messaging_service_sid)) {
            tpl_error_log('Twilio SMS - To: ' . $to . ', MessagingServiceSid: ' . substr($messaging_service_sid, 0, 5) . '..., Account SID: ' . substr($account_sid, 0, 5) . '...');
        } else {
            tpl_error_log('Twilio SMS - To: ' . $to . ', From: ' . $from_number . ', Account SID: ' . substr($account_sid, 0, 5) . '...');
        }
        
        $url = "https://api.twilio.com/2010-04-01/Accounts/{$account_sid}/Messages.json";
        
        $data = [
            'To' => $to,
            'Body' => $message
        ];
        
        // MessagingServiceSid varsa onu kullan, yoksa From Number kullan
        if (!empty($messaging_service_sid)) {
            $data['MessagingServiceSid'] = $messaging_service_sid;
        } else {
            $data['From'] = $from_number;
        }
        
        $ch = curl_init($url);
        if ($ch === false) {
            tpl_error_log('Twilio cURL init failed');
            return ['success' => false, 'error' => 'cURL başlatılamadı'];
        }
        
        // cURL ayarları
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERPWD, $account_sid . ':' . $auth_token);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        
        // Timeout ayarları - DNS çözümleme için daha uzun süre
        curl_setopt($ch, CURLOPT_TIMEOUT, 60); // Toplam timeout
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30); // Bağlantı timeout artırıldı
        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 3600); // DNS cache 1 saat
        
        // DNS ayarları - DNS çözümleme sorunlarını çözmek için
        if (defined('CURLOPT_RESOLVE')) {
            // DNS önceden çözümle ve direkt IP kullan
            $twilio_ip = gethostbyname('api.twilio.com');
            if ($twilio_ip !== 'api.twilio.com' && filter_var($twilio_ip, FILTER_VALIDATE_IP)) {
                // IP adresi başarıyla alındı, direkt kullan
                curl_setopt($ch, CURLOPT_RESOLVE, ["api.twilio.com:443:$twilio_ip"]);
                tpl_error_log('Twilio DNS resolved to IP: ' . $twilio_ip);
            }
        }
        
        // SSL ayarları
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        
        // IPv4/IPv6 - IPv4'e zorla (daha stabil)
        if (defined('CURLOPT_IPRESOLVE')) {
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }
        
        // DNS sorunlarını çözmek için alternatif DNS server kullan (opsiyonel)
        if (defined('CURLOPT_DNS_SERVERS')) {
            // Google DNS kullan (8.8.8.8, 8.8.4.4)
            // curl_setopt($ch, CURLOPT_DNS_SERVERS, '8.8.8.8,8.8.4.4');
        }
        
        // Verbose logging (debug için)
        $verbose = fopen('php://temp', 'w+');
        curl_setopt($ch, CURLOPT_VERBOSE, true);
        curl_setopt($ch, CURLOPT_STDERR, $verbose);
        
        $response = curl_exec($ch);
        $curl_error = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curl_info = curl_getinfo($ch);
        
        // Debug bilgilerini logla
        if ($response === false || !empty($curl_error)) {
            rewind($verbose);
            $verbose_log = stream_get_contents($verbose);
            fclose($verbose);
            tpl_error_log('Twilio cURL Error: ' . $curl_error);
            tpl_error_log('Twilio cURL Verbose: ' . substr($verbose_log, 0, 500));
            tpl_error_log('Twilio cURL Info: DNS: ' . ($curl_info['namelookup_time'] ?? 'N/A') . 's, Connect: ' . ($curl_info['connect_time'] ?? 'N/A') . 's, Total: ' . ($curl_info['total_time'] ?? 'N/A') . 's');
        } else {
            fclose($verbose);
        }
        
        curl_close($ch);
        
        if ($response === false || !empty($curl_error)) {
            // Daha açıklayıcı hata mesajı
            if (strpos($curl_error, 'name lookup') !== false || strpos($curl_error, 'DNS') !== false) {
                return ['success' => false, 'error' => 'DNS çözümleme hatası. İnternet bağlantınızı kontrol edin veya birkaç dakika sonra tekrar deneyin.'];
            }
            tpl_error_log('Twilio cURL Error: ' . $curl_error);
            return ['success' => false, 'error' => 'Bağlantı hatası: ' . $curl_error];
        }
        
        if ($http_code == 201) {
            $result = json_decode($response, true);
            $message_sid = $result['sid'] ?? '';
            $message_status = $result['status'] ?? 'unknown';
            $error_code = $result['error_code'] ?? null;
            $error_message = $result['error_message'] ?? null;
            
            // Detaylı log
            tpl_error_log('Twilio SMS Response - SID: ' . $message_sid . ', Status: ' . $message_status . ', Error Code: ' . ($error_code ?? 'null') . ', Error Message: ' . ($error_message ?? 'null'));
            tpl_error_log('Twilio SMS Full Response: ' . substr($response, 0, 500));
            
            // Status kontrolü
            if ($message_status === 'accepted' || $message_status === 'queued' || $message_status === 'sending') {
                // Mesaj kuyruğa alındı veya gönderiliyor - başarılı
                tpl_error_log('Twilio SMS Success - Mesaj kuyruğa alındı/gönderiliyor. Status: ' . $message_status);
                return ['success' => true, 'sid' => $message_sid, 'status' => $message_status];
            } elseif ($message_status === 'failed' || $message_status === 'undelivered') {
                // Mesaj başarısız
                $error_msg = $error_message ?? 'Mesaj gönderilemedi (Status: ' . $message_status . ')';
                tpl_error_log('Twilio SMS Failed - Status: ' . $message_status . ', Error: ' . $error_msg);
                return ['success' => false, 'error' => $error_msg . ' (Status: ' . $message_status . ')'];
            } else {
                // Diğer durumlar (sent, delivered, vb.)
                tpl_error_log('Twilio SMS - Status: ' . $message_status);
                return ['success' => true, 'sid' => $message_sid, 'status' => $message_status];
            }
        } else {
            $error = json_decode($response, true);
            $error_msg = $error['message'] ?? ($error['more_info'] ?? 'Bilinmeyen hata');
            $error_code = $error['code'] ?? $http_code;
            tpl_error_log('Twilio SMS Error - HTTP: ' . $http_code . ', Code: ' . $error_code . ', Message: ' . $error_msg . ', To: ' . $to . ', Response: ' . substr($response, 0, 200));
            
            // Özel hata mesajları
            if ($error_code == 21408) {
                // Türkiye için izin yok
                return ['success' => false, 'error' => 'Türkiye (+90) için SMS gönderme izni yok! Twilio Dashboard\'dan (https://console.twilio.com) → Settings → Geo Permissions → Türkiye\'yi aktif edin. VEYA NetGSM kullanın (Ayarlar → SMS Sağlayıcı → NetGSM).'];
            } elseif ($error_code == 21659) {
                // From numarası hatalı
                return ['success' => false, 'error' => 'From numarası Twilio hesabınızda kayıtlı değil! Twilio Dashboard\'dan (https://console.twilio.com) → Phone Numbers bölümünden aktif bir numara alın. Türkiye için NetGSM kullanmanız önerilir (Ayarlar → SMS Sağlayıcı → NetGSM).'];
            } elseif ($error_code == 21608) {
                // Numara blacklist'te
                return ['success' => false, 'error' => 'Bu numara Twilio tarafından engellenmiş. Lütfen farklı bir numara deneyin.'];
            } elseif ($error_code == 21211 || strpos($error_msg, 'did not match the expected pattern') !== false || strpos($error_msg, 'pattern') !== false || strpos(strtolower($error_msg), 'string') !== false) {
                // Geçersiz numara veya pattern hatası
                return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_to . '. Numara E.164 formatında olmalı (örn: +905551234567). Gönderilen format: ' . $to];
            } elseif ($error_code == 21408 || strpos($error_msg, 'region') !== false || strpos($error_msg, 'Permission') !== false) {
                // Bölge izni hatası
                return ['success' => false, 'error' => $error_msg . ' Twilio Dashboard\'dan (https://console.twilio.com) → Settings → Geo Permissions bölümünden ilgili ülkeyi aktif edin. VEYA NetGSM kullanın.'];
            }
            
            return ['success' => false, 'error' => $error_msg . ' (Code: ' . $error_code . ')'];
        }
    } catch (Exception $e) {
        tpl_error_log('Twilio SMS Exception: ' . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}


function send_whatsapp_twilio($to, $message, $from_number, $account_sid, $auth_token, $messaging_service_sid = '') {
    try {
        // Account SID ve Auth Token'ı temizle
        $account_sid = trim($account_sid);
        $auth_token = trim($auth_token);
        $from_number = trim($from_number);
        $messaging_service_sid = trim($messaging_service_sid);
        
        // Validasyon
        if (empty($account_sid) || substr($account_sid, 0, 2) !== 'AC' && substr($account_sid, 0, 2) !== 'ac') {
            tpl_error_log('Twilio WhatsApp: Account SID geçersiz');
            return ['success' => false, 'error' => 'Account SID geçersiz!'];
        }
        
        if (empty($auth_token) || strlen($auth_token) < 30) {
            tpl_error_log('Twilio WhatsApp: Auth Token geçersiz');
            return ['success' => false, 'error' => 'Auth Token geçersiz!'];
        }
        
        // WhatsApp için From Number zorunlu (WhatsApp formatında olmalı)
        if (empty($messaging_service_sid) && empty($from_number)) {
            return ['success' => false, 'error' => 'WhatsApp için From Number veya MessagingServiceSid gerekli!'];
        }
        
        // Telefon numarasını temizle ve WhatsApp formatına çevir
        $to = preg_replace('/[^0-9]/', '', $to);
        
        // Türk telefon numaraları için +90 ekle
        if (strlen($to) == 10 && substr($to, 0, 1) == '5') {
            $to = '+90' . $to;
        } elseif (strlen($to) == 11 && substr($to, 0, 2) == '05') {
            $to = '+90' . substr($to, 1);
        } elseif (substr($to, 0, 1) != '+') {
            $to = '+' . $to;
        }
        
        // WhatsApp formatı: whatsapp:+905551234567
        if (strpos($to, 'whatsapp:') === false) {
            $to = 'whatsapp:' . $to;
        }
        
        // From Number'ı WhatsApp formatına çevir
        // WhatsApp için Sandbox numarası kullanılır: +14155238886
        $whatsapp_sandbox_number = 'whatsapp:+14155238886';
        $from = '';
        
        if (!empty($messaging_service_sid)) {
            // MessagingServiceSid kullan
            tpl_error_log('Twilio WhatsApp - To: ' . $to . ', MessagingServiceSid: ' . substr($messaging_service_sid, 0, 5) . '...');
        } else {
            // WhatsApp için Sandbox numarasını kullan (zorunlu)
            // Kullanıcı normal numara girmiş olsa bile, WhatsApp için Sandbox numarası kullanılır
            $from = $whatsapp_sandbox_number;
            tpl_error_log('Twilio WhatsApp - To: ' . $to . ', From: ' . $from . ' (Sandbox)');
        }
        
        $url = "https://api.twilio.com/2010-04-01/Accounts/{$account_sid}/Messages.json";
        
        $data = [
            'To' => $to,
            'Body' => $message
        ];
        
        // MessagingServiceSid varsa onu kullan, yoksa From Number kullan
        if (!empty($messaging_service_sid)) {
            $data['MessagingServiceSid'] = $messaging_service_sid;
        } else {
            $data['From'] = $from;
        }
        
        $ch = curl_init($url);
        if ($ch === false) {
            tpl_error_log('Twilio WhatsApp cURL init failed');
            return ['success' => false, 'error' => 'cURL başlatılamadı'];
        }
        
        // cURL ayarları (SMS ile aynı)
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_USERPWD, $account_sid . ':' . $auth_token);
        curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($data));
        curl_setopt($ch, CURLOPT_HTTPHEADER, ['Content-Type: application/x-www-form-urlencoded']);
        curl_setopt($ch, CURLOPT_TIMEOUT, 60);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 30);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);
        
        // DNS ayarları
        if (defined('CURLOPT_RESOLVE')) {
            $twilio_ip = gethostbyname('api.twilio.com');
            if ($twilio_ip !== 'api.twilio.com' && filter_var($twilio_ip, FILTER_VALIDATE_IP)) {
                curl_setopt($ch, CURLOPT_RESOLVE, ["api.twilio.com:443:$twilio_ip"]);
            }
        }
        
        if (defined('CURLOPT_IPRESOLVE')) {
            curl_setopt($ch, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
        }
        
        $response = curl_exec($ch);
        $curl_error = curl_error($ch);
        $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);
        
        if ($response === false || !empty($curl_error)) {
            if (strpos($curl_error, 'name lookup') !== false || strpos($curl_error, 'DNS') !== false) {
                return ['success' => false, 'error' => 'DNS çözümleme hatası. İnternet bağlantınızı kontrol edin.'];
            }
            tpl_error_log('Twilio WhatsApp cURL Error: ' . $curl_error);
            return ['success' => false, 'error' => 'Bağlantı hatası: ' . $curl_error];
        }
        
        if ($http_code == 201) {
            $result = json_decode($response, true);
            $message_sid = $result['sid'] ?? '';
            $message_status = $result['status'] ?? 'unknown';
            tpl_error_log('Twilio WhatsApp Success - SID: ' . $message_sid . ', Status: ' . $message_status);
            return ['success' => true, 'sid' => $message_sid, 'status' => $message_status];
        } else {
            $error = json_decode($response, true);
            $error_msg = $error['message'] ?? ($error['more_info'] ?? 'Bilinmeyen hata');
            $error_code = $error['code'] ?? $http_code;
            tpl_error_log('Twilio WhatsApp Error - HTTP: ' . $http_code . ', Code: ' . $error_code . ', Message: ' . $error_msg);
            
            // Özel hata mesajları
            if ($error_code == 21610) {
                return ['success' => false, 'error' => 'WhatsApp numarası geçersiz veya WhatsApp Sandbox\'a kayıtlı değil! Twilio Console\'dan WhatsApp Sandbox numarasını kontrol edin.'];
            } elseif ($error_code == 21608) {
                return ['success' => false, 'error' => 'Bu numara WhatsApp\'ta engellenmiş. Lütfen farklı bir numara deneyin.'];
            }
            
            return ['success' => false, 'error' => $error_msg . ' (Code: ' . $error_code . ')'];
        }
    } catch (Exception $e) {
        tpl_error_log('Twilio WhatsApp Exception: ' . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}


function send_sms_netgsm($to, $message, $username, $password, $msgheader = '') {
    try {
        // Boş telefon numarası kontrolü
        if (empty($to)) {
            tpl_error_log('NetGSM: Telefon numarası boş');
            return ['success' => false, 'error' => 'Telefon numarası boş! Lütfen superadmin ayarlarından telefon numaranızı girin.'];
        }
        
        // NetGSM için telefon numarasını temizle ve normalize et
        $original_to = $to;
        
        // Önce validate_and_normalize_phone kullan (tutarlılık için)
        $phone_validation = validate_and_normalize_phone((string)$to);
        if (!$phone_validation['valid']) {
            tpl_error_log('NetGSM: Telefon numarası validasyonu başarısız: ' . $phone_validation['error'] . ' (numara: ' . $original_to . ')');
            return ['success' => false, 'error' => $phone_validation['error']];
        }
        
        // Normalize edilmiş telefon numarasını al
        $to = $phone_validation['phone'];
        
        // 10 haneli değilse veya 5 ile başlamıyorsa hata
        if (strlen($to) != 10) {
            tpl_error_log('NetGSM: Geçersiz telefon numarası uzunluğu: ' . strlen($to) . ' (numara: ' . $to . ', orijinal: ' . $original_to . ')');
            return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı! Türkiye numarası 10 haneli olmalı (örn: 5551234567). Gelen numara: ' . $original_to];
        }
        
        if (substr($to, 0, 1) != '5') {
            tpl_error_log('NetGSM: Telefon numarası 5 ile başlamıyor: ' . $to . ' (orijinal: ' . $original_to . ')');
            return ['success' => false, 'error' => 'Geçersiz telefon numarası formatı! Türkiye numarası 5 ile başlamalı (örn: 5551234567). Gelen numara: ' . $original_to];
        }

        // NetGSM API tam format: 90 + numara
        $gsm_number = '90' . $to;
        
        // Validasyon
        if (empty($username) || empty($password)) {
            tpl_error_log('NetGSM: Username veya Password boş');
            return ['success' => false, 'error' => 'NetGSM kullanıcı adı veya şifre boş!'];
        }
        
        if (empty($message)) {
            tpl_error_log('NetGSM: Mesaj boş');
            return ['success' => false, 'error' => 'Mesaj boş olamaz!'];
        }
        
        // NetGSM API URL
        $url = "http://api.netgsm.com.tr/sms/send/get";
        
        // Mesaj başlığı (msgheader) - boşsa varsayılan kullan
        if (empty($msgheader)) {
            $msgheader = $username; // Varsayılan olarak kullanıcı adı
        }
        
        // API parametreleri
        $params = [
            'usercode' => $username,
            'password' => $password,
            'gsmno' => $gsm_number,
            'message' => $message,
            'msgheader' => $msgheader,
            'language' => 'TR' // Türkçe karakter desteği
        ];
        
        $url_with_params = $url . '?' . http_build_query($params);
        
        // cURL ile istek gönder
        $ch = curl_init($url_with_params);
        if ($ch === false) {
            tpl_error_log('NetGSM cURL init failed');
            return ['success' => false, 'error' => 'cURL başlatılamadı'];
        }
        
        // Optimize edilmiş timeout ayarları - Login için hızlı yanıt
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10); // 10 saniye timeout (login için yeterli)
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5); // 5 saniye connection timeout
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_setopt($ch, CURLOPT_MAXREDIRS, 3);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
        curl_setopt($ch, CURLOPT_USERAGENT, 'UniPanel/1.0');
        curl_setopt($ch, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_1_1);
        curl_setopt($ch, CURLOPT_TCP_KEEPALIVE, 1);
        curl_setopt($ch, CURLOPT_TCP_KEEPIDLE, 30);
        curl_setopt($ch, CURLOPT_TCP_KEEPINTVL, 5);
        
        // Optimize edilmiş retry - 3 deneme yeterli
        $max_retries = 3;
        $response = false;
        $curl_error = '';
        $http_code = 0;
        $last_successful_response = false;
        
        // DNS ön çözümleme (performans için)
        $netgsm_ip = gethostbyname('api.netgsm.com.tr');
        if ($netgsm_ip !== 'api.netgsm.com.tr' && filter_var($netgsm_ip, FILTER_VALIDATE_IP)) {
            curl_setopt($ch, CURLOPT_RESOLVE, ["api.netgsm.com.tr:80:$netgsm_ip"]);
        }
        
        for ($retry = 0; $retry < $max_retries; $retry++) {
            if ($retry > 0) {
                // Kısa retry delay: 1, 2 saniye
                $delay = $retry;
                sleep($delay);
                
                // Her retry'da yeni connection
                curl_close($ch);
                $ch = curl_init($url_with_params);
                if ($ch === false) {
                    continue;
                }
                curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
                curl_setopt($ch, CURLOPT_TIMEOUT, 10);
                curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
                curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
                curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
                curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, false);
                curl_setopt($ch, CURLOPT_USERAGENT, 'UniPanel/1.0');
                if ($netgsm_ip !== 'api.netgsm.com.tr' && filter_var($netgsm_ip, FILTER_VALIDATE_IP)) {
                    curl_setopt($ch, CURLOPT_RESOLVE, ["api.netgsm.com.tr:80:$netgsm_ip"]);
                }
            }
            
            $response = curl_exec($ch);
            $curl_error = curl_error($ch);
            $http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
            
            // Başarılı response kontrolü
            if ($response !== false && empty($curl_error) && $http_code == 200) {
                $response_trimmed = trim($response);
                // "00" ile başlıyorsa başarılı
                if (substr($response_trimmed, 0, 2) === '00') {
                    $last_successful_response = $response_trimmed;
                    break; // Başarılı, çık
                }
            }
            
            // Fatal hatalar için retry yap (DNS çözümlenemezse bile retry yap)
            // Sadece çok kritik hatalar için durdur
            if (!empty($curl_error)) {
                $fatal_errors = [
                    'SSL certificate problem',
                    'certificate verify failed',
                    'unable to get local issuer certificate'
                ];
                $is_fatal = false;
                foreach ($fatal_errors as $fatal) {
                    if (stripos($curl_error, $fatal) !== false) {
                        $is_fatal = true;
                        break;
                    }
                }
                if ($is_fatal && $retry >= 3) {
                    // SSL hatası ve 3+ deneme yapıldıysa dur
                    tpl_error_log("NetGSM Fatal SSL error: $curl_error");
                    break;
                }
            }
        }
        
        // Son denemede başarılı response varsa kullan
        if ($last_successful_response !== false) {
            $response = $last_successful_response;
        }
        
        curl_close($ch);
        
        // Response validation - KESİN KONTROL (SMS KESİN GİTMELİ)
        $final_response = false;
        if ($last_successful_response !== false) {
            $final_response = trim($last_successful_response);
        } elseif ($response !== false) {
            $final_response = trim($response);
        }
        
        // Eğer hiç response yoksa hata döndür
        if ($final_response === false || empty($final_response)) {
            $error_msg = 'Bağlantı hatası: ' . ($curl_error ?: 'Yanıt alınamadı');
            tpl_error_log('NetGSM cURL Error: ' . $curl_error . ' (Retries: ' . $retry . ', HTTP: ' . $http_code . ')');
            return ['success' => false, 'error' => $error_msg . " (Tüm " . $max_retries . " deneme başarısız)", 'retryable' => true];
        }
        
        // Response validation - KESİN KONTROL (boşluk, yeni satır, vb. temizle)
        $final_response = trim($final_response);
        $final_response = preg_replace('/\s+/', '', $final_response); // Tüm boşlukları kaldır
        
        // KESİN BAŞARI KONTROLÜ - "00" ile başlamalı
        if (empty($final_response)) {
            tpl_error_log('NetGSM Empty Response Error');
            return ['success' => false, 'error' => 'NetGSM boş yanıt döndü (Tüm denemeler başarısız)', 'retryable' => true];
        }
        
        // İlk 2 karakter "00" olmalı - KESİN KONTROL
        $response_code = substr($final_response, 0, 2);
        
        if ($response_code === '00') {
            // Başarılı - NetGSM response formatı: "00 message_id" veya sadece "00"
            $message_id = strlen($final_response) > 2 ? substr($final_response, 2) : '';
            $message_id = trim($message_id);
            
            // KESİN BAŞARI - Response'u tekrar doğrula
            if (strlen($final_response) >= 2 && substr($final_response, 0, 2) === '00') {
                return ['success' => true, 'message_id' => $message_id, 'confirmed' => true, 'response' => $final_response];
            } else {
                // Response değişti, tekrar kontrol et
                tpl_error_log('NetGSM Response validation failed: ' . $final_response);
                return ['success' => false, 'error' => 'NetGSM yanıt doğrulaması başarısız', 'retryable' => true];
            }
        } else {
            // Hata kodları
            $error_messages = [
                '20' => 'Mesaj metni boş veya 160 karakterden uzun',
                '30' => 'Geçersiz kullanıcı adı veya şifre',
                '40' => 'Mesaj başlığı (msgheader) kayıtlı değil',
                '50' => 'Abone hesabında yeterli bakiye yok',
                '51' => 'Gönderilecek numara formatı hatalı',
                '70' => 'Hatalı sorgu. Gönderdiğiniz parametrelerden birisi hatalı veya zorunlu alanlardan birisi eksik',
                '80' => 'Gönderilecek numara sistemde tanımlı değil veya aktif değil',
                '85' => 'Mükerrer gönderim hatası',
            ];
            
            $error_code = substr($final_response, 0, 2);
            $error_msg = $error_messages[$error_code] ?? 'Bilinmeyen hata (Kod: ' . $error_code . ')';
            tpl_error_log('NetGSM SMS Error - Code: ' . $error_code . ', Message: ' . $error_msg);
            
            // Retry edilebilir hatalar (bazı hatalar geçici olabilir)
            $retryable_errors = ['20', '70', '80']; // Mesaj formatı, sorgu hatası, numara hatası
            $is_retryable = in_array($error_code, $retryable_errors);
            
            return [
                'success' => false, 
                'error' => $error_msg . ' (Kod: ' . $error_code . ')',
                'response_code' => $error_code,
                'response' => $final_response,
                'error_code' => $error_code,
                'retryable' => $is_retryable
            ];
        }
        
    } catch (Exception $e) {
        tpl_error_log('NetGSM SMS Exception: ' . $e->getMessage());
        return ['success' => false, 'error' => $e->getMessage()];
    }
}


function handle_send_message($post) {
    // Output buffer kontrolü - AJAX isteklerinde output'u engelle
    $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
    if ($isAjax) {
        // Tüm output'u engelle
        while (ob_get_level() > 0) {
            ob_end_clean();
        }
    }
    
    try {
        $db = get_db();
        
        // RATE LIMITS TABLOSUNU OLUŞTUR (Raporlar için gerekli)
        ensure_rate_limits_table($db);
        
        // Paket kontrolü - SMS gönderimi için Business paketi gerekli
        if (!function_exists('require_subscription_feature')) {
            require_once __DIR__ . '/../../lib/general/subscription_guard.php';
        }
        
        // Guard kontrolü - SMS özelliği için Business paketi gerekli
        if (!function_exists('has_subscription_feature')) {
            require_once __DIR__ . '/../../lib/general/subscription_helper.php';
        }
        
        if (!has_subscription_feature('sms')) {
            // Guard sayfasına yönlendir veya hata mesajı ayarla
            $isAjax = !empty($_SERVER['HTTP_X_REQUESTED_WITH']) && strtolower($_SERVER['HTTP_X_REQUESTED_WITH']) === 'xmlhttprequest';
            if ($isAjax) {
                // AJAX ise session'a hata yaz, üst handler JSON döndürecek
                $_SESSION['error'] = 'SMS gönderimi için Business paketine yükseltmeniz gerekiyor.';
                return;
            } else {
                // Guard sayfasına yönlendir
                require_subscription_feature('sms');
                return;
            }
        }
        
        // RATE LIMITING: Saatlik SMS/WhatsApp limiti kontrol et (100 mesaj/saat)
        cleanup_old_rate_limits($db);
        $rate_check = check_rate_limit($db, 'sms', 100);
        if (!$rate_check['allowed']) {
            $_SESSION['error'] = $rate_check['message'];
            return;
        }
        try {
            $message_template = tpl_validate_string($post['sms_body'] ?? '', [
                'field' => 'SMS içeriği',
                'min' => 5,
                'max' => 2000,
            ]);
        } catch (TplValidationException $validationException) {
            $_SESSION['error'] = $validationException->getMessage();
            return;
        }
        
        // SMS içeriğini validate et
        $sms_validation = validate_sms_content($message_template);
        if (!$sms_validation['valid']) {
            // Sadece kritik hatalar (boş mesaj gibi) engelleme yapar
            // Uzunluk uyarıları sadece bilgilendirme amaçlı
            $critical_errors = array_filter($sms_validation['errors'], function($error) {
                return strpos($error, 'boş') !== false;
            });
            
            if (!empty($critical_errors)) {
                $_SESSION['error'] = "SMS mesajı geçersiz: " . implode(', ', $critical_errors);
                return;
            }
        }
        
        // SMS uzunluğu bilgilendirmesi (uyarı değil, bilgi)
        if ($sms_validation['estimated_sms_count'] > 1) {
            $sms_info = "📱 Mesaj " . $sms_validation['estimated_sms_count'] . " SMS olarak gönderilecek";
            if ($sms_validation['has_turkish']) {
                $sms_info .= " (Türkçe karakter içeriyor, 70 karakter/SMS)";
            } else {
                $sms_info .= " (160 karakter/SMS)";
            }
            $sms_info .= " - Toplam: " . $sms_validation['length'] . " karakter";
            
            // Sadece çok uzun mesajlar için uyarı göster
            if ($sms_validation['estimated_sms_count'] > 5) {
                $_SESSION['warning'] = $sms_info;
            } else {
                // Normal uzunlukta mesajlar için sessizce devam et
                tpl_error_log("SMS Info: " . $sms_info);
            }
        }
        
        $club_name = get_setting('club_name', 'Topluluk');
        $allow_duplicates = !empty($post['allow_duplicate_sms']);
        // SADECE NETGSM - Twilio kaldırıldı
        $sms_provider = 'netgsm'; // Sadece NetGSM
        
        // NetGSM bilgilerini güvenli şekilde çek
        try {
            $netgsm_username = get_netgsm_credential('username');
            $netgsm_password = get_netgsm_credential('password');
            $netgsm_msgheader = get_netgsm_credential('msgheader');
            
            tpl_error_log('NetGSM Credentials Check - Username: ' . (!empty($netgsm_username) ? 'SET (' . strlen($netgsm_username) . ' chars)' : 'EMPTY') . ', Password: ' . (!empty($netgsm_password) ? 'SET (' . strlen($netgsm_password) . ' chars)' : 'EMPTY') . ', MsgHeader: ' . (!empty($netgsm_msgheader) ? 'SET (' . $netgsm_msgheader . ')' : 'EMPTY'));
        } catch (Exception $e) {
            tpl_error_log('NetGSM Credentials Error: ' . $e->getMessage());
            error_log('NetGSM Credentials Error: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
            $netgsm_username = '';
            $netgsm_password = '';
            $netgsm_msgheader = '';
        } catch (Error $e) {
            tpl_error_log('NetGSM Credentials Fatal Error: ' . $e->getMessage());
            error_log('NetGSM Credentials Fatal Error: ' . $e->getMessage());
            $netgsm_username = '';
            $netgsm_password = '';
            $netgsm_msgheader = '';
        }

        // Force constants kontrolü
        if (defined('NETGSM_FORCE_USERNAME') && constant('NETGSM_FORCE_USERNAME') !== '') {
            $netgsm_username = constant('NETGSM_FORCE_USERNAME');
            tpl_error_log('NetGSM Username overridden by NETGSM_FORCE_USERNAME constant');
        }
        if (defined('NETGSM_FORCE_PASSWORD') && constant('NETGSM_FORCE_PASSWORD') !== '') {
            $netgsm_password = constant('NETGSM_FORCE_PASSWORD');
            tpl_error_log('NetGSM Password overridden by NETGSM_FORCE_PASSWORD constant');
        }
        if (defined('NETGSM_FORCE_MSGHEADER') && constant('NETGSM_FORCE_MSGHEADER') !== '') {
            $netgsm_msgheader = constant('NETGSM_FORCE_MSGHEADER');
            tpl_error_log('NetGSM MsgHeader overridden by NETGSM_FORCE_MSGHEADER constant');
        }
        
        // NetGSM bilgileri kontrolü - daha detaylı hata mesajı
        if (empty($netgsm_username) || empty($netgsm_password)) {
            $missing = [];
            if (empty($netgsm_username)) $missing[] = 'Kullanıcı Adı';
            if (empty($netgsm_password)) $missing[] = 'Şifre';
            
            $error_msg = "NetGSM ayarları eksik! Eksik alanlar: " . implode(', ', $missing) . ". ";
            $error_msg .= "Lütfen Ayarlar → SMS API Ayarları'ndan NetGSM bilgilerini girin veya superadmin/config.php dosyasına ekleyin.";
            
            $_SESSION['error'] = $error_msg;
            tpl_error_log('NetGSM Missing Credentials: ' . implode(', ', $missing));
            return;
        }
        
        // Alıcıları belirle
        $recipients = [];

        if (!empty($post['selected_phones_json'])) {
            $decodedPhones = json_decode($post['selected_phones_json'], true);
            if (is_array($decodedPhones)) {
                $recipients = array_merge($recipients, $decodedPhones);
            }
        }
    if (isset($post['selected_phones']) && is_array($post['selected_phones'])) {
            $recipients = array_merge($recipients, $post['selected_phones']);
        }
        if (isset($post['recipients']) && $post['recipients'] === 'Tüm Üyeler') {
            $contacts = get_sms_member_contacts();
            foreach ($contacts as $contact) {
                if (!empty($contact['phone_number'])) {
                    $recipients[] = $contact['phone_number'];
                }
            }
        }

        $recipients = array_values(array_unique(array_filter(array_map(function($phone) {
            return trim((string)$phone);
        }, $recipients))));
        
        if (empty($recipients)) {
            $_SESSION['error'] = "Alıcı seçilmedi!";
            return;
        }
        
        // SADECE NETGSM - Twilio ve WhatsApp kaldırıldı
        if ($sms_provider !== 'netgsm') {
            $_SESSION['error'] = "Sadece NetGSM desteklenmektedir. Lütfen Ayarlar → SMS API Ayarları'ndan NetGSM'i seçin.";
            tpl_error_log('SMS Provider Error: ' . $sms_provider . ' is not supported. Only NetGSM is allowed.');
            return;
        }
        
        // SMS limit kontrolü - Business plan için
        $recipient_count = count($recipients);
        $subscriptionManager = null;
        try {
            if (!function_exists('get_subscription_manager')) {
                require_once __DIR__ . '/../../lib/general/subscription_helper.php';
            }
            if (defined('COMMUNITY_ID') && COMMUNITY_ID) {
                $subscriptionManager = get_subscription_manager();
                if ($subscriptionManager) {
                    $subscriptionManager->createSubscriptionTable(); // Tabloyu oluştur
                    $smsCheck = $subscriptionManager->canSendSms($recipient_count);
                    if (!$smsCheck['allowed']) {
                        $errorMessage = $smsCheck['message'] ?? 'SMS gönderim limiti aşıldı. Ek paket almanız gerekiyor.';
                        $_SESSION['error'] = $errorMessage;
                        return;
                    }
                }
            }
        } catch (Exception $e) {
            // SMS limit kontrolü hatası - devam et ama logla
            error_log("SMS limit check error: " . $e->getMessage());
            tpl_error_log("SMS limit check error: " . $e->getMessage());
        } catch (Error $e) {
            // Fatal error yakalama
            error_log("SMS limit check fatal error: " . $e->getMessage());
            tpl_error_log("SMS limit check fatal error: " . $e->getMessage());
        }
        
        $member_name_map = get_member_names_for_phones($recipients);
        
        $sent_count = 0;
        $failed_count = 0;
        $errors = [];
        
        // SADECE NETGSM - Maksimum optimizasyon ile gönder
        if ($sms_provider === 'netgsm') {
            // Bu kontrol yukarıda yapıldı, burada sadece log
            tpl_error_log('NetGSM SMS Send Attempt - Recipients: ' . count($recipients) . ', Username: ' . (!empty($netgsm_username) ? 'SET' : 'EMPTY') . ', Password: ' . (!empty($netgsm_password) ? 'SET' : 'EMPTY') . ', MsgHeader: ' . ($netgsm_msgheader ?? 'EMPTY'));
            
            foreach ($recipients as $phone) {
                tpl_error_log('NetGSM SMS Attempt to: ' . $phone);
                
                // Telefon numarasını validate et
                $phone_validation = validate_and_normalize_phone($phone);
                if (!$phone_validation['valid']) {
                    $failed_count++;
                    $error_msg = $phone_validation['error'];
                    // "The string did not match the expected pattern" hatasını daha açıklayıcı hale getir
                    if (strpos($error_msg, 'pattern') !== false || strpos($error_msg, 'match') !== false) {
                        $error_msg = 'Geçersiz telefon numarası formatı: ' . $phone . '. Türkiye numarası olmalı (örn: 5551234567 veya 05341234567)';
                    }
                    $errors[] = $phone . ': ' . $error_msg;
                    tpl_error_log('NetGSM SMS Invalid Phone: ' . $phone . ' - ' . $error_msg);
                    continue;
                }
                
                $normalized_phone = $phone_validation['phone'];
                
                // Duplicate SMS kontrolü
                $member_name = $member_name_map[$normalized_phone] ?? null;
                $final_message = personalize_sms_message($message_template, $member_name, $phone, $club_name);
                
                // Duplicate kontrolü - sadece aynı mesaj için (2 dakika içinde)
                // Not: Farklı mesajlar gönderilebilir, sadece aynı mesajın tekrarı engellenir
                if (!$allow_duplicates && check_duplicate_sms($db, $normalized_phone, $final_message, 2)) {
                    $errors[] = $phone . ': Bu mesaj kısa süre önce gönderildi (duplicate)';
                    tpl_error_log('NetGSM SMS Duplicate: ' . $phone);
                    continue;
                }
                
                // NetGSM ile direkt gönder - KESİN GİTMESİ İÇİN ekstra kontroller
                $result = send_sms_netgsm($phone, $final_message, $netgsm_username, $netgsm_password, $netgsm_msgheader);
                
                // KESİN BAŞARI KONTROLÜ - SADECE confirmed=true olanları say
                $sms_sent_this_phone = false;
                if ($result['success'] && isset($result['confirmed']) && $result['confirmed'] === true) {
                    $sent_count++;
                    $sms_sent_this_phone = true;
                    $message_id = $result['message_id'] ?? 'N/A';
                    tpl_error_log('NetGSM SMS CONFIRMED SUCCESS to: ' . $phone . ' - Message ID: ' . $message_id);
                    
                    // SMS kullanımını HEMEN kaydet (her başarılı gönderimde)
                    try {
                        if (!function_exists('get_subscription_manager')) {
                            require_once __DIR__ . '/../../lib/general/subscription_helper.php';
                        }
                        if (defined('COMMUNITY_ID') && COMMUNITY_ID) {
                            $subscriptionManager = get_subscription_manager();
                            if ($subscriptionManager) {
                                $subscriptionManager->createSubscriptionTable();
                                
                                // Önce SMS kredilerinden kullan (varsa)
                                $creditsRemaining = $subscriptionManager->useSmsCredits(1);
                                if ($creditsRemaining == 0) {
                                    // Kredi kullanıldı, sadece logla
                                    tpl_error_log("SMS credit used for $phone: 1 SMS from credits");
                                } else {
                                    // Kredi yok veya yetersiz, normal kullanım kaydı yap
                                    $subscriptionManager->recordSmsUsage(1, $final_message, 'netgsm');
                                    tpl_error_log("SMS usage recorded immediately for $phone: 1 SMS (no credits available)");
                                }
                            }
                        }
                    } catch (Exception $e) {
                        error_log("SMS usage record error for $phone: " . $e->getMessage());
                        tpl_error_log("SMS usage record error for $phone: " . $e->getMessage());
                    } catch (Error $e) {
                        error_log("SMS usage record fatal error for $phone: " . $e->getMessage());
                        tpl_error_log("SMS usage record fatal error for $phone: " . $e->getMessage());
                    }
                    
                    // RAPORLAR İÇİN: rate_limits tablosuna kaydet (raporlar buradan okuyor)
                    try {
                        increment_rate_limit($db, 'sms');
                        tpl_error_log("Rate limit incremented for $phone (reports tracking)");
                    } catch (Exception $e) {
                        error_log("Rate limit increment error for $phone: " . $e->getMessage());
                        tpl_error_log("Rate limit increment error for $phone: " . $e->getMessage());
                    } catch (Error $e) {
                        error_log("Rate limit increment fatal error for $phone: " . $e->getMessage());
                        tpl_error_log("Rate limit increment fatal error for $phone: " . $e->getMessage());
                    }
                } elseif ($result['success']) {
                    // Başarılı ama confirmed yok - TEKRAR DENEMELİYİZ (güvenilir değil)
                    tpl_error_log('NetGSM SMS Success but NOT CONFIRMED to: ' . $phone . ' - Retrying to confirm...');
                    
                    // Tekrar dene - confirmed almak için
                    $retry_success = false;
                    for ($confirm_retry = 0; $confirm_retry < 3; $confirm_retry++) {
                        sleep(1 + $confirm_retry); // 1, 2, 3 saniye
                        $confirm_result = send_sms_netgsm($phone, $final_message, $netgsm_username, $netgsm_password, $netgsm_msgheader);
                        if ($confirm_result['success'] && isset($confirm_result['confirmed']) && $confirm_result['confirmed'] === true) {
                            $sent_count++;
                            $sms_sent_this_phone = true;
                            $message_id = $confirm_result['message_id'] ?? 'N/A';
                            tpl_error_log('NetGSM SMS CONFIRMED on retry ' . ($confirm_retry + 1) . ' to: ' . $phone . ' - Message ID: ' . $message_id);
                            
                            // SMS kullanımını HEMEN kaydet
                            try {
                                if (!function_exists('get_subscription_manager')) {
                                    require_once __DIR__ . '/../../lib/general/subscription_helper.php';
                                }
                                if (defined('COMMUNITY_ID') && COMMUNITY_ID) {
                                    $subscriptionManager = get_subscription_manager();
                                    if ($subscriptionManager) {
                                        $subscriptionManager->createSubscriptionTable();
                                        
                                        // Önce SMS kredilerinden kullan (varsa)
                                        $creditsRemaining = $subscriptionManager->useSmsCredits(1);
                                        if ($creditsRemaining == 0) {
                                            tpl_error_log("SMS credit used on retry for $phone: 1 SMS from credits");
                                        } else {
                                            $subscriptionManager->recordSmsUsage(1, $final_message, 'netgsm');
                                            tpl_error_log("SMS usage recorded on retry for $phone: 1 SMS (no credits available)");
                                        }
                                    }
                                }
                            } catch (Exception $e) {
                                error_log("SMS usage record error for $phone: " . $e->getMessage());
                                tpl_error_log("SMS usage record error for $phone: " . $e->getMessage());
                            }
                            
                            // RAPORLAR İÇİN: rate_limits tablosuna kaydet
                            try {
                                increment_rate_limit($db, 'sms');
                                tpl_error_log("Rate limit incremented on retry for $phone (reports tracking)");
                            } catch (Exception $e) {
                                error_log("Rate limit increment error for $phone: " . $e->getMessage());
                                tpl_error_log("Rate limit increment error for $phone: " . $e->getMessage());
                            }
                            
                            $retry_success = true;
                            break;
                        }
                    }
                    
                    if (!$retry_success) {
                        // Confirmed alamadık - başarısız say
                        $failed_count++;
                        $error_msg = 'SMS gönderildi ancak doğrulama yapılamadı (confirmed=false)';
                        $errors[] = $phone . ': ' . $error_msg;
                        tpl_error_log('NetGSM SMS NOT CONFIRMED to: ' . $phone . ' - All confirmation retries failed');
                    }
                } else {
                    // Başarısız - ekstra deneme yap (KESİN GİTMESİ İÇİN)
                    tpl_error_log('NetGSM SMS Failed to: ' . $phone . ' - Retrying with extra attempt...');
                    
                    // Son bir şans daha - 5 ekstra deneme (KESİN GİTMESİ İÇİN)
                    $extra_success = false;
                    for ($extra = 0; $extra < 5; $extra++) {
                        $extra_delay = 2 + ($extra * 2); // 2, 4, 6, 8, 10 saniye
                        tpl_error_log("NetGSM Extra Retry $extra/5 for $phone after $extra_delay seconds");
                        sleep($extra_delay);
                        
                        $extra_result = send_sms_netgsm($phone, $final_message, $netgsm_username, $netgsm_password, $netgsm_msgheader);
                        if ($extra_result['success'] && isset($extra_result['confirmed']) && $extra_result['confirmed'] === true) {
                            $sent_count++;
                            $sms_sent_this_phone = true;
                            $message_id = $extra_result['message_id'] ?? 'N/A';
                            tpl_error_log('NetGSM SMS EXTRA SUCCESS to: ' . $phone . ' on extra attempt ' . ($extra + 1) . ' - Message ID: ' . $message_id);
                            
                            // SMS kullanımını HEMEN kaydet
                            try {
                                if (!function_exists('get_subscription_manager')) {
                                    require_once __DIR__ . '/../../lib/general/subscription_helper.php';
                                }
                                if (defined('COMMUNITY_ID') && COMMUNITY_ID) {
                                    $subscriptionManager = get_subscription_manager();
                                    if ($subscriptionManager) {
                                        $subscriptionManager->createSubscriptionTable();
                                        $subscriptionManager->recordSmsUsage(1, $final_message, 'netgsm');
                                        tpl_error_log("SMS usage recorded on extra retry for $phone: 1 SMS");
                                    }
                                }
                            } catch (Exception $e) {
                                error_log("SMS usage record error for $phone: " . $e->getMessage());
                                tpl_error_log("SMS usage record error for $phone: " . $e->getMessage());
                            }
                            
                            // RAPORLAR İÇİN: rate_limits tablosuna kaydet
                            try {
                                increment_rate_limit($db, 'sms');
                                tpl_error_log("Rate limit incremented on extra retry for $phone (reports tracking)");
                            } catch (Exception $e) {
                                error_log("Rate limit increment error for $phone: " . $e->getMessage());
                                tpl_error_log("Rate limit increment error for $phone: " . $e->getMessage());
                            }
                            
                            $extra_success = true;
                            break;
                        }
                    }
                    
                    if (!$extra_success) {
                        $failed_count++;
                        $error_msg = $result['error'] ?? 'Bilinmeyen hata (Tüm denemeler başarısız - 10 + 5 ekstra = 15 toplam deneme)';
                        $errors[] = $phone . ': ' . $error_msg;
                        tpl_error_log('NetGSM SMS FINAL FAILED to: ' . $phone . ' - Error: ' . $error_msg . ' (Total attempts: 15)');
                    }
                }
            }
        } else {
            $_SESSION['error'] = "Sadece NetGSM desteklenmektedir. Lütfen Ayarlar → SMS API Ayarları'ndan NetGSM bilgilerini girin.";
            tpl_error_log('SMS Provider Error: ' . $sms_provider . ' is not supported. Only NetGSM is allowed.');
            return;
        }
        
        // Sonuç mesajı - Sadece NetGSM
        $provider_name = 'SMS (NetGSM)';
        
        // SMS gönderiminin tamamlandığından emin ol - logla
        tpl_error_log("SMS Send Complete - Sent: $sent_count, Failed: $failed_count, Total Recipients: " . count($recipients));
        
        // NOT: SMS kullanımı artık her başarılı gönderimde (loop içinde) kaydediliyor
        // rate_limits tablosuna da her başarılı gönderimde kaydediliyor (raporlar için)
        // Burada sadece özet log tutuyoruz
        if ($sent_count > 0) {
            tpl_error_log("SMS usage summary: $sent_count SMS sent and recorded individually (both sms_usage and rate_limits tables)");
            
            // RAPORLAR İÇİN KONTROL: rate_limits tablosunda kayıt var mı?
            $check_stmt = $db->prepare("SELECT SUM(action_count) as total FROM rate_limits WHERE club_id = ? AND action_type = 'sms'");
            $check_stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
            $check_result = $check_stmt->execute();
            $check_row = $check_result->fetchArray(SQLITE3_ASSOC);
            $total_in_rate_limits = (int)($check_row['total'] ?? 0);
            tpl_error_log("Rate limits table check: Total SMS in rate_limits = $total_in_rate_limits (Expected at least $sent_count from this send)");
            
            $message_text = "{$provider_name} başarıyla gönderildi! 📱 Gönderilen: {$sent_count}, Başarısız: {$failed_count}";
            if ($failed_count > 0 && count($errors) <= 5) {
                $message_text .= "\nHatalar: " . implode(', ', $errors);
            }
            $_SESSION['message'] = $message_text;
            // Mesaj sekmesinde kal - yönlendirme yapma
            $_SESSION['stay_on_messages'] = true;
        } else {
            $error_summary = count($errors) > 0 ? " İlk hata: " . $errors[0] : "";
            $_SESSION['error'] = "Hiçbir {$provider_name} gönderilemedi! ({$failed_count} deneme başarısız)" . $error_summary . " Lütfen Ayarlar → SMS API Ayarları'ndan bilgileri kontrol edin ve error.log dosyasına bakın.";
            tpl_error_log($provider_name . ' Send Failed - All attempts failed. Total: ' . count($recipients));
            // Mesaj sekmesinde kal - yönlendirme yapma
            $_SESSION['stay_on_messages'] = true;
        }

        if (!empty($errors)) {
            $_SESSION['sms_errors'] = array_slice($errors, 0, 15);
        } else {
            unset($_SESSION['sms_errors']);
        }
        
    } catch (Exception $e) {
        $_SESSION['error'] = "SMS gönderme hatası: " . $e->getMessage();
        tpl_error_log('SMS send error: ' . $e->getMessage());
        error_log('SMS send exception: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
    } catch (Error $e) {
        // Fatal error yakalama (Parse errors, Type errors, vb.)
        $_SESSION['error'] = "SMS gönderme hatası oluştu. Lütfen tekrar deneyin.";
        tpl_error_log('SMS send fatal error: ' . $e->getMessage());
        error_log('SMS send fatal error: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
    } catch (Throwable $e) {
        // Tüm hataları yakala (Exception ve Error'ın üst sınıfı)
        $_SESSION['error'] = "SMS gönderme hatası oluştu. Lütfen tekrar deneyin.";
        tpl_error_log('SMS send throwable error: ' . $e->getMessage());
        error_log('SMS send throwable error: ' . $e->getMessage() . ' | Trace: ' . $e->getTraceAsString());
    }
}

/**
 * İşbirliği logosu yükleme işlemi
 */

// ============================================
// GERÇEK HAYAT SENARYOLARI İÇİN OPTİMİZASYONLAR
// ============================================

/**
 * Email adresini validate et ve normalize et
 */
function validate_and_normalize_email($email) {
    if (empty($email)) {
        return ['valid' => false, 'error' => 'Email adresi boş'];
    }
    
    $email = trim(strtolower($email));
    
    // Email format kontrolü
    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        return ['valid' => false, 'error' => 'Geçersiz email formatı'];
    }
    
    // Email uzunluk kontrolü (RFC 5321: 320 karakter max)
    if (strlen($email) > 320) {
        return ['valid' => false, 'error' => 'Email adresi çok uzun (max 320 karakter)'];
    }
    
    // Disposable email kontrolü (opsiyonel - gerçek hayatta spam önleme için)
    $disposable_domains = ['tempmail.com', '10minutemail.com', 'guerrillamail.com'];
    $domain = substr(strrchr($email, "@"), 1);
    if (in_array($domain, $disposable_domains)) {
        return ['valid' => false, 'error' => 'Geçici email adresleri kabul edilmiyor'];
    }
    
    return ['valid' => true, 'email' => $email];
}

/**
 * Telefon numarasını validate et ve normalize et
 */
function validate_and_normalize_phone($phone) {
    if (empty($phone)) {
        return ['valid' => false, 'error' => 'Telefon numarası boş'];
    }
    
    $original_phone = $phone;
    
    // Önce trim yap
    $phone = trim((string)$phone);
    
    // Boşluk, tire, parantez gibi karakterleri kaldır
    $phone = preg_replace('/[\s\-\(\)]+/', '', $phone);
    
    // normalize_phone_number fonksiyonunu kullan
    $normalized = normalize_phone_number($phone);
    
    // Boş kontrolü
    if (empty($normalized)) {
        tpl_error_log('validate_and_normalize_phone: Normalize edilmiş numara boş. Orijinal: ' . $original_phone);
        return ['valid' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_phone];
    }
    
    // Türkiye telefon numarası kontrolü (10 haneli olmalı)
    if (strlen($normalized) < 10 || strlen($normalized) > 15) {
        tpl_error_log('validate_and_normalize_phone: Geçersiz uzunluk. Normalize: ' . $normalized . ', Orijinal: ' . $original_phone . ', Uzunluk: ' . strlen($normalized));
        return ['valid' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_phone . ' (Uzunluk: ' . strlen($normalized) . ', Beklenen: 10-15)'];
    }
    
    // Sadece rakam kontrolü
    if (!preg_match('/^[0-9]+$/', $normalized)) {
        tpl_error_log('validate_and_normalize_phone: Sadece rakam değil. Normalize: ' . $normalized . ', Orijinal: ' . $original_phone);
        return ['valid' => false, 'error' => 'Telefon numarası sadece rakam içermeli: ' . $original_phone];
    }
    
    // Türkiye numarası kontrolü - 10 haneli ve 5 ile başlamalı (5428055983 formatı)
    if (strlen($normalized) != 10) {
        tpl_error_log('validate_and_normalize_phone: Geçersiz uzunluk. Normalize: ' . $normalized . ', Orijinal: ' . $original_phone . ', Uzunluk: ' . strlen($normalized) . ' (Beklenen: 10)');
        return ['valid' => false, 'error' => 'Geçersiz telefon numarası formatı: ' . $original_phone . ' (10 haneli olmalı, örn: 5428055983)'];
    }
    
    if (substr($normalized, 0, 1) != '5') {
        tpl_error_log('validate_and_normalize_phone: Türkiye numarası formatı değil. Normalize: ' . $normalized . ', Orijinal: ' . $original_phone);
        return ['valid' => false, 'error' => 'Geçersiz Türkiye telefon numarası formatı: ' . $original_phone . ' (5 ile başlamalı, örn: 5428055983)'];
    }
    
    return ['valid' => true, 'phone' => $normalized];
}

/**
 * Email içeriğini validate et
 */
function validate_email_content($subject, $message) {
    $errors = [];
    
    // Subject kontrolü
    if (empty(trim($subject))) {
        $errors[] = 'Konu boş olamaz';
    } elseif (strlen($subject) > 200) {
        $errors[] = 'Konu çok uzun (max 200 karakter)';
    }
    
    // Message kontrolü
    if (empty(trim(strip_tags($message)))) {
        $errors[] = 'Mesaj içeriği boş olamaz';
    } elseif (strlen($message) > 1000000) { // 1MB limit
        $errors[] = 'Mesaj içeriği çok uzun (max 1MB)';
    }
    
    // Spam kelime kontrolü (opsiyonel)
    $spam_words = ['viagra', 'casino', 'lottery'];
    $message_lower = strtolower($message);
    foreach ($spam_words as $word) {
        if (strpos($message_lower, $word) !== false) {
            $errors[] = 'Mesaj içeriği spam olarak algılandı';
            break;
        }
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors
    ];
}

/**
 * SMS mesajını validate et
 */
function validate_sms_content($message) {
    $errors = [];
    
    if (empty(trim($message))) {
        $errors[] = 'SMS mesajı boş olamaz';
        return [
            'valid' => false,
            'errors' => $errors,
            'has_turkish' => false,
            'length' => 0,
            'estimated_sms_count' => 0
        ];
    }
    
    $length = mb_strlen($message);
    
    // Türkçe karakter kontrolü (GSM 7-bit encoding için bilgi amaçlı)
    $turkish_chars = ['ç', 'ğ', 'ı', 'ö', 'ş', 'ü', 'Ç', 'Ğ', 'İ', 'Ö', 'Ş', 'Ü'];
    $has_turkish = false;
    foreach ($turkish_chars as $char) {
        if (mb_strpos($message, $char) !== false) {
            $has_turkish = true;
            break;
        }
    }
    
    // SMS sayısı tahmini:
    // - Türkçe karakter yoksa: 160 karakter = 1 SMS
    // - Türkçe karakter varsa: 70 karakter = 1 SMS (GSM 7-bit extended)
    // - Çok uzun mesajlar otomatik olarak çoklu SMS olarak gönderilir
    $estimated_sms_count = $has_turkish ? ceil($length / 70) : ceil($length / 160);
    
    // Çok uzun mesajlar için uyarı (ama engelleme yok)
    // Max 10 SMS (yaklaşık 700-1600 karakter) makul bir limit
    if ($estimated_sms_count > 10) {
        $errors[] = "Mesaj çok uzun! Yaklaşık {$estimated_sms_count} SMS olarak gönderilecek. Lütfen kısaltın.";
    }
    
    return [
        'valid' => empty($errors),
        'errors' => $errors,
        'has_turkish' => $has_turkish,
        'length' => $length,
        'estimated_sms_count' => $estimated_sms_count
    ];
}

/**
 * Duplicate email kontrolü (aynı kampanyada aynı email'e tekrar gönderilmesini önle)
 */
function check_duplicate_email($db, $campaign_id, $recipient_email) {
    try {
        $stmt = $db->prepare("SELECT id FROM email_queue WHERE campaign_id = ? AND recipient_email = ? AND status IN ('pending', 'sending', 'sent') LIMIT 1");
        $stmt->bindValue(1, $campaign_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, strtolower(trim($recipient_email)), SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        return $row !== false;
    } catch (Exception $e) {
        tpl_error_log("Duplicate email check error: " . $e->getMessage());
        return false; // Hata durumunda duplicate olarak işaretleme
    }
}

/**
 * Duplicate SMS kontrolü (aynı numaraya kısa sürede tekrar gönderilmesini önle)
 * Not: Duplicate kontrolü sadece aynı mesaj için geçerli, farklı mesajlar gönderilebilir
 */
function check_duplicate_sms($db, $recipient_phone, $message, $time_window_minutes = 2) {
    try {
        $normalized_phone = normalize_phone_number($recipient_phone);
        $time_threshold = date('Y-m-d H:i:s', strtotime("-$time_window_minutes minutes"));
        
        // Mesajın hash'ini al (uzun mesajlar için)
        $message_hash = md5($message);
        
        // Sadece aynı mesaj ve aynı numara için kontrol et
        $stmt = $db->prepare("SELECT id FROM sms_queue WHERE recipient_phone = ? AND message = ? AND created_at > ? AND status IN ('pending', 'sending', 'sent') LIMIT 1");
        $stmt->bindValue(1, $normalized_phone, SQLITE3_TEXT);
        $stmt->bindValue(2, $message, SQLITE3_TEXT);
        $stmt->bindValue(3, $time_threshold, SQLITE3_TEXT);
        $result = $stmt->execute();
        $row = $result->fetchArray(SQLITE3_ASSOC);
        return $row !== false;
    } catch (Exception $e) {
        tpl_error_log("Duplicate SMS check error: " . $e->getMessage());
        // Hata durumunda duplicate olarak işaretleme (güvenlik için)
        return false;
    }
}

/**
 * Exponential backoff ile retry zamanını hesapla
 */
function calculate_next_retry_time($attempts, $base_delay_minutes = 5) {
    // Exponential backoff: 5, 10, 20, 40 dakika...
    $delay = $base_delay_minutes * pow(2, $attempts - 1);
    // Max 24 saat
    $delay = min($delay, 1440);
    return date('Y-m-d H:i:s', strtotime("+$delay minutes"));
}

/**
 * Email bounce kaydı oluştur
 */
function log_email_bounce($db, $queue_id, $recipient_email, $bounce_type, $bounce_reason, $bounce_message = '') {
    try {
        ensure_email_tables($db);
        
        $stmt = $db->prepare("INSERT INTO email_bounces (club_id, recipient_email, bounce_type, bounce_reason, bounce_message, queue_id) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(2, $recipient_email, SQLITE3_TEXT);
        $stmt->bindValue(3, $bounce_type, SQLITE3_TEXT); // 'hard' veya 'soft'
        $stmt->bindValue(4, $bounce_reason, SQLITE3_TEXT);
        $stmt->bindValue(5, $bounce_message, SQLITE3_TEXT);
        $stmt->bindValue(6, $queue_id, SQLITE3_INTEGER);
        $stmt->execute();
        
        // Email queue'da is_bounced flag'ini set et
        $update_stmt = $db->prepare("UPDATE email_queue SET is_bounced = 1, bounce_reason = ? WHERE id = ?");
        $update_stmt->bindValue(1, $bounce_reason, SQLITE3_TEXT);
        $update_stmt->bindValue(2, $queue_id, SQLITE3_INTEGER);
        $update_stmt->execute();
    } catch (Exception $e) {
        tpl_error_log("Email bounce log error: " . $e->getMessage());
    }
}

/**
 * Email delivery log kaydı oluştur
 */
function log_email_delivery($db, $queue_id, $recipient_email, $delivery_status, $smtp_response, $provider = 'smtp') {
    try {
        ensure_email_tables($db);
        
        $stmt = $db->prepare("INSERT INTO email_delivery_logs (queue_id, club_id, recipient_email, delivery_status, smtp_response, provider) VALUES (?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $queue_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(3, $recipient_email, SQLITE3_TEXT);
        $stmt->bindValue(4, $delivery_status, SQLITE3_TEXT); // 'sent', 'delivered', 'bounced', 'failed'
        $stmt->bindValue(5, $smtp_response, SQLITE3_TEXT);
        $stmt->bindValue(6, $provider, SQLITE3_TEXT);
        $stmt->execute();
    } catch (Exception $e) {
        tpl_error_log("Email delivery log error: " . $e->getMessage());
    }
}

/**
 * SMS delivery log kaydı oluştur
 */
function log_sms_delivery($db, $queue_id, $recipient_phone, $delivery_status, $provider_response, $provider = 'netgsm', $cost = 0) {
    try {
        ensure_email_tables($db); // SMS tabloları da burada oluşturuluyor
        
        $stmt = $db->prepare("INSERT INTO sms_delivery_logs (queue_id, club_id, recipient_phone, delivery_status, provider_response, provider, cost) VALUES (?, ?, ?, ?, ?, ?, ?)");
        $stmt->bindValue(1, $queue_id, SQLITE3_INTEGER);
        $stmt->bindValue(2, CLUB_ID, SQLITE3_INTEGER);
        $stmt->bindValue(3, $recipient_phone, SQLITE3_TEXT);
        $stmt->bindValue(4, $delivery_status, SQLITE3_TEXT);
        $stmt->bindValue(5, $provider_response, SQLITE3_TEXT);
        $stmt->bindValue(6, $provider, SQLITE3_TEXT);
        $stmt->bindValue(7, $cost, SQLITE3_REAL);
        $stmt->execute();
    } catch (Exception $e) {
        tpl_error_log("SMS delivery log error: " . $e->getMessage());
    }
}

/**
 * SMTP bağlantı timeout ve retry mekanizması
 */
function send_smtp_mail_with_retry($to, $subject, $message, $from_name, $from_email, $config = [], $max_retries = 3) {
    $attempts = 0;
    $last_error = null;
    
    while ($attempts < $max_retries) {
        $attempts++;
        
        try {
            $result = send_smtp_mail($to, $subject, $message, $from_name, $from_email, $config);
            
            if ($result) {
                return ['success' => true, 'attempts' => $attempts];
            }
            
            $last_error = 'SMTP gönderim başarısız';
            
            // Exponential backoff: 2, 4, 8 saniye
            if ($attempts < $max_retries) {
                $delay = pow(2, $attempts);
                sleep($delay);
            }
        } catch (Exception $e) {
            $last_error = $e->getMessage();
            
            // Network hatası ise retry yap
            if (strpos($last_error, 'timeout') !== false || strpos($last_error, 'connection') !== false) {
                if ($attempts < $max_retries) {
                    $delay = pow(2, $attempts);
                    sleep($delay);
                    continue;
                }
            } else {
                // Fatal hata, retry yapma
                break;
            }
        }
    }
    
    return ['success' => false, 'attempts' => $attempts, 'error' => $last_error];
}

/**
 * SMS gönderim retry mekanizması (provider failover ile) - İyileştirilmiş versiyon
 */
function send_sms_with_retry_and_failover($to, $message, $primary_provider = 'netgsm', $max_retries = 5) {
    $total_attempts = 0;
    $last_error = null;
    $last_error_code = null;
    $providers = [$primary_provider];
    
    // Failover: NetGSM başarısız olursa Twilio'ya geç (eğer Twilio ayarları varsa)
    if ($primary_provider === 'netgsm') {
        $twilio_account_sid = get_setting('twilio_account_sid', '');
        if (!empty($twilio_account_sid)) {
            $providers[] = 'twilio';
        }
    } else {
        $netgsm_username = get_netgsm_credential('username');
        if (!empty($netgsm_username)) {
            $providers[] = 'netgsm';
        }
    }
    
    foreach ($providers as $provider) {
        $attempts = 0;
        
        while ($attempts < $max_retries) {
            $attempts++;
            $total_attempts++;
            
            try {
                if ($provider === 'netgsm') {
                    $netgsm_username = get_netgsm_credential('username');
                    $netgsm_password = get_netgsm_credential('password');
                    $netgsm_msgheader = get_netgsm_credential('msgheader');
                    
                    $result = send_sms_netgsm($to, $message, $netgsm_username, $netgsm_password, $netgsm_msgheader);
                } else {
                    $twilio_account_sid = get_setting('twilio_account_sid', '');
                    $twilio_auth_token = get_setting('twilio_auth_token', '');
                    $twilio_from_number = get_setting('twilio_from_number', '');
                    $twilio_messaging_service_sid = get_setting('twilio_messaging_service_sid', '');
                    
                    $result = send_sms_twilio($to, $message, $twilio_from_number, $twilio_account_sid, $twilio_auth_token, $twilio_messaging_service_sid);
                }
                
                if ($result['success']) {
                    return ['success' => true, 'provider' => $provider, 'attempts' => $total_attempts, 'result' => $result];
                }
                
                $last_error = $result['error'] ?? 'SMS gönderim başarısız';
                $last_error_code = $result['error_code'] ?? null;
                $is_retryable = $result['retryable'] ?? true;
                
                // Retry edilemeyen hatalar için durdur (örneğin: geçersiz kullanıcı adı, bakiye yok)
                if (!$is_retryable) {
                    tpl_error_log("SMS non-retryable error: $last_error (Code: $last_error_code)");
                    break; // Bu provider'dan vazgeç, bir sonrakine geç
                }
                
                // Exponential backoff (sadece retryable hatalar için) - daha agresif retry
                if ($attempts < $max_retries && $is_retryable) {
                    // Daha kısa bekleme süreleri: 2, 4, 6, 8 saniye (daha garantili gönderim için)
                    $delay = min(2 * $attempts, 8);
                    tpl_error_log("SMS retry after $delay seconds (attempt $attempts/$max_retries)");
                    sleep($delay);
                }
            } catch (Exception $e) {
                $last_error = $e->getMessage();
                tpl_error_log("SMS exception: $last_error");
                
                // Network hatası ise retry yap
                if (strpos($last_error, 'timeout') !== false || 
                    strpos($last_error, 'connection') !== false ||
                    strpos($last_error, 'DNS') !== false) {
                    if ($attempts < $max_retries) {
                        $delay = min(pow(2, $attempts - 1), 5);
                        usleep($delay * 1000000);
                        continue;
                    }
                } else {
                    // Fatal hata, bir sonraki provider'a geç
                    break;
                }
            }
        }
        
        // Bu provider başarısız oldu, bir sonrakine geç
        if ($attempts >= $max_retries) {
            tpl_error_log("Provider $provider failed after $attempts attempts, trying next provider");
            continue;
        }
    }
    
    return [
        'success' => false, 
        'attempts' => $total_attempts, 
        'error' => $last_error, 
        'error_code' => $last_error_code,
        'providers_tried' => $providers
    ];
}

