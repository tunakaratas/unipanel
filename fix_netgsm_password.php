<?php
/**
 * NetGSM şifresini SuperAdmin config'den credentials.php'ye aktar
 */

$projectRoot = __DIR__;

// SuperAdmin config'den NetGSM şifresini al
$superadminConfigPath = $projectRoot . '/superadmin/config.php';
if (!file_exists($superadminConfigPath)) {
    die("SuperAdmin config bulunamadı!\n");
}

$superadminConfig = require $superadminConfigPath;
$netgsmPass = $superadminConfig['netgsm']['pass'] ?? '';

if (empty($netgsmPass)) {
    die("SuperAdmin config'de NetGSM şifresi bulunamadı!\n");
}

// credentials.php'yi güncelle
$credentialsPath = $projectRoot . '/config/credentials.php';
if (!file_exists($credentialsPath)) {
    die("credentials.php bulunamadı!\n");
}

$credentials = require $credentialsPath;

// Şifreyi güncelle
$credentials['netgsm']['password'] = $netgsmPass;

// Dosyayı yaz
$content = "<?php\n";
$content .= "/**\n";
$content .= " * Credentials Configuration\n";
$content .= " */\n\n";
$content .= "return " . var_export($credentials, true) . ";\n";

file_put_contents($credentialsPath, $content);

echo "✓ credentials.php güncellendi!\n";
echo "NetGSM Username: " . $credentials['netgsm']['username'] . "\n";
echo "NetGSM Password: AYARLI (" . strlen($netgsmPass) . " karakter)\n";
echo "NetGSM Header: " . $credentials['netgsm']['msgheader'] . "\n";

