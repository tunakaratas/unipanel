<?php
/**
 * Gerçek API çağrısı testi
 * Swift'in gönderdiği gibi test eder
 */

// Simüle edilmiş GET parametresi
$_GET['university_id'] = 'bandırma17eylülüniversitesi';
$_GET['limit'] = '10';
$_GET['offset'] = '0';
$_SERVER['REQUEST_METHOD'] = 'GET';
$_SERVER['HTTP_HOST'] = 'localhost';

echo "=== API ÇAĞRISI TEST ===\n\n";
echo "GET Parametreleri:\n";
echo "  university_id: " . $_GET['university_id'] . "\n";
echo "  limit: " . $_GET['limit'] . "\n";
echo "  offset: " . $_GET['offset'] . "\n\n";

// get_requested_university_id fonksiyonunu test et
function normalize_university_id($value) {
    $value = trim((string)$value);
    if ($value === '') {
        return '';
    }
    $normalized = mb_strtolower($value, 'UTF-8');
    $normalized = str_replace([' ', '-', '_'], '', $normalized);
    return $normalized;
}

function get_requested_university_id() {
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

    $raw = basename($raw);
    if (strpos($raw, '..') !== false || strpos($raw, '/') !== false || strpos($raw, '\\') !== false) {
        return '';
    }

    return normalize_university_id($raw);
}

$requested_id = get_requested_university_id();
echo "get_requested_university_id() sonucu: '{$requested_id}'\n\n";

// Normalize test
$test_cases = [
    'Bandırma 17 Eylül Üniversitesi',
    'bandırma17eylülüniversitesi',
    'BANDIRMA 17 EYLÜL ÜNİVERSİTESİ',
    'bandırma-17-eylül-üniversitesi'
];

echo "Normalize Test:\n";
foreach ($test_cases as $test) {
    $normalized = normalize_university_id($test);
    echo "  '{$test}' -> '{$normalized}'\n";
    echo "  Eşleşiyor mu? " . ($normalized === $requested_id ? '✅ EVET' : '❌ HAYIR') . "\n\n";
}
