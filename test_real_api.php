<?php
/**
 * Gerçek API testi - Swift'in gönderdiği gibi
 */

// Simüle edilmiş Swift request
$test_cases = [
    'bandırma17eylülüniversitesi', // Normalize edilmiş (Swift'ten gelecek)
    urlencode('bandırma17eylülüniversitesi'), // URL encoded (Swift'ten gelecek)
];

foreach ($test_cases as $index => $test_id) {
    echo "=== TEST " . ($index + 1) . " ===\n";
    echo "Input: '{$test_id}'\n";
    
    // Simüle et
    $_GET = ['university_id' => $test_id, 'limit' => '10', 'offset' => '0'];
    $_SERVER['REQUEST_METHOD'] = 'GET';
    $_SERVER['HTTP_HOST'] = 'localhost';
    
    // get_requested_university_id fonksiyonunu test et
    function normalize_university_id($value) {
        $value = trim((string)$value);
        if ($value === '') return '';
        $normalized = mb_strtolower($value, 'UTF-8');
        $normalized = str_replace([' ', '-', '_'], '', $normalized);
        return $normalized;
    }
    
    function get_requested_university_id() {
        $raw = '';
        if (isset($_GET['university_id'])) {
            $raw = (string)$_GET['university_id'];
            $raw = urldecode($raw);
            if (strpos($raw, '%') !== false) {
                $raw = urldecode($raw);
            }
        }
        $raw = trim($raw);
        if ($raw === '' || $raw === 'all') return '';
        $raw = basename($raw);
        if (strpos($raw, '..') !== false || strpos($raw, '/') !== false || strpos($raw, '\\') !== false) {
            return '';
        }
        return normalize_university_id($raw);
    }
    
    $result = get_requested_university_id();
    echo "Result: '{$result}'\n";
    
    // Beklenen sonuç
    $expected = 'bandırma17eylülüniversitesi';
    echo "Expected: '{$expected}'\n";
    echo "Match: " . ($result === $expected ? '✅ EVET' : '❌ HAYIR') . "\n\n";
}
