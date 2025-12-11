<?php
require_once __DIR__ . '/security_helper.php';
/**
 * QR Kod Oluşturma Endpoint'i
 * Her topluluk ve etkinlik için özel QR kodlar oluşturur
 */

header('Content-Type: application/json');
require_once __DIR__ . '/connection_pool.php';

// QR kod oluşturma için endroid/qr-code kütüphanesi kullanılacak
// Eğer yoksa, basit bir SVG QR kod oluşturucu kullanabiliriz

function generateQRCodeSVG($data, $size = 200) {
    // Basit bir QR kod SVG oluşturucu
    // Not: Bu basit bir implementasyon, production için endroid/qr-code kullanılmalı
    $url = "https://api.qrserver.com/v1/create-qr-code/?size={$size}x{$size}&data=" . urlencode($data);
    return $url;
}

function generateQRCodeBase64($data, $size = 200) {
    // QR kod için harici servis kullan
    $url = "https://api.qrserver.com/v1/create-qr-code/?size={$size}x{$size}&data=" . urlencode($data);
    $image = @file_get_contents($url);
    if ($image) {
        return base64_encode($image);
    }
    return null;
}

$method = $_SERVER['REQUEST_METHOD'];

if ($method === 'GET') {
    $type = $_GET['type'] ?? ''; // 'community' veya 'event'
    $id = $_GET['id'] ?? '';
    $communityId = $_GET['community_id'] ?? '';
    $size = isset($_GET['size']) ? intval($_GET['size']) : 200;
    
    if (empty($type) || empty($id)) {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Type ve id parametreleri gerekli'
        ]);
        exit;
    }
    
    // QR kod içeriği oluştur - Web URL'i kullan (iOS güvenlik için)
    $deepLink = '';
    $webUrl = '';
    $redirectUrl = '';
    $baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
    
    if ($type === 'community') {
        // Deep link: unifour://community/{community_id}
        $deepLink = 'unifour://community/' . urlencode($id);
        // Web URL'i de ekle (fallback için)
        $webUrl = $baseUrl . "/communities/" . urlencode($id) . "/";
        // Redirect URL'i (QR kod içeriği olarak kullanılacak)
        $redirectUrl = $baseUrl . "/qr-redirect.php?type=community&id=" . urlencode($id);
    } elseif ($type === 'event') {
        if (empty($communityId)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'Event için community_id gerekli'
            ]);
            exit;
        }
        // Deep link: unifour://event/{community_id}/{event_id}
        $deepLink = 'unifour://event/' . urlencode($communityId) . '/' . urlencode($id);
        // Web URL'i de ekle (fallback için)
        $webUrl = $baseUrl . "/communities/" . urlencode($communityId) . "/?view=events&event_id=" . urlencode($id);
        // Redirect URL'i (QR kod içeriği olarak kullanılacak)
        $redirectUrl = $baseUrl . "/qr-redirect.php?type=event&id=" . urlencode($id) . "&community_id=" . urlencode($communityId);
    } elseif ($type === 'url') {
        // Direkt URL parametresi
        $url = $_GET['url'] ?? '';
        if (empty($url)) {
            http_response_code(400);
            echo json_encode([
                'success' => false,
                'error' => 'URL parametresi gerekli'
            ]);
            exit;
        }
        $deepLink = urldecode($url);
        $webUrl = urldecode($url);
        $redirectUrl = urldecode($url);
    } else {
        http_response_code(400);
        echo json_encode([
            'success' => false,
            'error' => 'Geçersiz type. community, event veya url olmalı'
        ]);
        exit;
    }
    
    // QR kod içeriği olarak redirect URL'i kullan (iOS güvenlik için web URL'i gerekli)
    $qrContent = $redirectUrl;
    
    // QR kod URL'i oluştur
    $qrUrl = generateQRCodeSVG($qrContent, $size);
    $qrBase64 = generateQRCodeBase64($qrContent, $size);
    
    echo json_encode([
        'success' => true,
        'data' => [
            'qr_url' => $qrUrl,
            'qr_base64' => $qrBase64,
            'content' => $qrContent,
            'redirect_url' => $redirectUrl,
            'deep_link' => $deepLink,
            'web_url' => $webUrl,
            'type' => $type,
            'id' => $id
        ]
    ]);
} else {
    http_response_code(405);
    echo json_encode([
        'success' => false,
        'error' => 'Method not allowed'
    ]);
}
?>

