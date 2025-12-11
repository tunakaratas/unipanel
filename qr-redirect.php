<?php
/**
 * QR Kod Redirect Sayfası
 * QR kod okutulduğunda bu sayfa açılır ve deep link'e yönlendirir
 * 
 * Kullanım:
 * /qr-redirect.php?type=community&id={community_id}
 * /qr-redirect.php?type=event&id={event_id}&community_id={community_id}
 */

header('Content-Type: text/html; charset=utf-8');

$type = $_GET['type'] ?? '';
$id = $_GET['id'] ?? '';
$community_id = $_GET['community_id'] ?? '';

// Deep link oluştur
$deepLink = '';
$webUrl = '';
$fallbackUrl = '';

if ($type === 'community' && !empty($id)) {
    $deepLink = 'unifour://community/' . urlencode($id);
    $webUrl = '/communities/' . urlencode($id) . '/';
    $fallbackUrl = $webUrl;
} elseif ($type === 'event' && !empty($id) && !empty($community_id)) {
    $deepLink = 'unifour://event/' . urlencode($community_id) . '/' . urlencode($id);
    $webUrl = '/communities/' . urlencode($community_id) . '/?view=events&event_id=' . urlencode($id);
    $fallbackUrl = $webUrl;
} else {
    // Geçersiz parametreler - ana sayfaya yönlendir
    header('Location: /');
    exit;
}

// Base URL
$baseUrl = (isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on' ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'];
$fullWebUrl = $baseUrl . $webUrl;
$fullDeepLink = $deepLink;
?>
<!DOCTYPE html>
<html lang="tr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Yönlendiriliyor...</title>
    <meta http-equiv="refresh" content="2;url=<?= htmlspecialchars($fullWebUrl, ENT_QUOTES, 'UTF-8') ?>">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            background: white;
            border-radius: 20px;
            padding: 40px;
            text-align: center;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            max-width: 400px;
            width: 100%;
        }
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #667eea;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        h1 {
            color: #333;
            font-size: 24px;
            margin-bottom: 10px;
        }
        p {
            color: #666;
            font-size: 16px;
            margin-bottom: 20px;
        }
        .button {
            display: inline-block;
            padding: 12px 24px;
            background: #667eea;
            color: white;
            text-decoration: none;
            border-radius: 8px;
            font-weight: 600;
            margin-top: 10px;
            transition: background 0.3s;
        }
        .button:hover {
            background: #5568d3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="spinner"></div>
        <h1>Yönlendiriliyor...</h1>
        <p>Uygulama açılıyor...</p>
        <a href="<?= htmlspecialchars($fullWebUrl, ENT_QUOTES, 'UTF-8') ?>" class="button">Web Sayfasını Aç</a>
    </div>

    <script>
        (function() {
            // Deep link'i dene
            var deepLink = <?= json_encode($fullDeepLink, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG) ?>;
            var webUrl = <?= json_encode($fullWebUrl, JSON_UNESCAPED_SLASHES | JSON_HEX_TAG) ?>;
            
            // Platform tespiti
            var isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) && !window.MSStream;
            var isAndroid = /Android/.test(navigator.userAgent);
            var isSafari = /^((?!chrome|android).)*safari/i.test(navigator.userAgent);
            
            var deepLinkAttempted = false;
            var fallbackTriggered = false;
            
            // Deep link'i açmayı dene
            function tryDeepLink() {
                if (deepLinkAttempted) return;
                deepLinkAttempted = true;
                
                // iOS Safari için özel yöntem
                if (isIOS && isSafari) {
                    // iOS Safari'de iframe ile deep link açmayı dene (daha güvenilir)
                    var iframe = document.createElement('iframe');
                    iframe.style.display = 'none';
                    iframe.style.width = '0';
                    iframe.style.height = '0';
                    iframe.src = deepLink;
                    document.body.appendChild(iframe);
                    
                    // iframe'i hemen kaldır
                    setTimeout(function() {
                        if (iframe.parentNode) {
                            iframe.parentNode.removeChild(iframe);
                        }
                    }, 100);
                    
                    // 500ms sonra hala bu sayfadaysak web URL'ine yönlendir
                    setTimeout(function() {
                        if (!fallbackTriggered) {
                            fallbackTriggered = true;
                            window.location.href = webUrl;
                        }
                    }, 500);
                } else if (isIOS) {
                    // iOS Chrome veya diğer tarayıcılar için
                    window.location.href = deepLink;
                    
                    setTimeout(function() {
                        if (!fallbackTriggered) {
                            fallbackTriggered = true;
                            window.location.href = webUrl;
                        }
                    }, 500);
                } else if (isAndroid) {
                    // Android için intent URL'i dene
                    var intentUrl = 'intent://' + deepLink.replace('unifour://', '') + '#Intent;scheme=unifour;package=com.unifour.app;end';
                    window.location.href = intentUrl;
                    
                    setTimeout(function() {
                        if (!fallbackTriggered) {
                            fallbackTriggered = true;
                            window.location.href = webUrl;
                        }
                    }, 500);
                } else {
                    // Desktop için direkt deep link dene
                    window.location.href = deepLink;
                    
                    setTimeout(function() {
                        if (!fallbackTriggered) {
                            fallbackTriggered = true;
                            window.location.href = webUrl;
                        }
                    }, 1000);
                }
            }
            
            // Sayfa yüklendiğinde deep link'i dene
            if (document.readyState === 'loading') {
                document.addEventListener('DOMContentLoaded', function() {
                    setTimeout(tryDeepLink, 100);
                });
            } else {
                setTimeout(tryDeepLink, 100);
            }
            
            // Fallback: Eğer 2 saniye içinde yönlendirme olmadıysa web URL'ine git
            setTimeout(function() {
                if (!fallbackTriggered) {
                    fallbackTriggered = true;
                    window.location.href = webUrl;
                }
            }, 2000);
            
            // Sayfa görünürlüğü değiştiğinde kontrol et (iOS için)
            document.addEventListener('visibilitychange', function() {
                if (document.hidden && !fallbackTriggered) {
                    // Sayfa gizlendi, muhtemelen uygulama açıldı
                    fallbackTriggered = true;
                }
            });
            
            // Blur event'i (iOS için)
            window.addEventListener('blur', function() {
                if (!fallbackTriggered) {
                    // Pencere kayboldu, muhtemelen uygulama açıldı
                    fallbackTriggered = true;
                }
            });
        })();
    </script>
</body>
</html>
