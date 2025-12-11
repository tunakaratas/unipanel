<?php
/**
 * Push Notification Service
 * Firebase Cloud Messaging (FCM) ve Apple Push Notification Service (APNs) entegrasyonu
 */

namespace UniPanel\Notifications;

use Exception;

class PushNotificationService {
    private $fcmServerKey;
    private $fcmUrl = 'https://fcm.googleapis.com/fcm/send';
    
    public function __construct() {
        $credentials = require __DIR__ . '/../../config/credentials.php';
        $this->fcmServerKey = $credentials['fcm']['server_key'] ?? null;
        
        if (!$this->fcmServerKey) {
            error_log("FCM Server Key bulunamadı. Bildirimler gönderilemeyecek.");
        }
    }
    
    /**
     * Tek bir cihaza bildirim gönder
     */
    public function sendToDevice($deviceToken, $platform, $title, $body, $data = []) {
        if (!$this->fcmServerKey) {
            error_log("FCM Server Key eksik. Bildirim gönderilemedi.");
            return false;
        }
        
        if ($platform === 'ios') {
            return $this->sendToIOS($deviceToken, $title, $body, $data);
        } elseif ($platform === 'android') {
            return $this->sendToAndroid($deviceToken, $title, $body, $data);
        }
        
        return false;
    }
    
    /**
     * Birden fazla cihaza bildirim gönder
     */
    public function sendToMultipleDevices($deviceTokens, $title, $body, $data = []) {
        if (!$this->fcmServerKey) {
            error_log("FCM Server Key eksik. Bildirim gönderilemedi.");
            return false;
        }
        
        if (empty($deviceTokens)) {
            return false;
        }
        
        // FCM'de maksimum 1000 token gönderilebilir
        $chunks = array_chunk($deviceTokens, 1000);
        $results = [];
        
        foreach ($chunks as $chunk) {
            $result = $this->sendToFCM($chunk, $title, $body, $data);
            $results[] = $result;
        }
        
        return $results;
    }
    
    /**
     * iOS cihazlara bildirim gönder
     */
    private function sendToIOS($deviceToken, $title, $body, $data = []) {
        $payload = [
            'to' => $deviceToken,
            'notification' => [
                'title' => $title,
                'body' => $body,
                'sound' => 'default',
                'badge' => 1
            ],
            'data' => array_merge([
                'click_action' => 'FLUTTER_NOTIFICATION_CLICK',
                'sound' => 'default'
            ], $data),
            'priority' => 'high',
            'apns' => [
                'headers' => [
                    'apns-priority' => '10'
                ],
                'payload' => [
                    'aps' => [
                        'sound' => 'default',
                        'badge' => 1,
                        'alert' => [
                            'title' => $title,
                            'body' => $body
                        ]
                    ]
                ]
            ]
        ];
        
        return $this->sendToFCM([$deviceToken], $title, $body, $data, $payload);
    }
    
    /**
     * Android cihazlara bildirim gönder
     */
    private function sendToAndroid($deviceToken, $title, $body, $data = []) {
        $payload = [
            'to' => $deviceToken,
            'notification' => [
                'title' => $title,
                'body' => $body,
                'sound' => 'default',
                'icon' => 'notification_icon'
            ],
            'data' => array_merge([
                'click_action' => 'FLUTTER_NOTIFICATION_CLICK',
                'sound' => 'default'
            ], $data),
            'priority' => 'high'
        ];
        
        return $this->sendToFCM([$deviceToken], $title, $body, $data, $payload);
    }
    
    /**
     * FCM API'ye istek gönder
     */
    private function sendToFCM($deviceTokens, $title, $body, $data = [], $customPayload = null) {
        if (empty($deviceTokens)) {
            return false;
        }
        
        // Tek token için 'to', çoklu token için 'registration_ids' kullan
        if (count($deviceTokens) === 1) {
            $payload = $customPayload ?? [
                'to' => $deviceTokens[0],
                'notification' => [
                    'title' => $title,
                    'body' => $body,
                    'sound' => 'default'
                ],
                'data' => array_merge([
                    'click_action' => 'FLUTTER_NOTIFICATION_CLICK'
                ], $data),
                'priority' => 'high'
            ];
        } else {
            $payload = [
                'registration_ids' => $deviceTokens,
                'notification' => [
                    'title' => $title,
                    'body' => $body,
                    'sound' => 'default'
                ],
                'data' => array_merge([
                    'click_action' => 'FLUTTER_NOTIFICATION_CLICK'
                ], $data),
                'priority' => 'high'
            ];
        }
        
        $headers = [
            'Authorization: key=' . $this->fcmServerKey,
            'Content-Type: application/json'
        ];
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $this->fcmUrl);
        curl_setopt($ch, CURLOPT_POST, true);
        curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_POSTFIELDS, json_encode($payload, JSON_UNESCAPED_UNICODE));
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
        curl_setopt($ch, CURLOPT_TIMEOUT, 10);
        
        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);
        
        if ($error) {
            error_log("FCM cURL hatası: " . $error);
            return false;
        }
        
        if ($httpCode !== 200) {
            error_log("FCM HTTP hatası: " . $httpCode . " - Response: " . $response);
            return false;
        }
        
        $responseData = json_decode($response, true);
        
        if (isset($responseData['failure']) && $responseData['failure'] > 0) {
            error_log("FCM bildirim gönderme hatası: " . json_encode($responseData));
        }
        
        return $responseData;
    }
    
    /**
     * Queue'dan bildirim gönder
     */
    public function sendFromQueue($queueItem) {
        $deviceToken = $queueItem['device_token'] ?? null;
        $platform = $queueItem['platform'] ?? 'android';
        $title = $queueItem['title'] ?? '';
        $body = $queueItem['body'] ?? '';
        $data = [];
        
        if (!empty($queueItem['data'])) {
            $data = is_string($queueItem['data']) ? json_decode($queueItem['data'], true) : $queueItem['data'];
        }
        
        if (!$deviceToken || !$title || !$body) {
            return false;
        }
        
        return $this->sendToDevice($deviceToken, $platform, $title, $body, $data);
    }
}
