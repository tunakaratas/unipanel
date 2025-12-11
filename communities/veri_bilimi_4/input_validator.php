<?php
/**
 * UniPanel Input Validator
 *
 * Bu sınıf, tüm kullanıcı girdileri için merkezi doğrulama ve
 * sanitize işlemlerini sağlar. SuperAdmin paneli de dahil olmak
 * üzere her yerde ortak olarak kullanılabilir.
 */

namespace UniPanel\General;

class InputValidator
{
    /**
     * String sanitize - trim + HTML özel karakter temizliği.
     */
    public static function sanitizeString(?string $value, bool $allowHTML = false): string
    {
        if ($value === null) {
            return '';
        }

        $value = trim($value);

        return $allowHTML ? $value : htmlspecialchars($value, ENT_QUOTES, 'UTF-8');
    }

    /**
     * E-posta doğrulama ve sanitize işlemi.
     */
    public static function validateEmail(string $email): array
    {
        $email = trim($email);

        if ($email === '') {
            return ['valid' => false, 'error' => 'Email boş olamaz'];
        }

        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
            return ['valid' => false, 'error' => 'Geçersiz email formatı'];
        }

        return ['valid' => true, 'value' => filter_var($email, FILTER_SANITIZE_EMAIL)];
    }

    /**
     * Telefon numarası doğrulama.
     */
    public static function validatePhone(string $phone): array
    {
        $phone = trim($phone);

        if ($phone === '') {
            return ['valid' => false, 'error' => 'Telefon numarası boş olamaz'];
        }

        if (!preg_match('/^[\d\s\-\+\(\)]+$/', $phone)) {
            return ['valid' => false, 'error' => 'Telefon numarası sadece rakam ve + - ( ) içerebilir'];
        }

        $digits = preg_replace('/[^\d]/', '', $phone);
        if (strlen($digits) < 10) {
            return ['valid' => false, 'error' => 'Telefon numarası en az 10 haneli olmalıdır'];
        }

        return ['valid' => true, 'value' => $phone];
    }

    /**
     * Integer doğrulama.
     */
    public static function validateInt($value, ?int $min = null, ?int $max = null): array
    {
        if (!is_numeric($value)) {
            return ['valid' => false, 'error' => 'Geçersiz sayı'];
        }

        $intValue = (int) $value;

        if ($min !== null && $intValue < $min) {
            return ['valid' => false, 'error' => "Sayı en az {$min} olmalıdır"];
        }

        if ($max !== null && $intValue > $max) {
            return ['valid' => false, 'error' => "Sayı en fazla {$max} olmalıdır"];
        }

        return ['valid' => true, 'value' => $intValue];
    }

    /**
     * URL doğrulama.
     */
    public static function validateURL(string $url): array
    {
        $url = trim($url);

        if ($url === '') {
            return ['valid' => false, 'error' => 'URL boş olamaz'];
        }

        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            return ['valid' => false, 'error' => 'Geçersiz URL formatı'];
        }

        return ['valid' => true, 'value' => $url];
    }

    /**
     * Tarih doğrulama (varsayılan format Y-m-d).
     */
    public static function validateDate(string $date, string $format = 'Y-m-d'): array
    {
        $date = trim($date);

        if ($date === '') {
            return ['valid' => false, 'error' => 'Tarih boş olamaz'];
        }

        $dt = \DateTime::createFromFormat($format, $date);
        $isValid = $dt && $dt->format($format) === $date;

        return $isValid
            ? ['valid' => true, 'value' => $date]
            : ['valid' => false, 'error' => "Geçersiz tarih formatı (örn: 2024-12-31)"];
    }

    /**
     * Saat doğrulama (H:i).
     */
    public static function validateTime(string $time): array
    {
        $time = trim($time);

        if ($time === '') {
            return ['valid' => false, 'error' => 'Saat boş olamaz'];
        }

        if (!preg_match('/^([01]?[0-9]|2[0-3]):[0-5][0-9]$/', $time)) {
            return ['valid' => false, 'error' => 'Geçersiz saat formatı (örn: 14:30)'];
        }

        return ['valid' => true, 'value' => $time];
    }

    /**
     * Dosya boyutu doğrulama.
     */
    public static function validateFileSize(array $file, int $maxSize): array
    {
        if (!isset($file['size'])) {
            return ['valid' => false, 'error' => 'Dosya bilgisi alınamadı'];
        }

        if ($file['size'] <= 0) {
            return ['valid' => false, 'error' => 'Dosya boş'];
        }

        if ($file['size'] > $maxSize) {
            $max = round($maxSize / (1024 * 1024), 1);
            $current = round($file['size'] / (1024 * 1024), 1);
            return ['valid' => false, 'error' => "Dosya boyutu çok büyük. Maksimum: {$max}MB, mevcut: {$current}MB"];
        }

        return ['valid' => true, 'value' => $file['size']];
    }

    /**
     * Dosya uzantısı doğrulama.
     */
    public static function validateFileType(array $file, array $allowedTypes): array
    {
        if (!isset($file['name'])) {
            return ['valid' => false, 'error' => 'Dosya bilgisi alınamadı'];
        }

        $extension = strtolower(pathinfo($file['name'], PATHINFO_EXTENSION));

        if (!in_array($extension, $allowedTypes, true)) {
            return ['valid' => false, 'error' => 'Geçersiz dosya tipi'];
        }

        return ['valid' => true, 'value' => $extension];
    }

    /**
     * POST verilerini toplu olarak doğrulama.
     */
    public static function validatePost(array $data, array $rules): array
    {
        $errors = [];
        $validated = [];

        foreach ($rules as $field => $rule) {
            $value = $data[$field] ?? null;

            if (($rule['required'] ?? false) && ($value === null || $value === '')) {
                $errors[$field] = $rule['error'] ?? "{$field} zorunludur";
                continue;
            }

            if ($value === null || $value === '') {
                continue;
            }

            $result = ['valid' => true, 'value' => self::sanitizeString($value)];

            switch ($rule['type'] ?? 'string') {
                case 'email':
                    $result = self::validateEmail($value);
                    break;
                case 'phone':
                    $result = self::validatePhone($value);
                    break;
                case 'int':
                    $result = self::validateInt($value, $rule['min'] ?? null, $rule['max'] ?? null);
                    break;
                case 'url':
                    $result = self::validateURL($value);
                    break;
                case 'date':
                    $result = self::validateDate($value, $rule['format'] ?? 'Y-m-d');
                    break;
                case 'time':
                    $result = self::validateTime($value);
                    break;
                case 'string':
                default:
                    break;
            }

            if (!$result['valid']) {
                $errors[$field] = $result['error'];
            } else {
                $validated[$field] = $result['value'];
            }
        }

        return [
            'valid' => empty($errors),
            'errors' => $errors,
            'data' => $validated,
        ];
    }

    /**
     * XSS güvenli output.
     */
    public static function outputSafe(?string $value, bool $allowHTML = false): string
    {
        return self::sanitizeString($value, $allowHTML);
    }
}

// Backward compatibility helpers (global functions)
if (!function_exists('sanitize_input')) {
    function sanitize_input($value)
    {
        return InputValidator::sanitizeString($value);
    }
}

if (!function_exists('validate_email')) {
    function validate_email($email)
    {
        return InputValidator::validateEmail($email);
    }
}

if (!function_exists('validate_phone')) {
    function validate_phone($phone)
    {
        return InputValidator::validatePhone($phone);
    }
}

if (!function_exists('validate_int')) {
    function validate_int($value, $min = null, $max = null)
    {
        return InputValidator::validateInt($value, $min, $max);
    }
}

if (!function_exists('output_safe')) {
    function output_safe($value, $allowHTML = false)
    {
        return InputValidator::outputSafe($value, $allowHTML);
    }
}


