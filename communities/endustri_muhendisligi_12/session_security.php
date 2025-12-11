<?php
/**
 * SessionSecurity helper – centralizes session hardening routines.
 */

namespace UniPanel\General;

class SessionSecurity
{
    public static function start(array $options = []): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }

        $defaults = [
            'cookie_lifetime' => 60 * 60 * 24 * 7,
            'cookie_path' => '/',
            'cookie_domain' => '',
            'cookie_secure' => (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off'),
            'cookie_httponly' => true,
            'cookie_samesite' => 'Strict',
            'use_strict_mode' => 1,
        ];

        $config = array_merge($defaults, $options);

        if (PHP_VERSION_ID >= 70300) {
            session_set_cookie_params($config);
        } else {
            session_set_cookie_params(
                $config['cookie_lifetime'],
                $config['cookie_path'],
                $config['cookie_domain'],
                $config['cookie_secure'],
                $config['cookie_httponly']
            );
        }

        ini_set('session.use_strict_mode', $config['use_strict_mode']);
        ini_set('session.cookie_samesite', $config['cookie_samesite']);
        ini_set('session.cookie_secure', $config['cookie_secure'] ? '1' : '0');
        ini_set('session.cookie_httponly', '1');

        session_start();
        self::guard();
    }

    public static function guard(): void
    {
        if (empty($_SESSION['__session_initialized'])) {
            $_SESSION['__session_initialized'] = true;
            $_SESSION['__session_ip'] = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
            $_SESSION['__session_ua'] = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';
            session_regenerate_id(true);
            return;
        }

        $currentIp = $_SERVER['REMOTE_ADDR'] ?? 'unknown';
        $currentUa = $_SERVER['HTTP_USER_AGENT'] ?? 'unknown';

        if ($_SESSION['__session_ip'] !== $currentIp || $_SESSION['__session_ua'] !== $currentUa) {
            session_unset();
            session_destroy();
            throw new \RuntimeException('Oturum doğrulama başarısız: IP veya User-Agent değişti.');
        }
    }

    public static function regenerateIfNeeded(int $intervalSeconds = 300): void
    {
        $last = $_SESSION['__session_last_regenerate'] ?? 0;
        $now = time();
        if (($now - $last) >= $intervalSeconds) {
            session_regenerate_id(true);
            $_SESSION['__session_last_regenerate'] = $now;
        }
    }

    public static function enforceTimeout(int $idleMinutes = 60 * 24 * 7): void
    {
        if ($idleMinutes <= 0) {
            return;
        }

        $timeout = $idleMinutes * 60;
        $last = $_SESSION['__session_last_activity'] ?? 0;
        $now = time();

        if ($last && ($now - $last) > $timeout) {
            session_unset();
            session_destroy();
            throw new \RuntimeException('Oturum zaman aşımına uğradı.');
        }

        $_SESSION['__session_last_activity'] = $now;
    }
}

