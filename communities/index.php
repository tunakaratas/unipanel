<?php
/**
 * Communities Router - Handles /communities/{slug}/ URLs
 * This file routes community URLs when mod_rewrite is not available
 */

// Get community slug from query parameter (if mod_rewrite worked) or from URL path
$communitySlug = $_GET['slug'] ?? '';

// If not in query, extract from URL path
if (empty($communitySlug)) {
    $requestUri = $_SERVER['REQUEST_URI'] ?? '';
    $requestPath = parse_url($requestUri, PHP_URL_PATH);
    $pathParts = explode('/', trim($requestPath, '/'));
    $slugIndex = array_search('communities', $pathParts);
    
    if ($slugIndex !== false) {
        $communitySlug = $pathParts[$slugIndex + 1] ?? '';
    }
}

// Validate community slug
if (empty($communitySlug) || !preg_match('/^[a-z0-9_-]+$/i', $communitySlug)) {
    http_response_code(404);
    die('Community not found');
}

// Check if community directory exists
$communityPath = __DIR__ . '/' . $communitySlug;
if (!is_dir($communityPath)) {
    http_response_code(404);
    die('Community directory not found');
}

// Check if index.php exists
$indexFile = $communityPath . '/index.php';
if (!file_exists($indexFile)) {
    http_response_code(404);
    die('Community index file not found');
}

// Change to community directory and include index.php
chdir($communityPath);
$_SERVER['SCRIPT_FILENAME'] = $indexFile;
require $indexFile;

