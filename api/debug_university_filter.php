<?php
/**
 * Debug script for university filtering issue
 * This script logs all steps of university filtering to help identify the problem
 */

require_once __DIR__ . '/security_helper.php';
require_once __DIR__ . '/../lib/autoload.php';

// Log file path
$log_file = __DIR__ . '/../logs/university_filter_debug.log';

function write_log($message) {
    global $log_file;
    $timestamp = date('Y-m-d H:i:s');
    $log_message = "[{$timestamp}] {$message}\n";
    file_put_contents($log_file, $log_message, FILE_APPEND);
}

// Clear previous log
file_put_contents($log_file, "=== University Filter Debug Log Started ===\n");

write_log("=== Starting University Filter Debug ===");

// Get university_id from GET parameter
$raw_university_id = isset($_GET['university_id']) ? trim($_GET['university_id']) : '';
write_log("Raw university_id from GET: '{$raw_university_id}'");

if (empty($raw_university_id) || $raw_university_id === 'all') {
    write_log("No university filter or 'all' selected - exiting");
    echo json_encode(['success' => false, 'message' => 'No university_id provided']);
    exit;
}

// Normalize function (same as in communities.php)
function normalize_university_id($value) {
    $value = trim((string)$value);
    if ($value === '') {
        return '';
    }
    $normalized = mb_strtolower($value, 'UTF-8');
    $normalized = str_replace([' ', '-', '_'], '', $normalized);
    return $normalized;
}

// Path traversal protection
$raw_university_id = basename($raw_university_id);
if (strpos($raw_university_id, '..') !== false || strpos($raw_university_id, '/') !== false || strpos($raw_university_id, '\\') !== false) {
    write_log("ERROR: Invalid university_id format (path traversal detected)");
    echo json_encode(['success' => false, 'message' => 'Invalid university_id format']);
    exit;
}

// Normalize the requested university ID
$normalized_requested_id = normalize_university_id($raw_university_id);
write_log("Normalized requested university_id: '{$normalized_requested_id}'");

// Now check all communities
$communities_dir = __DIR__ . '/../communities';
if (!is_dir($communities_dir)) {
    write_log("ERROR: Communities directory not found: {$communities_dir}");
    echo json_encode(['success' => false, 'message' => 'Communities directory not found']);
    exit;
}

write_log("Scanning communities directory: {$communities_dir}");

$community_folders = glob($communities_dir . '/*', GLOB_ONLYDIR);
if ($community_folders === false) {
    $community_folders = [];
    write_log("WARNING: glob() returned false");
} else {
    write_log("Found " . count($community_folders) . " community folders");
}

$excluded_dirs = ['.', '..', 'assets', 'public', 'templates', 'system', 'docs'];
$matched_communities = [];
$skipped_communities = [];

foreach ($community_folders as $folder_path) {
    $community_id = basename($folder_path);
    
    if (in_array($community_id, $excluded_dirs)) {
        write_log("Skipping excluded directory: {$community_id}");
        continue;
    }
    
    $db_path = $folder_path . '/unipanel.sqlite';
    if (!file_exists($db_path)) {
        write_log("Skipping community '{$community_id}' - database not found");
        continue;
    }
    
    try {
        // Get connection
        $connResult = ConnectionPool::getConnection($db_path, false);
        if (!$connResult) {
            write_log("ERROR: Could not get connection for community '{$community_id}'");
            continue;
        }
        
        $db = $connResult['db'];
        $poolId = $connResult['pool_id'];
        
        // Get settings
        $settings_query = $db->query("SELECT setting_key, setting_value FROM settings WHERE club_id = 1");
        $settings = [];
        if ($settings_query) {
            while ($row = $settings_query->fetchArray(SQLITE3_ASSOC)) {
                $settings[$row['setting_key']] = $row['setting_value'];
            }
        }
        
        // Get university from settings
        $community_university_name = $settings['university'] ?? $settings['organization'] ?? '';
        write_log("Community '{$community_id}' - University name from DB: '{$community_university_name}'");
        
        if (empty($community_university_name)) {
            write_log("Community '{$community_id}' SKIPPED - No university set in settings");
            $skipped_communities[] = [
                'id' => $community_id,
                'reason' => 'No university set',
                'university_name' => ''
            ];
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            continue;
        }
        
        // Normalize community university
        $community_university_id = normalize_university_id($community_university_name);
        write_log("Community '{$community_id}' - Normalized university ID: '{$community_university_id}'");
        
        // Compare
        if ($community_university_id === '' || $community_university_id !== $normalized_requested_id) {
            write_log("Community '{$community_id}' SKIPPED - University mismatch (Requested: '{$normalized_requested_id}' vs Community: '{$community_university_id}')");
            $skipped_communities[] = [
                'id' => $community_id,
                'reason' => 'University mismatch',
                'university_name' => $community_university_name,
                'normalized_id' => $community_university_id,
                'requested_id' => $normalized_requested_id
            ];
            ConnectionPool::releaseConnection($db_path, $poolId, false);
            continue;
        }
        
        // MATCHED!
        write_log("✓ Community '{$community_id}' MATCHED - University filter passed");
        $matched_communities[] = [
            'id' => $community_id,
            'university_name' => $community_university_name,
            'normalized_id' => $community_university_id
        ];
        
        ConnectionPool::releaseConnection($db_path, $poolId, false);
        
    } catch (Exception $e) {
        write_log("ERROR processing community '{$community_id}': " . $e->getMessage());
        if (isset($poolId) && isset($db_path)) {
            try {
                ConnectionPool::releaseConnection($db_path, $poolId, false);
            } catch (Exception $releaseError) {
                write_log("ERROR releasing connection: " . $releaseError->getMessage());
            }
        }
    }
}

// Summary
write_log("=== SUMMARY ===");
write_log("Requested university_id (raw): '{$raw_university_id}'");
write_log("Requested university_id (normalized): '{$normalized_requested_id}'");
write_log("Total communities scanned: " . count($community_folders));
write_log("Matched communities: " . count($matched_communities));
write_log("Skipped communities: " . count($skipped_communities));

if (count($matched_communities) > 0) {
    write_log("Matched communities:");
    foreach ($matched_communities as $comm) {
        write_log("  - {$comm['id']} (University: '{$comm['university_name']}', Normalized: '{$comm['normalized_id']}')");
    }
}

if (count($skipped_communities) > 0) {
    write_log("Skipped communities:");
    foreach ($skipped_communities as $comm) {
        write_log("  - {$comm['id']}: {$comm['reason']}");
        if (isset($comm['university_name'])) {
            write_log("    University: '{$comm['university_name']}'");
        }
        if (isset($comm['normalized_id'])) {
            write_log("    Normalized ID: '{$comm['normalized_id']}'");
        }
    }
}

// Return JSON response
echo json_encode([
    'success' => true,
    'requested_id_raw' => $raw_university_id,
    'requested_id_normalized' => $normalized_requested_id,
    'matched_count' => count($matched_communities),
    'skipped_count' => count($skipped_communities),
    'matched_communities' => $matched_communities,
    'skipped_communities' => $skipped_communities,
    'log_file' => $log_file
], JSON_UNESCAPED_UNICODE | JSON_PRETTY_PRINT);

write_log("=== Debug Script Completed ===");
