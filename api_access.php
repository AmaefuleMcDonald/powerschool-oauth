<?php
session_start();
require 'oauth_config.php';

if (!isset($_SESSION['access_token']) || !isset($_SESSION['access_token_secret'])) {
    exit('You need to authorize first.');
}

$nonce = uniqid();
$timestamp = time();

$params = [
    'oauth_consumer_key' => OAUTH_CONSUMER_KEY,
    'oauth_nonce' => $nonce,
    'oauth_signature_method' => 'HMAC-SHA1',
    'oauth_timestamp' => $timestamp,
    'oauth_token' => $_SESSION['access_token'],
    'oauth_version' => '1.0'
];

// Set up the base string and signature
$resource_url = OAUTH_API_BASE_URL . 'student';
$base_string = "GET&" . urlencode($resource_url) . "&" . urlencode(http_build_query($params));
$signature = base64_encode(hash_hmac('sha1', $base_string, OAUTH_CONSUMER_SECRET . '&' . $_SESSION['access_token_secret'], true));
$params['oauth_signature'] = $signature;

// Make the API request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $resource_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: OAuth ' . http_build_query($params, '', ', ')
]);
$response = curl_exec($ch);
curl_close($ch);

// Display the API response
echo '<pre>';
print_r(json_decode($response, true));
echo '</pre>';
?>
