<?php
session_start();
require 'oauth_config.php';

// Generate a unique nonce
$nonce = uniqid();
$timestamp = time();

// Parameters for the request token
$params = [
    'oauth_consumer_key' => OAUTH_CONSUMER_KEY,
    'oauth_nonce' => $nonce,
    'oauth_signature_method' => 'HMAC-SHA1',
    'oauth_timestamp' => $timestamp,
    'oauth_version' => '1.0'
];

// Create the base string and signature
$base_string = "POST&" . urlencode(OAUTH_REQUEST_TOKEN_URL) . "&" . urlencode(http_build_query($params));
$signature = base64_encode(hash_hmac('sha1', $base_string, OAUTH_CONSUMER_SECRET . '&', true));
$params['oauth_signature'] = $signature;

// Send request
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, OAUTH_REQUEST_TOKEN_URL);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: OAuth ' . http_build_query($params, '', ', ')
]);
$response = curl_exec($ch);
curl_close($ch);

parse_str($response, $result);
$_SESSION['oauth_token'] = $result['oauth_token'];
$_SESSION['oauth_token_secret'] = $result['oauth_token_secret'];

// Redirect the user to PowerSchool to authorize the request token
header('Location: ' . OAUTH_AUTHORIZE_URL . '?oauth_token=' . $_SESSION['oauth_token']);
exit;
?>
