<?php
session_start();
require 'oauth_config.php';

// Get the request token
$oauth_token = $_SESSION['oauth_token'];
$oauth_token_secret = $_SESSION['oauth_token_secret'];

// Get verifier
$oauth_verifier = $_GET['oauth_verifier'];

// Set up parameters
$nonce = uniqid();
$timestamp = time();
$params = [
    'oauth_consumer_key' => OAUTH_CONSUMER_KEY,
    'oauth_nonce' => $nonce,
    'oauth_signature_method' => 'HMAC-SHA1',
    'oauth_timestamp' => $timestamp,
    'oauth_token' => $oauth_token,
    'oauth_version' => '1.0',
    'oauth_verifier' => $oauth_verifier
];

// Create base string and signature
$base_string = "POST&" . urlencode(OAUTH_ACCESS_TOKEN_URL) . "&" . urlencode(http_build_query($params));
$signature = base64_encode(hash_hmac('sha1', $base_string, OAUTH_CONSUMER_SECRET . '&' . $oauth_token_secret, true));
$params['oauth_signature'] = $signature;

// Send request to exchange for access token
$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, OAUTH_ACCESS_TOKEN_URL);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_HTTPHEADER, [
    'Authorization: OAuth ' . http_build_query($params, '', ', ')
]);
$response = curl_exec($ch);
curl_close($ch);

parse_str($response, $access_tokens);

// Store access tokens
$_SESSION['access_token'] = $access_tokens['oauth_token'];
$_SESSION['access_token_secret'] = $access_tokens['oauth_token_secret'];

// Redirect to API access page
header('Location: api_access.php');
exit;
?>
