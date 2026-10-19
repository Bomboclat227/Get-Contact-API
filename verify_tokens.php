<?php

declare(strict_types=1);

require __DIR__ . '/src/Http/HttpClientInterface.php';
require __DIR__ . '/src/Http/CurlHttpClient.php';
require __DIR__ . '/src/Security/Crypto.php';
require __DIR__ . '/src/Security/Signature.php';
require __DIR__ . '/src/Validator/NumberValidator.php';
require __DIR__ . '/src/GetContact.php';

use Restugbk\GetContact;
use Restugbk\Security\Crypto;

$credentialsPath = dirname(__DIR__, 2) . '/outputs/getcontact_credentials_2026-10-16.txt';
$values = [];

foreach (file($credentialsPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
    [$key, $value] = preg_split('/\s+/', trim($line), 2);
    $values[$key] = $value;
}

$token = $values['user_token'] ?? '';
$finalKey = $values['final_key'] ?? '';

$client = new GetContact($token, $finalKey);
$probe = '{"probe":"local-only"}';
$encrypted = Crypto::encrypt($probe, $finalKey);
$decrypted = Crypto::decrypt($encrypted, $finalKey);

printf("Client: %s\n", $client::class);
printf("Token loaded: %s...%s (%d chars)\n", substr($token, 0, 6), substr($token, -4), strlen($token));
printf("Final key loaded: %d hex chars\n", strlen($finalKey));
printf("AES round trip: %s\n", hash_equals($probe, $decrypted) ? 'OK' : 'FAILED');

