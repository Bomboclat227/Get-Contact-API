<?php

declare(strict_types=1);

require __DIR__ . '/src/Http/HttpClientInterface.php';
require __DIR__ . '/src/Http/CurlHttpClient.php';
require __DIR__ . '/src/Security/Crypto.php';
require __DIR__ . '/src/Security/Signature.php';
require __DIR__ . '/src/Validator/NumberValidator.php';
require __DIR__ . '/src/GetContact.php';

use Restugbk\GetContact;

$number = $argv[1] ?? '';
if (!preg_match('/^\+[1-9][0-9]{7,14}$/', $number)) {
    fwrite(STDERR, "Use an international number such as +77057241364\n");
    exit(2);
}

$token = getenv('GTC_TOKEN') ?: '';
$finalKey = getenv('GTC_FINAL_KEY') ?: '';
$deviceId = getenv('GTC_DEVICE_ID') ?: '';

if ($token === '' || $finalKey === '' || $deviceId === '') {
    fwrite(STDERR, "Set GTC_TOKEN, GTC_FINAL_KEY and GTC_DEVICE_ID\n");
    exit(3);
}

$client = new GetContact($token, $finalKey, null, $deviceId);
$mode = $argv[2] ?? 'tags';
$result = $mode === 'profile'
    ? $client->searchNumber($number)
    : $client->checkNumber($number);

echo json_encode($result, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES), PHP_EOL;

