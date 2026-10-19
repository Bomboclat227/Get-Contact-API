<?php

namespace Restugbk;

use Exception;
use Restugbk\Http\HttpClientInterface;
use Restugbk\Http\CurlHttpClient;
use Restugbk\Security\Crypto;
use Restugbk\Security\Signature;
use Restugbk\Validator\NumberValidator;

class GetContact
{
    private string $token;
    private string $finalKey;
    private string $deviceId;
    private HttpClientInterface $httpClient;

    public const HMAC = '31426764382a642f3a6665497235466f3d236d5d785b722b4c657457442a495b494524324866782a2364292478587a78662d7a7b7578593f71703e2b7e365762';
    public const API_URL = 'https://1endpoint-iiiiiiilllllllljjjjjjjjjjttttiiiiiivvvww1.store/v2.8/number-detail';
    public const SEARCH_URL = 'https://1endpoint-iiiiiiilllllllljjjjjjjjjjttttiiiiiivvvww1.store/v2.8/search';

    public function __construct(string $token, string $finalKey, ?HttpClientInterface $httpClient = null, string $deviceId = 'f43e47928ad910c2')
    {
        if (empty($token)) {
            throw new Exception("Token is required!");
        }
        if (empty($finalKey)) {
            throw new Exception("Final key is required!");
        }

        $this->token = $token;
        $this->finalKey = $finalKey;
        $this->deviceId = $deviceId;
        $this->httpClient = $httpClient ?? new CurlHttpClient();
    }

    public function checkNumber(string $number): array
    {
        $number = NumberValidator::validate($number);

        $payload = [
            "countryCode" => "kz",
            "phoneNumber" => $number,
            "source"      => "profile",
            "token"       => $this->token
        ];

        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $timestamp   = (string) round(microtime(true) * 1000);

        $signature   = Signature::generate($timestamp, $jsonPayload, self::HMAC);
        $encrypted   = Crypto::encrypt($jsonPayload, $this->finalKey);

        $headers = [
            "X-Os: android 9",
            "X-Mobile-Service: GMS",
            "X-App-Version: 8.8.0",
            "X-Client-Device-Id: {$this->deviceId}",
            "X-Lang: ru_RU",
            "X-Token: {$this->token}",
            "X-Req-Timestamp: {$timestamp}",
            "X-Encrypted: 1",
            "X-Network-Country: kz",
            "X-Country-Code: kz",
            "X-Req-Signature: {$signature}",
            "Content-Type: application/json"
        ];

        $response = $this->httpClient->post(
            self::API_URL,
            ["data" => $encrypted],
            $headers
        );

        if (!isset($response['data'])) {
            return [
                "success"   => false,
                "message"   => "Invalid response from API",
                "raw"       => $response
            ];
        }

        $decrypted = Crypto::decrypt($response['data'], $this->finalKey);
        $json      = json_decode($decrypted, true);

        return [
            "success" => true,
            "number"  => $number,
            "tags"    => array_map(fn($t) => $t['tag'], $json['result']['tags'] ?? []),
            "raw"     => $json
        ];
    }

    public function searchNumber(string $number): array
    {
        $number = NumberValidator::validate($number);

        $payload = [
            "countryCode" => "kz",
            "phoneNumber" => $number,
            "source"      => "search",
            "token"       => $this->token
        ];

        $jsonPayload = json_encode($payload, JSON_UNESCAPED_SLASHES);
        $timestamp   = (string) round(microtime(true) * 1000);

        $signature   = Signature::generate($timestamp, $jsonPayload, self::HMAC);
        $encrypted   = Crypto::encrypt($jsonPayload, $this->finalKey);

        $headers = [
            "X-Os: android 9",
            "X-Mobile-Service: GMS",
            "X-App-Version: 8.8.0",
            "X-Client-Device-Id: {$this->deviceId}",
            "X-Lang: ru_RU",
            "X-Token: {$this->token}",
            "X-Req-Timestamp: {$timestamp}",
            "X-Encrypted: 1",
            "X-Network-Country: kz",
            "X-Country-Code: kz",
            "X-Req-Signature: {$signature}",
            "Content-Type: application/json"
        ];

        $response = $this->httpClient->post(
            self::SEARCH_URL,
            ["data" => $encrypted],
            $headers
        );

        if (!isset($response['data'])) {
            return [
                "success"   => false,
                "message"   => "Invalid response from API",
                "raw"       => $response
            ];
        }

        $decrypted = Crypto::decrypt($response['data'], $this->finalKey);
        $json      = json_decode($decrypted, true);

        return [
            "success" => true,
            "number"  => $number,
            "profile" => $json['result']['profile'] ?? '',
            "raw"     => $json
        ];
    }
}
