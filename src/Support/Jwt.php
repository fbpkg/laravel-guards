<?php

namespace Fbpkg\Guards\Support;

use Fbpkg\Guards\Exceptions\ConfigurationException;
use JsonException;
use OpenSSLAsymmetricKey;
use UnexpectedValueException;

final class Jwt
{
    protected readonly string $algorithm;

    protected ?string $secret = null;

    protected ?OpenSSLAsymmetricKey $privateKey = null;

    protected ?OpenSSLAsymmetricKey $publicKey = null;

    public function __construct()
    {
        $this->algorithm = Config::jwtAlgorithm();

        if ($this->algorithm === 'HS256') {
            $this->secret = Config::jwtSecret();

            return;
        }

        $this->loadKeyPair();
    }

    /**
     * Encode and sign JWT claims.
     *
     * @param array<string, mixed> $claims
     *
     * @throws ConfigurationException
     * @throws JsonException
     */
    public function encode(array $claims): string
    {
        $header = [
            'typ' => 'JWT',
            'alg' => $this->algorithm,
        ];

        $encodedHeader = $this->base64UrlEncode(
            json_encode($header, JSON_THROW_ON_ERROR),
        );

        $encodedPayload = $this->base64UrlEncode(
            json_encode($claims, JSON_THROW_ON_ERROR),
        );

        $signingInput = $encodedHeader . '.' . $encodedPayload;

        $signature = $this->sign($signingInput);

        return $signingInput . '.' . $this->base64UrlEncode($signature);
    }

    /**
     * Verify a JWT and return its claims.
     *
     * @return array<string, mixed>
     *
     * @throws UnexpectedValueException
     * @throws ConfigurationException
     * @throws JsonException
     */
    public function decode(string $token): array
    {
        $parts = explode('.', $token);

        if (count($parts) !== 3) {
            throw new UnexpectedValueException('Invalid JWT format.');
        }

        [$encodedHeader, $encodedPayload, $encodedSignature] = $parts;

        $header = json_decode(
            $this->base64UrlDecode($encodedHeader),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        if (
            !is_array($header)
            || ($header['alg'] ?? null) !== $this->algorithm
        ) {
            throw new UnexpectedValueException(
                'The JWT signing algorithm does not match the configured algorithm.',
            );
        }

        $signature = $this->base64UrlDecode($encodedSignature);

        if (!$this->verify(
            $encodedHeader . '.' . $encodedPayload,
            $signature,
        )) {
            throw new UnexpectedValueException('Invalid JWT signature.');
        }

        $claims = json_decode(
            $this->base64UrlDecode($encodedPayload),
            true,
            512,
            JSON_THROW_ON_ERROR,
        );

        if (!is_array($claims)) {
            throw new UnexpectedValueException('Invalid JWT payload.');
        }

        if (
            isset($claims['exp'])
            && (!is_numeric($claims['exp']) || time() >= $claims['exp'])
        ) {
            throw new UnexpectedValueException('The JWT has expired.');
        }

        if (
            isset($claims['nbf'])
            && (!is_numeric($claims['nbf']) || time() < $claims['nbf'])
        ) {
            throw new UnexpectedValueException(
                'The JWT is not valid yet.',
            );
        }

        return $claims;
    }

    /**
     * Create a signature using the configured algorithm.
     */
    protected function sign(string $data): string
    {
        if ($this->algorithm === 'HS256') {
            return hash_hmac('sha256', $data, $this->secret, true);
        }

        if (!openssl_sign(
            $data,
            $signature,
            $this->privateKey,
            OPENSSL_ALGO_SHA256,
        )) {
            throw ConfigurationException::invalid(
                'Unable to sign the JWT using the configured private key.',
            );
        }

        return $this->derToRaw($signature);
    }

    /**
     * Verify a signature using the configured algorithm.
     */
    protected function verify(string $data, string $signature): bool
    {
        if ($this->algorithm === 'HS256') {
            $expected = hash_hmac(
                'sha256',
                $data,
                $this->secret,
                true,
            );

            return hash_equals($expected, $signature);
        }

        if (strlen($signature) !== 64) {
            return false;
        }

        return openssl_verify(
            $data,
            $this->rawToDer($signature),
            $this->publicKey,
            OPENSSL_ALGO_SHA256,
        ) === 1;
    }

    /**
     * Load and validate the ES256 key pair.
     */
    protected function loadKeyPair(): void
    {
        $privatePem = $this->resolveKey(
            Config::jwtPrivateKey(),
        );

        $publicPem = $this->resolveKey(
            Config::jwtPublicKey(),
        );

        $privateKey = openssl_pkey_get_private($privatePem);
        $publicKey = openssl_pkey_get_public($publicPem);

        if (!$privateKey || !$publicKey) {
            throw ConfigurationException::invalid(
                'The configured JWT keys are invalid.',
            );
        }

        $privateDetails = openssl_pkey_get_details($privateKey);
        $publicDetails = openssl_pkey_get_details($publicKey);

        if (
            !is_array($privateDetails)
            || !is_array($publicDetails)
            || ($privateDetails['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($publicDetails['type'] ?? null) !== OPENSSL_KEYTYPE_EC
            || ($privateDetails['ec']['curve_name'] ?? null) !== 'prime256v1'
            || ($publicDetails['ec']['curve_name'] ?? null) !== 'prime256v1'
        ) {
            throw ConfigurationException::invalid(
                'ES256 requires EC keys using the P-256 curve.',
            );
        }

        $privateEc = $privateDetails['ec'];
        $publicEc = $publicDetails['ec'];

        if (
            !isset($privateEc['x'], $privateEc['y'], $publicEc['x'], $publicEc['y'])
            || !hash_equals($privateEc['x'], $publicEc['x'])
            || !hash_equals($privateEc['y'], $publicEc['y'])
        ) {
            throw ConfigurationException::invalid(
                'The configured JWT private and public keys do not match.',
            );
        }

        $this->privateKey = $privateKey;
        $this->publicKey = $publicKey;
    }

    /**
     * Resolve PEM content or a file path to PEM content.
     */
    protected function resolveKey(string $key): string
    {
        if (str_contains($key, '-----BEGIN')) {
            return str_replace('\\n', "\n", $key);
        }

        if (is_file($key) && is_readable($key)) {
            $contents = file_get_contents($key);

            if ($contents !== false) {
                return $contents;
            }
        }

        throw ConfigurationException::invalid(
            'The configured JWT key must contain valid PEM data or a readable file path.',
        );
    }

    /**
     * Encode binary data using Base64 URL encoding.
     */
    protected function base64UrlEncode(string $value): string
    {
        return rtrim(
            strtr(base64_encode($value), '+/', '-_'),
            '=',
        );
    }

    /**
     * Decode Base64 URL encoded data.
     */
    protected function base64UrlDecode(string $value): string
    {
        if (
            $value === ''
            || preg_match('/\A[A-Za-z0-9_-]+\z/', $value) !== 1
        ) {
            throw new UnexpectedValueException(
                'Invalid Base64 URL encoding.',
            );
        }

        $decoded = base64_decode(
            strtr($value, '-_', '+/')
                . str_repeat('=', (4 - strlen($value) % 4) % 4),
            true,
        );

        if ($decoded === false) {
            throw new UnexpectedValueException(
                'Invalid Base64 URL encoding.',
            );
        }

        return $decoded;
    }

    /**
     * Convert an OpenSSL DER ECDSA signature to the 64-byte JWT format.
     */
    protected function derToRaw(string $signature): string
    {
        $offset = 0;

        if (ord($signature[$offset++]) !== 0x30) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid ECDSA signature.',
            );
        }

        $sequenceLength = $this->readDerLength($signature, $offset);

        if ($sequenceLength !== strlen($signature) - $offset) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid ECDSA signature.',
            );
        }

        $r = $this->readDerInteger($signature, $offset);
        $s = $this->readDerInteger($signature, $offset);

        if ($offset !== strlen($signature)) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid ECDSA signature.',
            );
        }

        return $this->integerToFixedBytes($r)
            . $this->integerToFixedBytes($s);
    }

    /**
     * Convert the 64-byte JWT ECDSA signature to OpenSSL DER format.
     */
    protected function rawToDer(string $signature): string
    {
        if (strlen($signature) !== 64) {
            throw new UnexpectedValueException(
                'Invalid ES256 signature length.',
            );
        }

        $r = $this->integerToDer(substr($signature, 0, 32));
        $s = $this->integerToDer(substr($signature, 32, 32));

        $sequence = $r . $s;

        return "\x30"
            . $this->encodeDerLength(strlen($sequence))
            . $sequence;
    }

    protected function readDerLength(
        string $data,
        int &$offset,
    ): int {
        if ($offset >= strlen($data)) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid DER signature.',
            );
        }

        $length = ord($data[$offset++]);

        if (($length & 0x80) === 0) {
            return $length;
        }

        $bytes = $length & 0x7f;

        if (
            $bytes === 0
            || $bytes > 4
            || $offset + $bytes > strlen($data)
        ) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid DER signature.',
            );
        }

        $length = 0;

        for ($i = 0; $i < $bytes; $i++) {
            $length = ($length << 8) | ord($data[$offset++]);
        }

        return $length;
    }

    protected function readDerInteger(
        string $data,
        int &$offset,
    ): string {
        if (
            $offset >= strlen($data)
            || ord($data[$offset++]) !== 0x02
        ) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid DER signature.',
            );
        }

        $length = $this->readDerLength($data, $offset);

        if ($length < 1 || $offset + $length > strlen($data)) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid DER signature.',
            );
        }

        $integer = substr($data, $offset, $length);
        $offset += $length;

        return ltrim($integer, "\0");
    }

    protected function integerToFixedBytes(string $integer): string
    {
        $integer = ltrim($integer, "\0");

        if (strlen($integer) > 32) {
            throw ConfigurationException::invalid(
                'OpenSSL returned an invalid ES256 integer.',
            );
        }

        return str_pad($integer, 32, "\0", STR_PAD_LEFT);
    }

    protected function integerToDer(string $integer): string
    {
        $integer = ltrim($integer, "\0");

        if ($integer === '') {
            $integer = "\0";
        } elseif ((ord($integer[0]) & 0x80) !== 0) {
            $integer = "\0" . $integer;
        }

        return "\x02"
            . $this->encodeDerLength(strlen($integer))
            . $integer;
    }

    protected function encodeDerLength(int $length): string
    {
        if ($length < 0x80) {
            return chr($length);
        }

        $encoded = '';

        while ($length > 0) {
            $encoded = chr($length & 0xff) . $encoded;
            $length >>= 8;
        }

        return chr(0x80 | strlen($encoded)) . $encoded;
    }
}
