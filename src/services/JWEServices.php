<?php

namespace PSEIntegration\services;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;

class JWEServices
{
    /**
     * Get encrypted text from symmetric key and generate token for it
     *
     * @param string $message
     * @param string $key
     * @param string $customerIV
     * @return string
     */
    public static function processEncrypt(string $message, string $key, string $customerIV): string
    {
        $encString = JWEServices::encrypt($message, $key, $customerIV);

        return JWEServices::generateTokenJWE($encString, $key);
    }

    /**
     * Get encrypted text from symmetric key and custom data
     *
     * @param string $message
     * @param string $key
     * @param string $customerIV
     * @return bool|string
     */
    public static function processDecrypt(string $message, string $key, string $customerIV): bool|string
    {
        $string = JWEServices::stringFyTokenJWE($message, $key);

        return JWEServices::decrypt($string, $key, $customerIV);
    }

    /**
     * Get decrypted text from symmetric key
     *
     * @param string $encryptedText
     * @param string $symmetricKey
     * @return string
     */
    public static function stringFyTokenJWE(string $encryptedText, string $symmetricKey): string
    {
        $jwk = SymmetricKeyJWK::fromKey($symmetricKey);
        $jwe = JWE::fromCompact($encryptedText);

        return $jwe->decryptWithJWK($jwk);
    }

    /**
     * Generate token from SymmetricKeyJWK
     *
     * @param string $message
     * @param string $symmetricKey
     * @return string
     */
    public static function generateTokenJWE(string $message, string $symmetricKey): string
    {
        $jwk = SymmetricKeyJWK::fromKey($symmetricKey);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $key_algo = DirectCEKAlgorithm::fromJWK($jwk, $header);
        $enc_algo = new A128CBCHS256Algorithm();
        $jwe = JWE::encrypt($message, $key_algo, $enc_algo);

        return $jwe->toCompact();
    }

    /**
     * Encrypt text with hash and password
     *
     * @param $plaintext
     * @param $password
     * @param $iv
     * @return string
     */
    public static function encrypt($plaintext, $password, $iv): string
    {
        return base64_encode(openssl_encrypt($plaintext, "AES-256-CBC", $password,
            OPENSSL_RAW_DATA, ($iv)));
    }

    /**
     * Decrypt text with hash and password
     *
     * @param $ivHashCiphertext
     * @param $password
     * @param $iv
     * @return false|string
     */
    public static function decrypt($ivHashCiphertext, $password, $iv): bool|string
    {
        return openssl_decrypt(base64_decode($ivHashCiphertext), "AES-256-CBC", $password,
            OPENSSL_RAW_DATA, ($iv));
    }
}
