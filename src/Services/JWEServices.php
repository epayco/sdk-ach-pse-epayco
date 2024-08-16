<?php

namespace PSEIntegration\Services;

use Sop\JWX\JWA\JWA;
use Sop\JWX\JWE\EncryptionAlgorithm\A256GCMAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;

class JWEServices
{
    private const CIPHER_ALGORITHM = 'AES-256-GCM';
    private const TAG_LENGTH = 16;
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

        return JWEServices::generateTokenJWE($encString, $key, $customerIV);
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
        $enc_algo = new A256GCMAlgorithm();
        $jwe = JWE::encrypt($message, $key_algo, $enc_algo);

        return $jwe->toCompact();
    }

    /**
     * Encrypt text with hash and password
     *
     * @param $plaintext
     * @param $password
     * @param $iv
     * @return string|null
     */
    public static function encrypt($plaintext, $password, $iv): ?string
    {
        $tag = "";

        $ciphertext = openssl_encrypt(
            $plaintext,
            self::CIPHER_ALGORITHM,
            $password,
            OPENSSL_RAW_DATA,
            $iv,
            $tag,
            "",
            self::TAG_LENGTH
        );

        return base64_encode($iv.$ciphertext.$tag);
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
        $decodedText = base64_decode($ivHashCiphertext);
        $tag = substr($decodedText, -self::TAG_LENGTH);
        $ivLength = strlen($iv);
        $encryptText = substr($decodedText, $ivLength, -self::TAG_LENGTH);

        return openssl_decrypt(
            $encryptText,
            self::CIPHER_ALGORITHM,
            $password,
            OPENSSL_RAW_DATA,
            $iv,
            $tag
        );
    }
}
