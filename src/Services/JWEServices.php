<?php

namespace PSEIntegration\Services;

use Sop\JWX\JWE\EncryptionAlgorithm\A128CBCHS256Algorithm;
use Sop\JWX\JWE\KeyAlgorithm\RSAESKeyAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\DirectCEKAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\PBES2HS256A128KWAlgorithm;
use Sop\JWX\JWE\JWE;
use Sop\JWX\JWK\Symmetric\SymmetricKeyJWK;
use Sop\JWX\JWT\Header\Header;
use Sop\JWX\JWT\Parameter\AlgorithmParameter;
use Sop\JWX\JWT\Parameter\JWTParameter;
use Sop\JWX\JWA\JWA;
use Sop\JWX\JWT\Parameter\InitializationVectorParameter;
use Sop\JWX\JWE\KeyAlgorithm\AESGCMKWAlgorithm;
use Sop\JWX\JWE\KeyAlgorithm\KeyAlgorithmFactory;
use Sop\JWX\JWE\KeyManagementAlgorithm;
use Sop\JWX\JWK\JWKSet;

class JWEServices
{
    public static function processEncrypt(string $message, string $key, string $customerIV)
    {
        $encString = JWEServices::encrypt($message, $key, $customerIV);
        return JWEServices::generateTokenJWE($encString, $key);
    }

    public static function processDencrypt(string $message, string $key, string $customerIV)
    {
        $string = JWEServices::stringfyTokenJWE($message, $key);
        return JWEServices::decrypt($string, $key, $customerIV);
    }

    public static function stringfyTokenJWE(string $textoencriptado, string $chaveencriptacao)
    {
        $jwk = SymmetricKeyJWK::fromKey($chaveencriptacao);
        $jwe = JWE::fromCompact($textoencriptado);
        return $jwe->decryptWithJWK($jwk);
    }

    public static function generateTokenJWE(string $message, string $chaveencriptacao)
    {
        $jwk = SymmetricKeyJWK::fromKey($chaveencriptacao);
        $header = new Header(new AlgorithmParameter(JWA::ALGO_DIR));
        $key_algo = DirectCEKAlgorithm::fromJWK($jwk, $header);
        $enc_algo = new A128CBCHS256Algorithm();
        $jwe = JWE::encrypt($message, $key_algo, $enc_algo);
        return $jwe->toCompact();
    }

    public static function encrypt($plaintext, $password, $iv)
    {
        return base64_encode(openssl_encrypt($plaintext, "AES-256-CBC", $password, OPENSSL_RAW_DATA, ($iv)));
    }
    
    public static function decrypt($ivHashCiphertext, $password, $iv)
    {
        return openssl_decrypt(base64_decode($ivHashCiphertext), "AES-256-CBC", $password, OPENSSL_RAW_DATA, ($iv));
    }
}
