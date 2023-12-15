<?php

namespace PSEIntegration\Services;

use Exception;
use GuzzleHttp\Client;
use HttpResponseException;
use PSEIntegration\Exceptions\UnauthorizedException;
use Psr\Http\Message\ResponseInterface;

class RequestServices
{
    private const ERROR_MESSAGES = "Call to %s returns %s";
    private static function getHttpClient(
        $url,
        int $timeout,
        string $certFile,
        string $certPassword,
        bool $certIgnoreInvalid) : \GuzzleHttp\Client
    {
        $config = [
            'base_uri' => $url,
            'timeout'  => $timeout
        ];

        if ($certIgnoreInvalid) {
            $config['verify'] = false;
        }

        if (!empty($certFile)) {
            $config['cert'] = [$certFile, $certPassword];
        }

        return new \GuzzleHttp\Client($config);
    }

    /**
     * @throws Exception
     */
    public static function doPostAPICall(
        int $timeout,
        string $url,
        string $method,
        string $content,
        string $auth,
        string $certFile,
        string $certPassword,
        bool $certIgnoreInvalid): string
    {
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        $headers = [];

        // Set Authorization header if exists
        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = $client->request('POST', $method, ['body' => $content, 'headers' => $headers]);

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } elseif ($response->getStatusCode() == 401) {
            throw new UnauthorizedException(
                sprintf(
                    self::ERROR_MESSAGES,
                    $method,
                    $response->getStatusCode() . " - " . $response->getBody()
                )
            );
        } else {
            trigger_error(sprintf(
                self::ERROR_MESSAGES,
                $method,
                $response->getStatusCode() . " - " . $response->getBody()
            ));
        }
    }

    /**
     * @throws HttpResponseException
     */
    public static function doPostFormAPICall(
        int $timeout,
        string $url,
        string $method,
        array $form,
        string $auth,
        string $certFile,
        string $certPassword,
        bool $certIgnoreInvalid): string
    {
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        $headers = [];

        // Set Authorization header if exists
        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = $client->request('POST', $method, ['form_params' => $form, 'headers' => $headers]);

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } else {
            throw new HttpResponseException(sprintf(
                self::ERROR_MESSAGES,
                $method,
                $response->getStatusCode() . " - " . $response->getBody()
            ));
        }
    }
}
