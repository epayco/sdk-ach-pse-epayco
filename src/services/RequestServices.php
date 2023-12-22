<?php
/** @noinspection PhpUnused */

namespace PSEIntegration\Services;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\GuzzleException;
use PSEIntegration\exceptions\UnauthorizedException;

class RequestServices
{
    private const CALL_EXCEPTION = "Call to %s returns %s - %s ";
    /**
     * Default Guzzle client
     *
     * @param string $baseUrl
     * @param int $timeout
     * @param string $certFile
     * @param string $certPassword
     * @param bool $verifySSL
     * @return Client
     */
    private static function getHttpClient(string $baseUrl, int $timeout, string $certFile,
                                          string $certPassword, bool $verifySSL) : Client
    {
        $config = [
            'base_uri' => $baseUrl,
            'timeout'  => $timeout
        ];

        if ($verifySSL) {
            $config['verify'] = false;
        }

        if (!empty($certFile)) {
            $config['cert'] = [$certFile, $certPassword];
        }

        return new Client($config);
    }

    /**
     * Generate custom post api call with custom body content
     *
     * @throws GuzzleException
     * @throws Exception
     */
    public static function doPostAPICall(int $timeout, string $url, string $endpoint, string $content, string $auth,
                                         string $certFile, string $certPassword, bool $certIgnoreInvalid) : string
    {
        $headers = [];
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = $client->request('POST', $endpoint, ['body' => $content, 'headers' => $headers]);

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } elseif ($response->getStatusCode() == 401) {
            throw new UnauthorizedException(sprintf(self::CALL_EXCEPTION,
                $endpoint, $response->getStatusCode(), $response->getBody()
            ));
        } else {
            throw new Exception(sprintf(self::CALL_EXCEPTION,
                $endpoint, $response->getStatusCode(), $response->getBody()
            ));
        }
    }

    /**
     * Generate custom post api call with form_params
     *
     * @throws GuzzleException
     * @throws Exception
     */
    public static function doPostFormAPICall(int $timeout, string $url, string $endpoint, array $form, string $auth,
                                             string $certFile, string $certPassword, bool $certIgnoreInvalid) : string
    {
        $headers = [];
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = $client->request('POST', $endpoint, ['form_params' => $form, 'headers' => $headers]);

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } else {
            throw new Exception(sprintf(self::CALL_EXCEPTION,
                $endpoint, $response->getStatusCode(), $response->getBody()
            ));
        }
    }
}
