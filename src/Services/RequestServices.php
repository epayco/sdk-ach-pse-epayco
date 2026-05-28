<?php
/** @noinspection PhpUnused */

namespace PSEIntegration\Services;

use Exception;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\GuzzleException;
use GuzzleHttp\Exception\RequestException;
use PSEIntegration\Exceptions\UnauthorizedException;
use Psr\Http\Message\ResponseInterface;

class RequestServices
{
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
     * Execute a request with retry policy for transient failures
     *
     * Retries on ConnectException (network/timeout) and 5xx server errors.
     * Does NOT retry on 4xx client errors.
     *
     * @param callable $request
     * @param int $retryCount
     * @param int $retryDelay Delay between retries in milliseconds
     * @return ResponseInterface
     * @throws GuzzleException
     */
    private static function executeWithRetry(callable $request, int $retryCount, int $retryDelay): ResponseInterface
    {
        $lastException = null;

        for ($attempt = 0; $attempt <= $retryCount; $attempt++) {
            try {
                return $request();
            } catch (ConnectException $e) {
                $lastException = $e;
            } catch (RequestException $e) {
                if ($e->hasResponse() && $e->getResponse()->getStatusCode() < 500) {
                    throw $e;
                }
                $lastException = $e;
            }

            if ($attempt < $retryCount) {
                usleep($retryDelay * 1000);
            }
        }

        throw $lastException;
    }

    /**
     * Generate custom post api call with custom body content
     *
     * @throws GuzzleException
     * @throws Exception
     */
    public static function doPostAPICall(int $timeout, string $url, string $endpoint, string $content, string $auth,
                                         string $certFile, string $certPassword, bool $certIgnoreInvalid,
                                         int $retryCount = 0, int $retryDelay = 1000) : string
    {
        $headers = [];
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = self::executeWithRetry(
            fn () => $client->request('POST', $endpoint, ['body' => $content, 'headers' => $headers]),
            $retryCount,
            $retryDelay
        );

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } elseif ($response->getStatusCode() == 401) {
            throw new UnauthorizedException(sprintf("Call to %s returns %s - %s ",
                $endpoint, $response->getStatusCode(), $response->getBody()
            ));
        } else {
            throw new Exception(sprintf("Call to %s returns %s - %s ",
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
                                             string $certFile, string $certPassword, bool $certIgnoreInvalid,
                                             int $retryCount = 0, int $retryDelay = 1000) : string
    {
        $headers = [];
        $client = RequestServices::getHttpClient($url, $timeout, $certFile, $certPassword, $certIgnoreInvalid);

        if (!empty($auth)) {
            $headers = [
                'Authorization' => $auth,
                'Content-Type'  => 'application/json',
            ];
        }

        $response = self::executeWithRetry(
            fn () => $client->request('POST', $endpoint, ['form_params' => $form, 'headers' => $headers]),
            $retryCount,
            $retryDelay
        );

        if ($response->getStatusCode() == 200) {
            return  $response->getBody();
        } else {
            throw new Exception(sprintf("Call to %s returns %s - %s ",
                $endpoint, $response->getStatusCode(), $response->getBody()
            ));
        }
    }
}
