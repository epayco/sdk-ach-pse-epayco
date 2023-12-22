<?php

namespace PSEIntegration\Services;

use ArrayObject;
use Exception;
use Illuminate\Support\Facades\Log;
use JsonMapper;
use JsonMapper_Exception;
use GuzzleHttp\Exception\GuzzleException;
use PSEIntegration\Cache\RedisCache;
use PSEIntegration\exceptions\UnauthorizedException;
use PSEIntegration\services\RequestServices;
use PSEIntegration\services\JWEServices;
use PSEIntegration\models\GetBankListRequest;
use PSEIntegration\models\CreateTransactionPaymentRequest;
use PSEIntegration\models\CreateTransactionPaymentResponse;
use PSEIntegration\models\FinalizeTransactionPaymentRequest;
use PSEIntegration\models\FinalizeTransactionPaymentResponse;
use PSEIntegration\models\TransactionInformationRequest;
use PSEIntegration\models\TransactionInformationResponse;
use PSEIntegration\models\CreateTransactionPaymentMulticreditRequest;

use PSEIntegration\models\Bank;
use PSEIntegration\traits\ApigeeUtils;

class ApigeeServices
{
    use ApigeeUtils;
    private string $apigeeClientId;

    private string $apigeeClientSecret;

    private string $apigeeOrganizationProdUrl;

    private string $apigeeEncryptKey;

    private string $apigeeEncryptIV;

    private static $apigeeToken;

    private static int $apigeeLoginAttemps = 0;

    public int $apigeeDefaultTimeout = 30000;

    public string $certificateFile = "";

    public string $certificatePassword = "";

    public bool $certificateIgnoreInvalid = false;

    private $auth;

    private RedisCache $redisCache;

    private const APIGEE_TOKEN_TTL = 3000;

    /**
     * Default constructor for Apigee service
     *
     * @param string $apigeeClientId
     * @param string $apigeeClientSecret
     * @param string $apigeeOrganizationProdUrl
     * @param string $apigeeEncryptIV
     * @param string $apigeeEncryptKey
     */
    public function __construct(
        string $apigeeClientId,
        string $apigeeClientSecret,
        string $apigeeOrganizationProdUrl,
        string $apigeeEncryptIV,
        string $apigeeEncryptKey)
    {
        $this->apigeeClientId = $apigeeClientId;
        $this->apigeeClientSecret = $apigeeClientSecret;
        $this->apigeeOrganizationProdUrl = $apigeeOrganizationProdUrl;
        $this->apigeeEncryptIV = $apigeeEncryptIV;
        $this->apigeeEncryptKey = $apigeeEncryptKey;
        $this->redisCache = new RedisCache();
    }

    /**
     * Set default time out
     *
     * @param int $apigeeDefaultTimeout
     * @return void
     */
    public function setApigeeDefaultTimeout(int $apigeeDefaultTimeout): void
    {
        $this->apigeeDefaultTimeout = $apigeeDefaultTimeout;
    }

    /**
     * Set custom certificate file
     *
     * @param string $certificateFile
     * @return void
     */
    public function setCertificateFile(string $certificateFile): void
    {
        $this->certificateFile = $certificateFile;
    }

    /**
     * Set certificate password for file
     *
     * @param string $certificatePassword
     * @return void
     */
    public function setCertificatePassword(string $certificatePassword): void
    {
        $this->certificatePassword = $certificatePassword;
    }

    /**
     * Set flag for ignore or not the SSL certificate
     *
     * @param bool $certificateIgnoreInvalid
     * @return void
     */
    public function setCertificateIgnoreInvalid(bool $certificateIgnoreInvalid): void
    {
        $this->certificateIgnoreInvalid = $certificateIgnoreInvalid;
    }

    public function login()
    {
        $key = 'ApigeeToken_' . $this->apigeeClientId;
        $apigeeToken = $this->redisCache->get($key);
        if ($apigeeToken) {
            Log::info('token_skd_ach_pse', [
                'key' => $key,
                'from' => 'Redis',
                'value' => $apigeeToken
            ]);
            ApigeeServices::$apigeeToken = $apigeeToken;
            return $apigeeToken;
        }

        $path = "oauth/client_credential/accesstoken?grant_type=client_credentials";

        $form = [
            "grant_type" => "client_credentials",
            "client_id" => $this->apigeeClientId,
            "client_secret" => $this->apigeeClientSecret
        ];

        $response = RequestServices::doPostFormAPICall(
            $this->apigeeDefaultTimeout,
            $this->apigeeOrganizationProdUrl,
            $path,
            $form,
            "",
            $this->certificateFile,
            $this->certificatePassword,
            $this->certificateIgnoreInvalid);
        $response = json_decode($response);

        ApigeeServices::$apigeeToken = $response->access_token;

        Log::info('token_skd_ach_pse', [
            'key' => $key,
            'from' => 'PSE',
            'value' => $response->access_token
        ]);

        $this->redisCache->set(
            $key,
            $response->access_token,
            self::APIGEE_TOKEN_TTL
        );
    }

    /**
     * Generate post request with recursive send on error
     *
     * @param string $method
     * @param string $content
     * @return string
     * @throws GuzzleException
     */
    private function post(string $method, string $content)
    {
        $path = "psewebapinf/api/" . $method . "?apikey=" . $this->apigeeClientId;

        $this->auth = "Bearer " . ApigeeServices::$apigeeToken;

        try {
            return RequestServices::doPostAPICall(
                $this->apigeeDefaultTimeout,
                $this->apigeeOrganizationProdUrl,
                $path, $content, $this->auth,
                $this->certificateFile,
                $this->certificatePassword,
                $this->certificateIgnoreInvalid);
        } catch (UnauthorizedException $e) {
            // Try login
            ApigeeServices::$apigeeLoginAttemps++;

            if (ApigeeServices::$apigeeLoginAttemps <= 3) {
                $this->login();

                // Try again
                return $this->post($method, $content);
            } else {
                throw $e;
            }
        } catch (Exception $e) {
            throw $e;
        }
    }


    private function sendRequest(string $method, Object $message, $type)
    {
        Log::info('message_skd_ach_pse', [
            'state' => 'before',
            'message' => $message
        ]);
        // Remove special characters(Pipeline and double quotation)
        $message = $this->removePipelineDoubleQuotation((array)$message);

        Log::info('message_skd_ach_pse', [
            'state' => 'after',
            'message' => $message
        ]);
        // Create JWE with AES
        $jwe = JWEServices::processEncrypt(json_encode($message), $this->apigeeEncryptKey, $this->apigeeEncryptIV);

        // Make request
        $responseString = $this->post($method, $jwe);

        // Decrypt and verify JWE
        $responseJWE = JWEServices::processDecrypt($responseString, $this->apigeeEncryptKey, $this->apigeeEncryptIV);

        $mapper = new JsonMapper();
        $mapper->bStrictNullTypes = false;

        if (gettype($type) == 'string') {
            return $mapper->mapArray(json_decode($responseJWE), new ArrayObject, $type);
        } else {
            return $mapper->map(json_decode($responseJWE), $type);
        }
    }

    /**
     * Get bank list
     *
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function getBankList(GetBankListRequest $request)
    {
        $this->login();
        return $this->sendRequest("GetBankListNF", $request, "\PSEIntegration\Models\Bank");
    }

    /**
     * Create a simple transaction payment
     *
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function createTransactionPayment(CreateTransactionPaymentRequest $request)
    {
        $this->login();
        return $this->sendRequest("CreateTransactionPaymentNF", $request, new CreateTransactionPaymentResponse());
    }

    /**
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function createTransactionPaymentMultiCredit(CreateTransactionPaymentMultiCreditRequest $request)
    {
        $this->login();
        return $this->sendRequest(
            "createTransactionPaymentMultiCreditNF", $request,
            new CreateTransactionPaymentResponse());
    }

    /**
     * Finalize transaction from request
     *
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function finalizeTransactionPayment(FinalizeTransactionPaymentRequest $request)
    {
        $this->login();
        return $this->sendRequest("FinalizeTransactionPaymentNF", $request, new FinalizeTransactionPaymentResponse());
    }

    /**
     * Get transaction information
     *
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function getTransactionInformation(TransactionInformationRequest $request)
    {
        $this->login();
        return $this->sendRequest("GetTransactionInformationNF", $request, new TransactionInformationResponse());
    }
}
