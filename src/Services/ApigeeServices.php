<?php
/** @noinspection PhpUnused */

namespace PSEIntegration\Services;

use ArrayObject;
use Exception;
use Illuminate\Support\Facades\Log;
use JsonMapper;
use JsonMapper_Exception;
use GuzzleHttp\Exception\GuzzleException;
use PSEIntegration\Cache\RedisCache;
use PSEIntegration\Models\GetBankListRequest;
use PSEIntegration\Exceptions\UnauthorizedException;
use PSEIntegration\Models\TransactionInformationRequest;
use PSEIntegration\Models\TransactionInformationResponse;
use PSEIntegration\Models\CreateTransactionPaymentRequest;
use PSEIntegration\Models\CreateTransactionPaymentResponse;
use PSEIntegration\Models\FinalizeTransactionPaymentRequest;
use PSEIntegration\Models\FinalizeTransactionPaymentResponse;
use PSEIntegration\Models\CreateTransactionPaymentMultiCreditRequest;
use PSEIntegration\Traits\ApigeeUtils;

class ApigeeServices
{
    use ApigeeUtils;
    private string $apigeeClientId;

    private string $apigeeClientSecret;

    private string $apigeeOrganizationProdUrl;

    private string $apigeeEncryptKey;

    private string $apigeeEncryptIV;

    private string|null $apigeeToken = null;

    private static int $ApigeeLoginAttempts = 0;

    public int $apigeeDefaultTimeout = 30000;

    public string $certificateFile = "";

    public string $certificatePassword = "";

    public bool $certificateIgnoreInvalid = false;

    private RedisCache $redisCache;

    private const APIGEE_TOKEN_TTL = 3000;

    /**
     * Default constructor for Apigee service
     * @param string $apigeeClientId
     * @param string $apigeeClientSecret
     * @param string $apigeeOrganizationProdUrl
     * @param string $apigeeEncryptIV
     * @param string $apigeeEncryptKey
     */
    public function __construct(string $apigeeClientId, string $apigeeClientSecret, string $apigeeOrganizationProdUrl,
                                string $apigeeEncryptIV, string $apigeeEncryptKey)
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
     * @param int $apigeeDefaultTimeout
     * @return void
     */
    public function setApigeeDefaultTimeout(int $apigeeDefaultTimeout): void
    {
        $this->apigeeDefaultTimeout = $apigeeDefaultTimeout;
    }

    /**
     * Set custom certificate file
     * @param string $certificateFile
     * @return void
     */
    public function setCertificateFile(string $certificateFile): void
    {
        $this->certificateFile = $certificateFile;
    }

    /**
     * Set certificate password for file
     * @param string $certificatePassword
     * @return void
     */
    public function setCertificatePassword(string $certificatePassword): void
    {
        $this->certificatePassword = $certificatePassword;
    }

    /**
     * Set flag for ignore or not the SSL certificate
     * @param bool $certificateIgnoreInvalid
     * @return void
     */
    public function setCertificateIgnoreInvalid(bool $certificateIgnoreInvalid): void
    {
        $this->certificateIgnoreInvalid = $certificateIgnoreInvalid;
    }

    /**
     * Login request by client_credentials
     * @return string|null
     * @throws GuzzleException
     */
    public function login(): null|string
    {
        $domain = preg_replace("/^https?:\/\//i", "", $this->apigeeOrganizationProdUrl);
        $key = 'apigee-token-' . $domain;
        $apigeeToken = $this->redisCache->get($key);
        if ($apigeeToken) {
            Log::info('token_skd_ach_pse', [
                'key' => $key,
                'from' => 'Redis',
                'value' => $apigeeToken
            ]);
            $this->apigeeToken = $apigeeToken;
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
            $path, $form,
            "",
            $this->certificateFile,
            $this->certificatePassword,
            $this->certificateIgnoreInvalid
        );
        $response = json_decode($response);

        $this->apigeeToken = $response->access_token;

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
     * @param string $method
     * @param string $content
     * @return string
     * @throws GuzzleException
     */
    private function post(string $method, string $content): string
    {
        $path = "psewebapinf/api/" . $method . "?apikey=" . $this->apigeeClientId;
        $auth = "Bearer " . $this->apigeeToken;

        try {
            return RequestServices::doPostAPICall(
                $this->apigeeDefaultTimeout, $this->apigeeOrganizationProdUrl, $path, $content, $auth,
                $this->certificateFile, $this->certificatePassword, $this->certificateIgnoreInvalid
            );
        } catch (UnauthorizedException|Exception|GuzzleException $e) {
            ApigeeServices::$ApigeeLoginAttempts++;

            if (ApigeeServices::$ApigeeLoginAttempts <= 3) {
                $this->login();

                return $this->post($method, $content);
            }

            throw $e;
        }
    }


    /**
     * Send custom request
     * @throws JsonMapper_Exception|GuzzleException
     */
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
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function getBankList(GetBankListRequest $request)
    {
        $this->login();
        return $this->sendRequest("GetBankListNF", $request, "\PSEIntegration\Models\Bank");
    }

    /**
     * Create a simple transaction payment
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
            "createTransactionPaymentMultiCreditNF",
            $request,
            new CreateTransactionPaymentResponse()
        );
    }

    /**
     * Finalize transaction from request
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function finalizeTransactionPayment(FinalizeTransactionPaymentRequest $request)
    {
        $this->login();
        return $this->sendRequest("FinalizeTransactionPaymentNF", $request, new FinalizeTransactionPaymentResponse());
    }

    /**
     * Get transaction information
     * @throws JsonMapper_Exception|GuzzleException
     */
    public function getTransactionInformation(TransactionInformationRequest $request)
    {
        $this->login();
        return $this->sendRequest("GetTransactionInformationNF", $request, new TransactionInformationResponse());
    }
}
