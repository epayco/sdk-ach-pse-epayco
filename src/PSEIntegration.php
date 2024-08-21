<?php
/** @noinspection PhpUnused */

namespace PSEIntegration;

use JsonMapper_Exception;
use GuzzleHttp\Exception\GuzzleException;
use PSEIntegration\Services\ApigeeServices;
use PSEIntegration\Models\GetBankListRequest;
use PSEIntegration\Models\TransactionInformationRequest;
use PSEIntegration\Models\CreateTransactionPaymentRequest;
use PSEIntegration\Models\FinalizeTransactionPaymentRequest;

class PSEIntegration
{
    /** @var ApigeeServices $services */
    private ApigeeServices $services;

    /**
     * Class for get pse transactions information
     * @param string $clientId
     * @param string $clientSecret
     * @param string $organizationProdUrl
     * @param string $encryptIV
     * @param string $encryptKey
     */
    public function __construct(string $clientId, string $clientSecret, string $organizationProdUrl,
                                string $encryptIV, string $encryptKey)
    {
        $this->services = new ApigeeServices($clientId, $clientSecret, $organizationProdUrl, $encryptIV, $encryptKey);
    }

    /**
     * Set default time out
     * @param int $timeout
     * @return void
     */
    public function setTimeout(int $timeout): void
    {
        $this->services->apigeeDefaultTimeout = $timeout;
    }

    /**
     * Set flag for ignore or not the SSL certificate
     * @param bool $certificateIgnoreInvalid
     * @return void
     */
    public function setCertificateIgnoreInvalid(bool $certificateIgnoreInvalid): void
    {
        $this->services->certificateIgnoreInvalid = $certificateIgnoreInvalid;
    }

    /**
     * Set custom certificate file
     * @param string $certificateFile
     * @param string $certificatePassword
     * @return void
     */
    public function setMutualTLSCertificate(string $certificateFile, string $certificatePassword): void
    {
        $this->services->certificateFile = $certificateFile;
        $this->services->certificatePassword = $certificatePassword;
    }

    /**
     * Get bank list
     * @throws JsonMapper_Exception
     * @throws GuzzleException
     */
    public function getBankList(GetBankListRequest $request)
    {
        return $this->services->getBankList($request);
    }

    public function deleteRedisSdkCache(){ 
        return $this->services->deleteRedisSdkCache();
    }

    /**
     * Create a simple transaction payment
     * @throws JsonMapper_Exception
     * @throws GuzzleException
     */
    public function createTransactionPayment(CreateTransactionPaymentRequest $request)
    {
        return $this->services->createTransactionPayment($request);
    }

    /**
     * Finalize transaction from request
     * @throws JsonMapper_Exception
     * @throws GuzzleException
     */
    public function finalizeTransactionPayment(FinalizeTransactionPaymentRequest $request)
    {
        return $this->services->finalizeTransactionPayment($request);
    }

    /**
     * Get transaction information
     * @throws JsonMapper_Exception
     * @throws GuzzleException
     */
    public function getTransactionInformation(TransactionInformationRequest $request)
    {
        return $this->services->getTransactionInformation($request);
    }
}
