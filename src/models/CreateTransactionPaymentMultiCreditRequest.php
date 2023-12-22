<?php
/** @noinspection PhpUnused */

namespace PSEIntegration\models;

/**
 * @property-read Credit[] $credits
 */

class CreateTransactionPaymentMultiCreditRequest
{
    public $entityCode;

    public $financialInstitutionCode;

    public $serviceCode;

    public $transactionValue;

    public $vatValue;

    public $ticketId;

    public $entityurl;

    public $userType;

    public $referenceNumber1;

    public $referenceNumber2;

    public $referenceNumber3;

    public $soliciteDate;

    public $paymentDescription;

    public $credits;

    public $identificationType;

    public $identificationNumber;

    public $fullName;

    public $cellphoneNumber;

    public $address;

    public $email;

    public $beneficiaryEntityIdentificationType;

    public $beneficiaryEntityIdentification;

    public $beneficiaryEntityName;

    public $beneficiaryEntityCIIUCategory;

    public $beneficiaryIdentificationType;

    public $beneficiaryIdentification;

    public $indicator4per1000;

    public function __construct(
        array $options=array()
    )
    {
        foreach($options as $key => $value)
        {
            $this->{$key}=$value;
        }
    }
}
