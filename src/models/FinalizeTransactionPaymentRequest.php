<?php

namespace PSEIntegration\Models;

class FinalizeTransactionPaymentRequest
{
    public $entityCode;

    public $trazabilityCode;

    public $entityAuthorizationId;
    
    public function __construct(string $entityCode, string $trazabilityCode, string $entityAuthorizationId)
    {
        $this->entityCode = $entityCode;
        $this->trazabilityCode = $trazabilityCode;
        $this->entityAuthorizationId = $entityAuthorizationId;
    }
}
