<?php

namespace PSEIntegration\Models;

class FinalizeTransactionPaymentRequest
{
    public string $entityCode;

    public string $traceabilityCode;

    public string $entityAuthorizationId;

    public function __construct(string $entityCode, string $traceabilityCode, string $entityAuthorizationId)
    {
        $this->entityCode = $entityCode;
        $this->traceabilityCode = $traceabilityCode;
        $this->entityAuthorizationId = $entityAuthorizationId;
    }
}
