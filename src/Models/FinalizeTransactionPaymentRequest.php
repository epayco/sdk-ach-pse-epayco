<?php

namespace PSEIntegration\Models;

class FinalizeTransactionPaymentRequest
{
    public string $entityCode;

    public string $trazabilityCode;

    public string $entityAuthorizationId;

    public function __construct(string $entityCode, string $trazabilityCode, string $entityAuthorizationId)
    {
        $this->entityCode = $entityCode;
        $this->trazabilityCode = $trazabilityCode;
        $this->entityAuthorizationId = $entityAuthorizationId;
    }
}
