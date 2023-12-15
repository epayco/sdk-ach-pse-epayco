<?php

namespace PSEIntegration\Models;

class TransactionInformationRequest
{
    public $entityCode;

    public $trazabilityCode;

    public function __construct(string $entityCode, string $trazabilityCode)
    {
        $this->entityCode = $entityCode;
        $this->trazabilityCode = $trazabilityCode;
    }
}
