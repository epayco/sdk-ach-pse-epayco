<?php

namespace PSEIntegration\Models;

class GetBankListRequest
{
    public $entityCode;

    public function __construct(string $entityCode)
    {
        $this->entityCode = $entityCode;
    }
}
