<?php

namespace PSEIntegration\Traits;

trait ApigeeUtils
{
    public function removePipeline($text): string
    {
        return str_ireplace('|', '', $text);
    }

    public function removeDoubleQuotation($text): string
    {
        return str_ireplace('"', '', $text);
    }

    public function removePipelineDoubleQuotation(array $request): ?array
    {
        $requestData = array_map([$this, 'removePipeline'], $request);
        return array_map([$this, 'removeDoubleQuotation'], $requestData);
    }

}
