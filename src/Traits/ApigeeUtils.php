<?php

namespace PSEIntegration\Traits;

trait ApigeeUtils
{
    public function removePipeline($text)
    {
        if (is_string($text)) {
            return str_ireplace('|', '', $text);
        }
        return $text;
    }

    public function removeDoubleQuotation($text)
    {
        // Handle arrays by processing each element recursively
        if (is_array($text)) {
            return array_map([$this, 'removeDoubleQuotation'], $text);
        }

        // Handle strings normally
        if (is_string($text)) {
            return str_ireplace('"', '', $text);
        }

        // Return other types unchanged
        return $text;
    }

    public function removePipelineDoubleQuotation(array $request): ?array
    {
        $requestData = array_map([$this, 'removePipeline'], $request);
        return array_map([$this, 'removeDoubleQuotation'], $requestData);
    }

}
