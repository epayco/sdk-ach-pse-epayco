<?php

namespace PSEIntegration\Cache;

interface Cache
{
    public function set($key, $value, $expiration);
    public function get($key);
    public function incr($key);
    public function delete($key);
}
