<?php

namespace PSEIntegration\cache;

interface Cache
{
    public function set($key, $value, $expiration);
    public function get($key);
    public function incr($key);
    public function delete($key);
}
