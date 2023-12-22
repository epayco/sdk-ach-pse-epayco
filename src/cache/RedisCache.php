<?php

namespace PSEIntegration\Cache;

class RedisCache implements Cache
{
    private $redis;

    public function __construct()
    {
        $this->redis = app('redis')->connection();
    }

    public function set($key, $value, $expiration): void
    {
        $this->redis->set($key, json_encode($value));
        $this->redis->expire($key, $expiration);
    }

    public function get($key): object|string|null
    {
        $redisCacheValues = $this->redis->get($key);
        return $redisCacheValues ? json_decode($redisCacheValues) : null;
    }

    public function incr($key): int
    {
        return $this->redis->incr($key);
    }

    public function delete($key): void
    {
        $this->redis->del($key);
    }

}
