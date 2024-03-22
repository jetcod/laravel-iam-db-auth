<?php

namespace Pixelvide\DBAuth\Auth;

use Aws\Credentials\CredentialProvider;
use Aws\Rds\AuthTokenGenerator;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Cache;

class RDSTokenProvider
{
    /**
     * AWS configuration values
     *
     * @var Array
     */
    protected $config;

    /**
     * Database connection string.
     *
     * @var string
     */
    protected $connectionString;

    /**
     * @var AuthTokenGenerator
     */
    private $rds_auth_generator;

    /**
     * Class constructor
     *
     * @param  Array - AWS configuration
     * @return Void
     */
    public function __construct(string $dsn, array $config)
    {
        $this->connectionString = md5($dsn);
        $this->cacheKey = md5($dsn);
        $this->config = $config;
        $provider = CredentialProvider::defaultProvider();
        $this->rds_auth_generator = new AuthTokenGenerator($provider);
    }

    /**
     * Get the DBs Auth token from the AWS Auth Token Generator
     *
     * @param  Bool - Force refetch of cached token
     * @return String - Auth token
     */
    public function getToken($refetch = false)
    {
        $key = md5($this->connectionString);
        
        if ($refetch) {
            Cache::forget($key);
        }

        return Cache::remember($key, 10, function () {
            return $this->rds_auth_generator->createToken(
                Arr::get($this->config, 'host').':'.Arr::get($this->config, 'port'),
                Arr::get($this->config, 'aws_region'),
                Arr::get($this->config, 'username')
            );
        });
    }
}