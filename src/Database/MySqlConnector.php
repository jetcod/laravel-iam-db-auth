<?php

namespace Jetcod\DBAuth\Database;

use Exception;
use Illuminate\Database\Connectors\MySqlConnector as DefaultMySqlConnector;
use Illuminate\Support\Arr;
use Illuminate\Support\Str;
use PDO;
use Pixelvide\DBAuth\Auth\RDSTokenProvider;

class MySqlConnector extends DefaultMySqlConnector
{
    /**
     * Create a new PDO Connection.
     *
     * @param string $dsn
     *
     * @return \PDO
     *
     * @throws \InvalidArgumentException when aws profile is not supplied
     */
    public function createConnection($dsn, array $config, array $options)
    {
        if (!Arr::has($config, 'use_iam_auth') || !Arr::get($config, 'use_iam_auth')) {
            return parent::createConnection($dsn, $config, $options);
        }

        [$username] = [
            Arr::get($config, 'username'),
        ];

        $token_provider = new RDSTokenProvider($dsn, $config);

        try {
            $password = $token_provider->getToken();

            return $this->createPdoConnection(
                $dsn,
                $username,
                $password,
                $options
            );
        } catch (\Exception $e) {
            $password = $token_provider->getToken(true);

            return $this->tryAgainIfCausedByLostConnectionOrBadToken(
                $e,
                $dsn,
                $username,
                $password,
                $options
            );
        }
    }

    /**
     * Handle an exception that occurred during connect execution.
     *
     * @param string $dsn
     * @param string $username
     * @param string $password
     * @param array  $options
     *
     * @return \PDO
     *
     * @throws \Exception
     */
    protected function tryAgainIfCausedByLostConnectionOrBadToken(\Exception $e, $dsn, $username, $password, $options)
    {
        if ($this->causedByLostConnection($e)) {
            return $this->createPdoConnection($dsn, $username, $password, $options);
        }

        if ($this->causedByLostConnectionOrBadToken($e)) {
            return $this->createPdoConnection($dsn, $username, $password, $options);
        }

        throw $e;
    }

    /**
     * Determine if the given exception was caused by a lost connection or bad auth token.
     *
     * @return bool
     */
    protected function causedByLostConnectionOrBadToken(\Exception $e)
    {
        $message = $e->getMessage();

        return Str::contains($message, [
            'server has gone away',
            'no connection to the server',
            'Lost connection',
            'is dead or not enabled',
            'Error while sending',
            'decryption failed or bad record mac',
            'server closed the connection unexpectedly',
            'SSL connection has been closed unexpectedly',
            'Error writing data to the connection',
            'Resource deadlock avoided',
            'Transaction() on null',
            'Access denied',
        ]);
    }
}
