<?php

/*
 * This file is part of jwt-auth.
 *
 * (c) Sean Tymon <tymon148@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Tymon\JWTAuth;

use Tymon\JWTAuth\Providers\Storage\StorageInterface;
use Config;

class Blacklist
{
    /**
     * @var \Tymon\JWTAuth\Providers\Storage\StorageInterface
     */
    protected $storage;
    protected $files;
    /**
     * Number of minutes from issue date in which a JWT can be refreshed.
     *
     * @var int
     */
    protected $refreshTTL = 20160;

    /**
     * @param \Tymon\JWTAuth\Providers\Storage\StorageInterface  $storage
     */
    public function __construct(StorageInterface $storage)
    {
        $this->storage = $storage;
    }

    /**
     * Add the token (jti claim) to the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function add(Payload $payload)
    {
        $exp = Utils::timestamp($payload['exp']);
        $refreshExp = Utils::timestamp($payload['iat'])->addMinutes($this->refreshTTL);

        // there is no need to add the token to the blacklist
        // if the token has already expired AND the refresh_ttl
        // has gone by
        if ($exp->isPast() && $refreshExp->isPast()) {
            return false;
        }

        /*
         * blacklist waitlisting keeps getting extended each time we access within 60 seconds
         * this happens because we keep replacing the blacklisting entry here each time we refresh the token
         * currently once 60 seconds passes without it being used it is blacklisted properly with no waitlisting
         * the below code is used to prevent this behavior
         */
        $parts = array_slice(str_split($hash = sha1($payload['jti']), 2), 0, 2);
        $cache_file = config('cache.stores.file.path').'/'.implode('/', $parts).'/'.$hash;
        if(file_exists($cache_file)) {
            $cache_file_timestamp = filemtime($cache_file);
            if(time() - $cache_file_timestamp < 60) {
                return true;
            }
        }
        // Set the cache entry's lifetime to be equal to the amount
        // of refreshable time it has remaining (which is the larger
        // of `exp` and `iat+refresh_ttl`), rounded up a minute
        $cacheLifetime = $exp->max($refreshExp)->addMinute()->diffInMinutes();

        $this->storage->add($payload['jti'], [], $cacheLifetime);

        return true;
    }

    /**
     * Determine whether the token has been blacklisted.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function has(Payload $payload)
    {
        $parts = array_slice(str_split($hash = sha1($payload['jti']), 2), 0, 2);
        $cache_file = config('cache.stores.file.path').'/'.implode('/', $parts).'/'.$hash;
        if(file_exists($cache_file)) {
            $cache_file_timestamp = filemtime($cache_file);
            $exp = Utils::timestamp($cache_file_timestamp)->addMinutes(1);
            if ($exp->isPast()) {
                return $this->storage->has($payload['jti']);
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    /**
     * Remove the token (jti claim) from the blacklist.
     *
     * @param  \Tymon\JWTAuth\Payload  $payload
     * @return bool
     */
    public function remove(Payload $payload)
    {
        return $this->storage->destroy($payload['jti']);
    }

    /**
     * Remove all tokens from the blacklist.
     *
     * @return bool
     */
    public function clear()
    {
        $this->storage->flush();

        return true;
    }

    /**
     * Set the refresh time limit.
     *
     * @param  int
     *
     * @return $this
     */
    public function setRefreshTTL($ttl)
    {
        $this->refreshTTL = (int) $ttl;

        return $this;
    }
}
