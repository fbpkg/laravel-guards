<?php

namespace Fbpkg\Guards\Models;

use Carbon\Carbon;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Support\Str;

/**
 * Represents an active authentication session.
 *
 * Each record belongs to an authenticatable entity and stores the
 * credentials and metadata required to manage that authentication session.
 *
 * Access and refresh tokens are never stored in their raw form.
 * Only their SHA-256 hashes are persisted in the database.
 *
 * @property int                    $id
 * @property string                 $uuid
 * @property int                    $authenticatable_id
 * @property string                 $guard
 * @property string                 $access_token_hash
 * @property Carbon                 $access_expires_at
 * @property string|null            $refresh_token_hash
 * @property Carbon|null            $refresh_expires_at
 * @property string|null            $ip_address
 * @property string|null            $user_agent
 * @property Carbon                 $created_at
 * @property Carbon|null            $last_used_at
 */
class AuthSession extends Model
{
    /**
     * The table associated with the model.
     */
    protected $table = 'auth_sessions';

    /**
     * The name of the "updated at" column.
     */
    public const UPDATED_AT = null;

    /**
     * The attributes that are mass assignable.
     */
    protected $fillable = [
        'uuid',
        'authenticatable_id',
        'guard',
        'access_token_hash',
        'access_expires_at',
        'refresh_token_hash',
        'refresh_expires_at',
        'ip_address',
        'user_agent',
        'created_at',
        'last_used_at',
    ];

    /**
     * The attributes that should be cast.
     */
    protected function casts(): array
    {
        return [
            'access_expires_at' => 'datetime',
            'refresh_expires_at' => 'datetime',
            'created_at' => 'datetime',
            'last_used_at' => 'datetime',
        ];
    }

    /**
     * Register model event handlers.
     *
     * Generate a UUIDv7 for the session when one has not been provided.
     */
    protected static function booted(): void
    {
        static::creating(function (self $session) {
            $session->uuid ??= (string) Str::uuid7();
        });
    }
}
