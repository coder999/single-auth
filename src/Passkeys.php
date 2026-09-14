<?php

declare(strict_types=1);

namespace Coder999\SingleAuth;

use InvalidArgumentException;
use PDO;

final class Passkeys
{
    private PDO $pdo;
    private Auth $auth;
    private string $rpId;
    private string $rpName;
    private int $challengeTtl;

    public function __construct(PDO $pdo, Auth $auth, array $options = [])
    {
        if (empty($options['rp_id'])) {
            throw new InvalidArgumentException('Passkeys requires an rp_id option.');
        }
        $this->pdo = $pdo;
        $this->auth = $auth;
        $this->rpId = (string)$options['rp_id'];
        $this->rpName = (string)($options['rp_name'] ?? 'single-auth');
        $this->challengeTtl = (int)($options['challenge_ttl'] ?? 120);
    }

    /**
     * The WebAuthn spec's own RP ID rule: an origin is valid when it is
     * https and its host is the RP ID or a subdomain of it.
     *
     * There is deliberately no way to relax this. Local development is
     * plain HTTP and therefore cannot use passkeys at all; that is a
     * known, accepted consequence, not a bug to work around.
     */
    public function originMatchesRpId(string $origin): bool
    {
        $parts = parse_url($origin);
        if ($parts === false || ($parts['scheme'] ?? '') !== 'https') {
            return false;
        }
        $host = $parts['host'] ?? '';
        if ($host === '') {
            return false;
        }
        return $host === $this->rpId || str_ends_with($host, '.' . $this->rpId);
    }
}
