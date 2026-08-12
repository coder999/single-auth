<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth;

use PDO;

final class AdminAuth
{
    private PDO $pdo;
    private string $cookieName;
    private string $cookieDomain;
    private bool $cookieSecure;
    private int $loginMaxAttempts;
    private int $loginWindowSeconds;

    public function __construct(PDO $pdo, array $options = [])
    {
        $this->pdo = $pdo;
        $this->cookieName = $options['cookie_name'] ?? 'mtmd_admin';
        // '' (host-only) matches marktuttlemd's current live cookie
        // behavior — callers pass '.marktuttlemd.com' / '.nexus.local'
        // only once they're ready for cross-subdomain sharing.
        $this->cookieDomain = $options['cookie_domain'] ?? '';
        $this->cookieSecure = $options['cookie_secure'] ?? true;
        $this->loginMaxAttempts = $options['login_max_attempts'] ?? 8;
        $this->loginWindowSeconds = $options['login_window_seconds'] ?? 900;
        $this->sessionStart();
    }

    public function sessionStart(): void
    {
        if (session_status() === PHP_SESSION_ACTIVE) {
            return;
        }
        session_name($this->cookieName);
        session_set_cookie_params([
            'lifetime' => 0,
            'path'     => '/',
            'domain'   => $this->cookieDomain,
            'secure'   => $this->cookieSecure,
            'httponly' => true,
            'samesite' => 'Lax',
        ]);
        session_start();
    }

    public function currentAdmin(): ?array
    {
        $this->sessionStart();
        if (empty($_SESSION['admin_id'])) {
            return null;
        }
        $st = $this->pdo->prepare('SELECT id, username, last_login FROM admin_users WHERE id = ?');
        $st->execute([$_SESSION['admin_id']]);
        $user = $st->fetch();
        return $user === false ? null : $user;
    }

    public function requireAdmin(string $loginUrl = 'login.php'): array
    {
        $user = $this->currentAdmin();
        if ($user === null) {
            header('Location: ' . $loginUrl);
            exit;
        }
        return $user;
    }
}
