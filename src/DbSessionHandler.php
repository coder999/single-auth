<?php

declare(strict_types=1);

namespace Coder999\SingleAuth;

use PDO;
use SessionHandlerInterface;

final class DbSessionHandler implements SessionHandlerInterface
{
    public function __construct(private PDO $pdo)
    {
    }

    public function open(string $path, string $name): bool
    {
        return true;
    }

    public function close(): bool
    {
        return true;
    }

    public function read(string $id): string|false
    {
        $st = $this->pdo->prepare('SELECT data FROM sessions WHERE id = ?');
        $st->execute([$id]);
        $row = $st->fetch(PDO::FETCH_ASSOC);
        return $row === false ? '' : $row['data'];
    }

    public function write(string $id, string $data): bool
    {
        $now = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))->format('Y-m-d H:i:s');

        $exists = $this->pdo->prepare('SELECT 1 FROM sessions WHERE id = ?');
        $exists->execute([$id]);

        if ($exists->fetch(PDO::FETCH_ASSOC) !== false) {
            $st = $this->pdo->prepare('UPDATE sessions SET data = ?, last_activity = ? WHERE id = ?');
            return $st->execute([$data, $now, $id]);
        }

        $st = $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)');
        return $st->execute([$id, $data, $now]);
    }

    public function destroy(string $id): bool
    {
        $st = $this->pdo->prepare('DELETE FROM sessions WHERE id = ?');
        return $st->execute([$id]);
    }

    public function gc(int $max_lifetime): int|false
    {
        $cutoff = (new \DateTimeImmutable('now', new \DateTimeZone('UTC')))
            ->modify("-{$max_lifetime} seconds")
            ->format('Y-m-d H:i:s');
        $st = $this->pdo->prepare('DELETE FROM sessions WHERE last_activity < ?');
        $st->execute([$cutoff]);
        return $st->rowCount();
    }
}
