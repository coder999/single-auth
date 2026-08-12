<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\DbSessionHandler;
use PDO;
use PHPUnit\Framework\TestCase;

final class DbSessionHandlerTest extends TestCase
{
    private PDO $pdo;
    private DbSessionHandler $handler;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE admin_sessions (
            id TEXT PRIMARY KEY,
            data TEXT NOT NULL,
            last_activity TEXT NOT NULL
        )');
        $this->handler = new DbSessionHandler($this->pdo);
    }

    public function testReadReturnsEmptyStringForUnknownId(): void
    {
        $this->assertSame('', $this->handler->read('nonexistent'));
    }

    public function testWriteThenReadRoundTrips(): void
    {
        $this->handler->write('sess1', 'admin_id|i:1;');

        $this->assertSame('admin_id|i:1;', $this->handler->read('sess1'));
    }

    public function testWriteTwiceUpdatesInPlace(): void
    {
        $this->handler->write('sess1', 'first');
        $this->handler->write('sess1', 'second');

        $this->assertSame('second', $this->handler->read('sess1'));
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM admin_sessions')->fetch()['n'];
        $this->assertSame(1, $count);
    }

    public function testDestroyRemovesTheRow(): void
    {
        $this->handler->write('sess1', 'data');

        $this->handler->destroy('sess1');

        $this->assertSame('', $this->handler->read('sess1'));
    }

    public function testGcRemovesOnlyExpiredRows(): void
    {
        $fresh = (new \DateTimeImmutable())->format('Y-m-d H:i:s');
        $stale = (new \DateTimeImmutable('-2 hours'))->format('Y-m-d H:i:s');
        $this->pdo->prepare('INSERT INTO admin_sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['fresh', 'a', $fresh]);
        $this->pdo->prepare('INSERT INTO admin_sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['stale', 'b', $stale]);

        $this->handler->gc(3600); // 1 hour max lifetime

        $this->assertSame('a', $this->handler->read('fresh'));
        $this->assertSame('', $this->handler->read('stale'));
    }
}
