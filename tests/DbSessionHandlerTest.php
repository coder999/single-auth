<?php

declare(strict_types=1);

namespace Mtmd\SingleAuth\Tests;

use Mtmd\SingleAuth\DbSessionHandler;
use PDO;
use PHPUnit\Framework\TestCase;
use DateTimeImmutable;
use DateTimeZone;

final class DbSessionHandlerTest extends TestCase
{
    private PDO $pdo;
    private DbSessionHandler $handler;

    protected function setUp(): void
    {
        $this->pdo = new PDO('sqlite::memory:');
        $this->pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        $this->pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
        $this->pdo->exec('CREATE TABLE sessions (
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
        $this->handler->write('sess1', 'user_id|i:1;');

        $this->assertSame('user_id|i:1;', $this->handler->read('sess1'));
    }

    public function testWriteTwiceUpdatesInPlace(): void
    {
        $this->handler->write('sess1', 'first');
        $this->handler->write('sess1', 'second');

        $this->assertSame('second', $this->handler->read('sess1'));
        $count = (int)$this->pdo->query('SELECT COUNT(*) AS n FROM sessions')->fetch()['n'];
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
        $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['fresh', 'a', $fresh]);
        $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
            ->execute(['stale', 'b', $stale]);

        $this->handler->gc(3600); // 1 hour max lifetime

        $this->assertSame('a', $this->handler->read('fresh'));
        $this->assertSame('', $this->handler->read('stale'));
    }

    public function testTimestampsAreAnchoredToUtcRegardlessOfAmbientTimezone(): void
    {
        date_default_timezone_set('America/Denver');
        try {
            // write() must store last_activity in UTC even though the
            // process-wide default timezone is Denver.
            $this->handler->write('denver-sess', 'data');

            $row = $this->pdo->query("SELECT last_activity FROM sessions WHERE id = 'denver-sess'")
                ->fetch(PDO::FETCH_ASSOC);
            $stored = new DateTimeImmutable($row['last_activity'], new DateTimeZone('UTC'));
            $trueUtcNow = new DateTimeImmutable('now', new DateTimeZone('UTC'));
            $this->assertLessThan(
                5,
                abs($trueUtcNow->getTimestamp() - $stored->getTimestamp()),
                'write() must anchor last_activity to UTC, not the ambient default timezone'
            );

            // A session that is genuinely stale in UTC terms (2 hours old)
            // must still be collected by gc(3600) even though gc() is
            // invoked while the ambient timezone is Denver.
            $staleUtc = (new DateTimeImmutable('-2 hours', new DateTimeZone('UTC')))->format('Y-m-d H:i:s');
            $this->pdo->prepare('INSERT INTO sessions (id, data, last_activity) VALUES (?, ?, ?)')
                ->execute(['denver-stale', 'x', $staleUtc]);

            $this->handler->gc(3600); // 1 hour max lifetime

            $this->assertSame(
                '',
                $this->handler->read('denver-stale'),
                'gc() cutoff must be computed in UTC so genuinely stale sessions are collected under any ambient timezone'
            );
            $this->assertSame(
                'data',
                $this->handler->read('denver-sess'),
                'a freshly written session must survive gc() regardless of ambient timezone'
            );
        } finally {
            date_default_timezone_set('UTC');
        }
    }
}
