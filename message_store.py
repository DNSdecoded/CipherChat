# -*- coding: utf-8 -*-
"""
Durable queue for messages addressed to offline recipients.

Without this the server drops anything sent to a user who is not currently
connected, which makes asynchronous conversation impossible - the entire point
of a messenger.

The server never sees plaintext. Queued rows hold the same sealed
`ratchet_message` envelope that would have been relayed live, so parking it on
disk grants the operator nothing they did not already have in transit.

Uses stdlib sqlite3: durable, transactional, and no new dependency.
"""

import json
import os
import sqlite3
import threading
import time


DEFAULT_DB_PATH = 'cipherchat_server.db'
DEFAULT_TTL_SECONDS = 7 * 24 * 60 * 60      # 7 days
DEFAULT_MAX_PER_RECIPIENT = 500


class MessageStore:
    """
    SQLite-backed offline message queue.

    Thread-safe: the server runs a thread per client, so every statement goes
    through one connection guarded by a lock. At this scale that simplicity is
    worth more than per-thread connections.
    """

    def __init__(self, path: str = DEFAULT_DB_PATH,
                 ttl_seconds: int = DEFAULT_TTL_SECONDS,
                 max_per_recipient: int = DEFAULT_MAX_PER_RECIPIENT):
        """
        Args:
            path: SQLite file. ':memory:' is supported for tests.
            ttl_seconds: Age past which a queued message is discarded
            max_per_recipient: Depth cap, so one recipient cannot fill the disk
        """
        self.path = path
        self.ttl_seconds = ttl_seconds
        self.max_per_recipient = max_per_recipient
        self._lock = threading.Lock()

        # check_same_thread=False is safe here because every access is
        # serialized by self._lock.
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._create_schema()

    def _create_schema(self):
        with self._lock:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS queued (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    recipient   TEXT NOT NULL,
                    sender      TEXT NOT NULL,
                    payload     TEXT NOT NULL,
                    created_at  REAL NOT NULL
                )
            """)
            # Delivery reads by recipient in id order; without this every drain
            # is a full scan.
            self._conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queued_recipient "
                "ON queued (recipient, id)"
            )
            self._conn.commit()

    def enqueue(self, recipient: str, sender: str, payload: dict) -> bool:
        """
        Store one message for later delivery.

        Args:
            recipient: Username the message is addressed to
            sender: Authenticated sender username
            payload: The full ratchet_message dict to replay on reconnect

        Returns:
            True if stored, False if the recipient's queue is full
        """
        with self._lock:
            depth = self._conn.execute(
                "SELECT COUNT(*) FROM queued WHERE recipient = ?", (recipient,)
            ).fetchone()[0]

            if depth >= self.max_per_recipient:
                return False

            self._conn.execute(
                "INSERT INTO queued (recipient, sender, payload, created_at) "
                "VALUES (?, ?, ?, ?)",
                (recipient, sender, json.dumps(payload), time.time())
            )
            self._conn.commit()
            return True

    def drain(self, recipient: str) -> list:
        """
        Return everything queued for a recipient and delete it, oldest first.

        Read and delete happen under one lock, so two concurrent logins cannot
        both receive the same message.

        Expired rows are dropped rather than delivered.

        Args:
            recipient: Username reconnecting

        Returns:
            List of payload dicts in original send order
        """
        cutoff = time.time() - self.ttl_seconds

        with self._lock:
            rows = self._conn.execute(
                "SELECT id, payload, created_at FROM queued "
                "WHERE recipient = ? ORDER BY id ASC",
                (recipient,)
            ).fetchall()

            if not rows:
                return []

            self._conn.execute("DELETE FROM queued WHERE recipient = ?", (recipient,))
            self._conn.commit()

        messages = []
        for row in rows:
            if row['created_at'] < cutoff:
                continue  # expired in the queue; drop silently
            try:
                messages.append(json.loads(row['payload']))
            except json.JSONDecodeError:
                continue  # corrupt row, not worth failing a login over
        return messages

    def purge_expired(self) -> int:
        """
        Delete messages older than the TTL.

        Returns:
            Number of rows removed
        """
        cutoff = time.time() - self.ttl_seconds
        with self._lock:
            cursor = self._conn.execute(
                "DELETE FROM queued WHERE created_at < ?", (cutoff,)
            )
            self._conn.commit()
            return cursor.rowcount

    def queue_depth(self, recipient: str = None) -> int:
        """
        Count queued messages, for one recipient or in total.

        Args:
            recipient: Username, or None for the whole queue

        Returns:
            Number of queued messages
        """
        with self._lock:
            if recipient is None:
                return self._conn.execute("SELECT COUNT(*) FROM queued").fetchone()[0]
            return self._conn.execute(
                "SELECT COUNT(*) FROM queued WHERE recipient = ?", (recipient,)
            ).fetchone()[0]

    def close(self):
        """Close the database connection."""
        with self._lock:
            self._conn.close()


if __name__ == "__main__":
    print("Testing MessageStore...")

    store = MessageStore(path=':memory:')

    # Nothing queued yet
    assert store.drain('alice') == []
    assert store.queue_depth() == 0
    print("[OK] Empty queue drains empty")

    # FIFO ordering is preserved
    for i in range(5):
        assert store.enqueue('alice', 'bob', {'seq': i, 'type': 'ratchet_message'})
    assert store.queue_depth('alice') == 5
    drained = store.drain('alice')
    assert [m['seq'] for m in drained] == [0, 1, 2, 3, 4], drained
    print("[OK] Messages drain in send order")

    # Draining removes them
    assert store.drain('alice') == []
    assert store.queue_depth() == 0
    print("[OK] Drain is destructive")

    # Recipients are isolated
    store.enqueue('alice', 'bob', {'seq': 'a'})
    store.enqueue('carol', 'bob', {'seq': 'c'})
    assert [m['seq'] for m in store.drain('alice')] == ['a']
    assert store.queue_depth('carol') == 1
    print("[OK] Queues are per-recipient")
    store.drain('carol')

    # Depth cap protects the disk
    capped = MessageStore(path=':memory:', max_per_recipient=3)
    assert capped.enqueue('dave', 'eve', {'n': 1})
    assert capped.enqueue('dave', 'eve', {'n': 2})
    assert capped.enqueue('dave', 'eve', {'n': 3})
    assert not capped.enqueue('dave', 'eve', {'n': 4}), "depth cap not enforced"
    assert capped.queue_depth('dave') == 3
    print("[OK] Per-recipient depth cap enforced")

    # Expired messages are neither delivered nor retained
    expiring = MessageStore(path=':memory:', ttl_seconds=0)
    expiring.enqueue('frank', 'gina', {'stale': True})
    time.sleep(0.01)
    assert expiring.drain('frank') == [], "expired message was delivered"
    print("[OK] Expired messages are not delivered")

    expiring2 = MessageStore(path=':memory:', ttl_seconds=0)
    expiring2.enqueue('frank', 'gina', {'stale': True})
    time.sleep(0.01)
    assert expiring2.purge_expired() == 1
    assert expiring2.queue_depth() == 0
    print("[OK] purge_expired removes stale rows")

    # Durability across reopen
    import tempfile
    import shutil
    workdir = tempfile.mkdtemp()
    try:
        db = os.path.join(workdir, 'q.db')
        first = MessageStore(path=db)
        first.enqueue('henry', 'iris', {'persisted': True})
        first.close()

        second = MessageStore(path=db)
        out = second.drain('henry')
        assert len(out) == 1 and out[0]['persisted'] is True, out
        second.close()
        print("[OK] Queue survives a server restart")
    finally:
        shutil.rmtree(workdir, ignore_errors=True)

    print("\n[PASS] All MessageStore tests passed!")
