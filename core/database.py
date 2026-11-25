"""SQLite storage. Every query uses ? placeholders, never string formatting.

Tables:
    meta    - key/value pairs: salt, KDF settings, wrapped Vault Key, lockout counters, settings
    entries - one row per credential. Only the id, uuid, schema version, nonce,
              ciphertext and the two timestamps are stored. Everything the user
              typed is inside the ciphertext.
"""

import os
import sqlite3
from pathlib import Path

DB_SCHEMA_VERSION = 1

# Each migration moves the database up by one version. New ones get added to the end.
MIGRATIONS = {
    1: [
        """CREATE TABLE IF NOT EXISTS meta (
               key   TEXT PRIMARY KEY,
               value BLOB NOT NULL
           )""",
        """CREATE TABLE IF NOT EXISTS entries (
               id             INTEGER PRIMARY KEY AUTOINCREMENT,
               uuid           TEXT NOT NULL UNIQUE,
               schema_version INTEGER NOT NULL,
               nonce          BLOB NOT NULL,
               ciphertext     BLOB NOT NULL,
               created_at     TEXT NOT NULL,
               updated_at     TEXT NOT NULL
           )""",
    ],
}


class Database:
    def __init__(self, path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        is_new = not self.path.exists()
        self.conn = sqlite3.connect(str(self.path))
        self.conn.row_factory = sqlite3.Row
        # Overwrite deleted data with zeros instead of leaving it in free pages.
        self.conn.execute("PRAGMA secure_delete = ON")
        if is_new and os.name != "nt":
            os.chmod(self.path, 0o600)  # owner only (on Windows the APPDATA folder is already per-user)
        self._migrate()

    # ---------- setup ----------

    def _migrate(self):
        current = self.conn.execute("PRAGMA user_version").fetchone()[0]
        if current > DB_SCHEMA_VERSION:
            raise RuntimeError("This vault was made by a newer version of PassGen Vault")
        for version in range(current + 1, DB_SCHEMA_VERSION + 1):
            with self.conn:
                for statement in MIGRATIONS[version]:
                    self.conn.execute(statement)
                # PRAGMA can't take placeholders; version is an int from our own table above.
                self.conn.execute(f"PRAGMA user_version = {int(version)}")

    def close(self):
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    # ---------- meta ----------

    def get_meta(self, key: str, default=None):
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row["value"] if row else default

    def set_meta(self, key: str, value):
        with self.conn:
            self._set_meta(key, value)

    def set_meta_many(self, values: dict):
        """Write several meta values in one transaction (all or nothing)."""
        with self.conn:
            for key, value in values.items():
                self._set_meta(key, value)

    def _set_meta(self, key, value):
        self.conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # ---------- entries ----------

    def insert_entry(self, entry_uuid, schema_version, nonce, ciphertext, created_at, updated_at) -> int:
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO entries (uuid, schema_version, nonce, ciphertext, created_at, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (entry_uuid, schema_version, nonce, ciphertext, created_at, updated_at),
            )
        return cursor.lastrowid

    def update_entry(self, entry_uuid, schema_version, nonce, ciphertext, updated_at) -> bool:
        with self.conn:
            cursor = self.conn.execute(
                "UPDATE entries SET schema_version = ?, nonce = ?, ciphertext = ?, updated_at = ? WHERE uuid = ?",
                (schema_version, nonce, ciphertext, updated_at, entry_uuid),
            )
        return cursor.rowcount == 1

    def delete_entry(self, entry_uuid) -> bool:
        with self.conn:
            cursor = self.conn.execute("DELETE FROM entries WHERE uuid = ?", (entry_uuid,))
        return cursor.rowcount == 1

    def get_entry(self, entry_uuid):
        return self.conn.execute("SELECT * FROM entries WHERE uuid = ?", (entry_uuid,)).fetchone()

    def all_entries(self) -> list:
        return self.conn.execute("SELECT * FROM entries ORDER BY id").fetchall()

    def count_entries(self) -> int:
        return self.conn.execute("SELECT COUNT(*) FROM entries").fetchone()[0]

    # ---------- backup ----------

    def backup_to(self, destination):
        """Copy the whole database with SQLite's online backup API."""
        target = sqlite3.connect(str(destination))
        try:
            self.conn.backup(target)
        finally:
            target.close()
