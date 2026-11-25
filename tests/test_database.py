from core.auth import AuthManager
from core.database import DB_SCHEMA_VERSION, Database
from core.vault_manager import VaultManager
from tests.conftest import FAST_KDF, MASTER

SECRETS = {
    "name": "SuperSecretBank",
    "url": "https://secret-bank-portal.example",
    "username": "test.user.4471@example.com",
    "password": "Tr0ub4dor&3-Horse!",
    "notes": "pin hint is pineapple",
}


def test_schema_created(db):
    assert db.conn.execute("PRAGMA user_version").fetchone()[0] == DB_SCHEMA_VERSION
    tables = {r[0] for r in db.conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"meta", "entries"} <= tables


def test_entries_table_has_only_expected_columns(db):
    columns = [r[1] for r in db.conn.execute("PRAGMA table_info(entries)")]
    assert columns == ["id", "uuid", "schema_version", "nonce", "ciphertext", "created_at", "updated_at"]


def test_raw_file_has_no_plaintext(tmp_path):
    path = tmp_path / "vault.db"
    db = Database(path)
    vault = VaultManager(db, AuthManager(db, kdf_params=FAST_KDF).setup(MASTER))
    entry = vault.add(category="Banking", **SECRETS)
    vault.update(entry.uuid, notes="changed note")
    db.close()

    raw = path.read_bytes()
    for value in list(SECRETS.values()) + [MASTER, "secret-bank-portal"]:
        assert value.encode() not in raw, value
        assert value.encode("utf-16-le") not in raw, value


def test_sql_injection_string_is_stored_literally(db):
    vault = VaultManager(db, AuthManager(db, kdf_params=FAST_KDF).setup(MASTER))
    evil = "'; DROP TABLE entries;--"
    entry = vault.add(name=evil, url=evil, username=evil, password=evil, notes=evil)
    assert db.count_entries() == 1  # the table is still there

    reopened = VaultManager(db, AuthManager(db).unlock(MASTER))
    loaded = reopened.get(entry.uuid)
    assert loaded.name == evil and loaded.password == evil
    assert reopened.list("drop table")[0].uuid == entry.uuid


def test_meta_round_trip(db):
    db.set_meta("a", b"\x00\x01")
    db.set_meta_many({"a": b"\x02", "b": 5})
    assert db.get_meta("a") == b"\x02"
    assert db.get_meta("b") == 5
    assert db.get_meta("missing", "default") == "default"


def test_reopen_keeps_data(tmp_path):
    path = tmp_path / "v.db"
    db = Database(path)
    db.insert_entry("u1", 1, b"n" * 12, b"ct", "t1", "t1")
    db.close()
    db = Database(path)
    assert db.get_entry("u1")["ciphertext"] == b"ct"
    assert db.delete_entry("u1") is True
    assert db.count_entries() == 0
    db.close()
