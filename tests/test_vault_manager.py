import logging
from datetime import datetime, timedelta, timezone

import pytest

from core import backup
from core.auth import AuthManager
from core.database import Database
from core.logging_setup import setup_logging
from core.vault_manager import VaultLockedError, VaultManager
from tests.conftest import FAST_KDF, MASTER, OTHER_MASTER


@pytest.fixture
def vault(db, auth):
    return VaultManager(db, auth.setup(MASTER))


def test_add_get_update_delete(vault):
    entry = vault.add(name="GitHub", url="https://github.com", username="dev", password="pw-1", category="Development")
    assert vault.get(entry.uuid).username == "dev"
    updated = vault.update(entry.uuid, notes="2FA on")
    assert updated.notes == "2FA on" and updated.password == "pw-1"
    assert updated.created_at == entry.created_at
    vault.delete(entry.uuid)
    with pytest.raises(KeyError):
        vault.get(entry.uuid)
    assert vault.db.count_entries() == 0


def test_name_and_password_required(vault):
    with pytest.raises(ValueError):
        vault.add(name="  ", password="x")
    with pytest.raises(ValueError):
        vault.add(name="Mail", password="")


def test_each_entry_gets_a_uuid_and_new_nonce_on_edit(vault, db):
    entry = vault.add(name="Mail", password="pw")
    nonce_before = db.get_entry(entry.uuid)["nonce"]
    vault.update(entry.uuid, notes="x")
    assert db.get_entry(entry.uuid)["nonce"] != nonce_before
    assert len(entry.uuid) == 36


def test_search_and_filter(vault):
    vault.add(name="GitHub", url="github.com", username="coder", password="a", category="Development")
    vault.add(name="Gmail", url="mail.google.com", username="me@gmail.com", password="b", category="Email")
    vault.add(name="Bank", password="c", category="Banking", notes="joint account with mom")
    assert [e.name for e in vault.list("git")] == ["GitHub"]
    assert [e.name for e in vault.list("GOOGLE")] == ["Gmail"]
    assert [e.name for e in vault.list("joint")] == ["Bank"]
    assert [e.name for e in vault.list("", "Email")] == ["Gmail"]
    assert [e.name for e in vault.list("bank", "Banking")] == ["Bank"]
    assert vault.list("nothing-matches") == []


def test_custom_categories(vault):
    vault.add(name="Steam", password="x", category="Games Night")
    assert "Games Night" in vault.categories()
    assert vault.categories()[0] == "General"


def test_entries_decrypt_after_restart(tmp_path):
    path = tmp_path / "vault.db"
    db = Database(path)
    vault = VaultManager(db, AuthManager(db, kdf_params=FAST_KDF).setup(MASTER))
    vault.add(name="GitHub", password="Sup3r-Secret-Value!")
    db.close()
    db = Database(path)
    vault = VaultManager(db, AuthManager(db).unlock(MASTER))
    assert vault.list()[0].password == "Sup3r-Secret-Value!"
    db.close()


def test_lock_drops_key_and_entries(vault):
    vault.add(name="Mail", password="pw")
    vault.lock()
    assert vault.is_locked
    assert vault._entries == {}
    with pytest.raises(VaultLockedError):
        vault.list()


def test_dashboard_stats(db, auth):
    now = datetime(2026, 6, 1, tzinfo=timezone.utc)
    clock = {"now": now - timedelta(days=200)}
    vault = VaultManager(db, auth.setup(MASTER), now=lambda: clock["now"])
    old = vault.add(name="Old site", password="password")  # very weak and old
    clock["now"] = now
    vault.add(name="A", password="xK9#mQ2$vL7!pR4@wZ8^")
    vault.add(name="B", password="xK9#mQ2$vL7!pR4@wZ8^")  # reused
    vault.add(name="C", password="hT6&nB3*cY1%fG5(dJ0)")
    vault.update(old.uuid, notes="edited but password unchanged")

    stats = vault.stats()
    assert stats.total == 4
    assert stats.reused == 2
    assert stats.old == 1  # editing notes doesn't reset the password age
    assert stats.weak == 1
    assert stats.strong == 3
    assert sum(stats.distribution.values()) == 4
    assert len(stats.recent) == 4 and stats.recent[0].name == "Old site"
    assert 0 <= stats.security_score < 100


def test_empty_stats(vault):
    stats = vault.stats()
    assert stats.total == 0 and stats.security_score == 0


def test_logs_never_contain_secrets(tmp_path, caplog, clock):
    """Run through most features and check the log text for any secret."""
    log_file = tmp_path / "app.log"
    handler = setup_logging(log_file, level=logging.DEBUG)
    caplog.set_level(logging.DEBUG)
    secrets_used = [MASTER, OTHER_MASTER, "Wrong-Guess-555!", "LogTestSite", "log.user@example.com",
                    "Hidden-Pass-998877", "https://log-test.example", "secret note text"]
    try:
        db = Database(tmp_path / "v.db")
        auth = AuthManager(db, clock=clock, kdf_params=FAST_KDF)
        vault = VaultManager(db, auth.setup(MASTER))
        entry = vault.add(name="LogTestSite", url="https://log-test.example", username="log.user@example.com",
                          password="Hidden-Pass-998877", notes="secret note text")
        vault.update(entry.uuid, password="Hidden-Pass-998877" + "x")
        for _ in range(4):
            with pytest.raises(Exception):
                auth.unlock("Wrong-Guess-555!")
        clock.advance(10_000)
        auth.change_password(MASTER, OTHER_MASTER)
        backup.export_backup(db, tmp_path / "b.pgvault")
        backup.verify_backup(tmp_path / "b.pgvault", OTHER_MASTER)
        vault.delete(entry.uuid)
        vault.lock()
        db.close()
    finally:
        logging.getLogger().removeHandler(handler)
        handler.close()

    file_text = log_file.read_text(encoding="utf-8")
    assert "Vault unlocked" in caplog.text and "Failed unlock attempt" in file_text
    for secret in secrets_used:
        assert secret not in file_text, secret
        assert secret not in caplog.text, secret
