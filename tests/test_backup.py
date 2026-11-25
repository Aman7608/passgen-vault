import pytest

from core import backup
from core.auth import AuthError, AuthManager
from core.clipboard import ClipboardGuard
from core.database import Database
from core.vault_manager import VaultManager
from tests.conftest import FAST_KDF, MASTER, OTHER_MASTER


def make_vault(path, password, *names):
    db = Database(path)
    vault = VaultManager(db, AuthManager(db, kdf_params=FAST_KDF).setup(password))
    for name in names:
        vault.add(name=name, password=f"pw-for-{name}")
    return db, vault


def test_backup_and_restore_round_trip(tmp_path):
    db, _ = make_vault(tmp_path / "vault.db", MASTER, "GitHub", "Mail")
    backup_file = backup.export_backup(db, tmp_path / "backups" / "my.pgvault")
    assert backup.verify_backup(backup_file, MASTER) == 2
    db.close()

    # The user later has a different vault, then restores the old backup.
    live = tmp_path / "live" / "vault.db"
    db2, _ = make_vault(live, OTHER_MASTER, "Only-in-new")
    db2.close()
    previous = backup.restore_backup(backup_file, MASTER, live)

    assert previous is not None and previous.exists()  # the old vault was kept
    db3 = Database(live)
    vault = VaultManager(db3, AuthManager(db3).unlock(MASTER))
    assert sorted(e.name for e in vault.list()) == ["GitHub", "Mail"]
    db3.close()

    db4 = Database(previous)
    assert [e.name for e in VaultManager(db4, AuthManager(db4).unlock(OTHER_MASTER)).list()] == ["Only-in-new"]
    db4.close()


def test_restore_with_wrong_password_is_refused(tmp_path):
    db, _ = make_vault(tmp_path / "a.db", MASTER, "GitHub")
    backup_file = backup.export_backup(db, tmp_path / "b.pgvault")
    db.close()
    live = tmp_path / "live.db"
    db2, _ = make_vault(live, OTHER_MASTER, "Keep me")
    db2.close()
    before = live.read_bytes()

    with pytest.raises(AuthError):
        backup.restore_backup(backup_file, "Wrong-Password-1!", live)
    assert live.read_bytes() == before  # nothing changed


def test_not_a_backup_file(tmp_path):
    junk = tmp_path / "junk.pgvault"
    junk.write_bytes(b"hello, this is not sqlite" * 50)
    with pytest.raises(backup.BackupError):
        backup.verify_backup(junk, MASTER)
    with pytest.raises(backup.BackupError):
        backup.verify_backup(tmp_path / "missing.pgvault", MASTER)


def test_cannot_back_up_over_live_vault(tmp_path):
    db, _ = make_vault(tmp_path / "vault.db", MASTER)
    with pytest.raises(backup.BackupError):
        backup.export_backup(db, tmp_path / "vault.db")
    db.close()


def test_backup_file_has_no_plaintext(tmp_path):
    db, vault = make_vault(tmp_path / "vault.db", MASTER)
    vault.add(name="PlainTextCheck", username="someone@example.com", password="NoLeak-4455!")
    path = backup.export_backup(db, tmp_path / "b.pgvault")
    db.close()
    raw = path.read_bytes()
    for value in (b"PlainTextCheck", b"someone@example.com", b"NoLeak-4455!"):
        assert value not in raw


# ---- clipboard auto-clear (lives here because it is also about not leaving secrets around) ----

class FakeClipboard:
    def __init__(self):
        self.text = ""
        self.timers = {}
        self.next_id = 0

    def get(self):
        return self.text

    def set(self, value):
        self.text = value

    def schedule(self, ms, func):
        self.next_id += 1
        self.timers[self.next_id] = (ms, func)
        return self.next_id

    def cancel(self, handle):
        self.timers.pop(handle, None)

    def fire_all(self):
        for _, func in list(self.timers.values()):
            func()
        self.timers.clear()


def make_guard(seconds=20):
    fake = FakeClipboard()
    return fake, ClipboardGuard(fake.get, fake.set, fake.schedule, fake.cancel, seconds)


def test_clipboard_clears_after_timeout():
    fake, guard = make_guard()
    guard.copy("secret-1")
    assert fake.text == "secret-1"
    assert list(fake.timers.values())[0][0] == 20_000
    fake.fire_all()
    assert fake.text == ""


def test_clipboard_not_cleared_if_user_copied_something_else():
    fake, guard = make_guard()
    guard.copy("secret-1")
    fake.text = "user copied this"
    fake.fire_all()
    assert fake.text == "user copied this"


def test_new_copy_replaces_old_timer():
    fake, guard = make_guard()
    guard.copy("a")
    guard.copy("b")
    assert len(fake.timers) == 1
    assert guard.clear_if_ours() and fake.text == ""
