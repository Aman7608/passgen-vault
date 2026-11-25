import pytest

from core.auth import AuthError, AuthManager, LockedOutError, WeakPasswordError, lockout_delay
from core.database import Database
from tests.conftest import FAST_KDF, MASTER, OTHER_MASTER


def test_setup_and_unlock(auth):
    key = auth.setup(MASTER, MASTER)
    assert auth.unlock(MASTER) == key


def test_wrong_password_fails_with_generic_message(auth):
    auth.setup(MASTER)
    with pytest.raises(AuthError) as err:
        auth.unlock("Not-The-Password-123!")
    assert str(err.value) == "Incorrect master password"


def test_unlock_after_reopening_db(tmp_path, clock):
    path = tmp_path / "vault.db"
    db = Database(path)
    key = AuthManager(db, clock=clock, kdf_params=FAST_KDF).setup(MASTER)
    db.close()

    db = Database(path)
    auth = AuthManager(db, clock=clock)  # real default params here: unlock reads the saved ones
    with pytest.raises(AuthError):
        auth.unlock("wrong")
    assert auth.unlock(MASTER) == key
    db.close()


def test_master_password_is_not_stored(tmp_path, clock):
    path = tmp_path / "vault.db"
    db = Database(path)
    AuthManager(db, clock=clock, kdf_params=FAST_KDF).setup(MASTER)
    db.close()
    assert MASTER.encode() not in path.read_bytes()


def test_weak_master_password_refused(auth):
    for weak in ("password123", "short", "qwertyuiop12"):
        with pytest.raises(WeakPasswordError):
            auth.setup(weak)
    assert not auth.is_setup()


def test_confirm_must_match(auth):
    with pytest.raises(ValueError):
        auth.setup(MASTER, MASTER + "x")


def test_lockout_delay_values():
    assert [lockout_delay(n) for n in range(1, 9)] == [0, 0, 30, 60, 120, 240, 480, 900]
    assert lockout_delay(20) == 900


def test_lockout_escalates(auth, clock):
    auth.setup(MASTER)
    for _ in range(2):
        with pytest.raises(AuthError):
            auth.unlock("wrong")
    with pytest.raises(AuthError):
        auth.unlock("wrong")  # 3rd failure -> 30 s
    with pytest.raises(LockedOutError) as err:
        auth.unlock(MASTER)  # even the right password has to wait
    assert err.value.seconds_left == pytest.approx(30)

    clock.advance(31)
    with pytest.raises(AuthError):
        auth.unlock("wrong")  # 4th failure -> 60 s
    assert auth.lockout_remaining() == pytest.approx(60)
    clock.advance(61)
    auth.unlock(MASTER)
    assert auth.failed_attempts == 0
    assert auth.lockout_remaining() == 0


def test_lockout_survives_restart(tmp_path, clock):
    path = tmp_path / "vault.db"
    db = Database(path)
    auth = AuthManager(db, clock=clock, kdf_params=FAST_KDF)
    auth.setup(MASTER)
    for _ in range(3):
        with pytest.raises(AuthError):
            auth.unlock("wrong")
    db.close()

    clock.advance(10)
    db = Database(path)  # app restarted
    auth = AuthManager(db, clock=clock)
    assert auth.failed_attempts == 3
    assert auth.lockout_remaining() == pytest.approx(20)
    with pytest.raises(LockedOutError):
        auth.unlock(MASTER)
    clock.advance(21)
    with pytest.raises(AuthError):
        auth.unlock("wrong")  # 4th failure, the count carried over
    assert auth.lockout_remaining() == pytest.approx(60)
    db.close()


def test_lockout_is_capped_at_15_minutes(auth, clock):
    auth.setup(MASTER)
    for _ in range(12):
        clock.advance(auth.lockout_remaining() + 1)
        with pytest.raises(AuthError):
            auth.unlock("wrong")
    assert auth.lockout_remaining() == pytest.approx(900)


def test_change_password(auth, db, clock):
    from core.vault_manager import VaultManager

    key = auth.setup(MASTER)
    vault = VaultManager(db, key)
    vault.add(name="GitHub", password="gh-secret-1")
    vault.add(name="Mail", password="mail-secret-2")
    old_wrapped = db.get_meta("wrapped_key")

    auth.change_password(MASTER, OTHER_MASTER, OTHER_MASTER)
    assert db.get_meta("wrapped_key") != old_wrapped
    with pytest.raises(AuthError):
        auth.unlock(MASTER)
    new_key = auth.unlock(OTHER_MASTER)
    assert new_key == key  # same Vault Key, only re-wrapped
    names = sorted(e.name for e in VaultManager(db, new_key).list())
    assert names == ["GitHub", "Mail"]


def test_change_password_needs_correct_old_password(auth):
    auth.setup(MASTER)
    with pytest.raises(AuthError):
        auth.change_password("wrong", OTHER_MASTER)
    auth.unlock(MASTER)


def test_change_password_refuses_weak_new_password(auth):
    auth.setup(MASTER)
    with pytest.raises(WeakPasswordError):
        auth.change_password(MASTER, "password1")
    auth.unlock(MASTER)
