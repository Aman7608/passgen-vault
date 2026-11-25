"""Master password setup, unlocking, lockout and password change.

Logging in works like this: derive the KEK from the typed password and try to
unwrap the Vault Key. If the password is wrong, AES-GCM's tag check fails.
So there is no password hash stored anywhere, and the master password is never saved.
"""

import json
import logging
import time

from core import crypto
from core.config import DEFAULT_KDF_PARAMS, FREE_ATTEMPTS, LOCKOUT_BASE_SECONDS, LOCKOUT_MAX_SECONDS
from core.strength import is_acceptable_master

log = logging.getLogger(__name__)

GENERIC_ERROR = "Incorrect master password"


class AuthError(Exception):
    """Wrong password. The message is always the same generic text."""

    def __init__(self, message=GENERIC_ERROR):
        super().__init__(message)


class LockedOutError(Exception):
    def __init__(self, seconds_left: float):
        self.seconds_left = max(0.0, seconds_left)
        super().__init__(f"Too many failed attempts. Try again in {int(self.seconds_left + 0.999)} seconds.")


class WeakPasswordError(ValueError):
    pass


def lockout_delay(failed_attempts: int) -> int:
    """Seconds to wait after this many failures: 0, 0, then 30, 60, 120 ... up to 900."""
    if failed_attempts < FREE_ATTEMPTS:
        return 0
    return min(LOCKOUT_BASE_SECONDS * 2 ** (failed_attempts - FREE_ATTEMPTS), LOCKOUT_MAX_SECONDS)


class AuthManager:
    def __init__(self, db, clock=time.time, kdf_params=None):
        """clock can be swapped in tests to fake the passing of time.
        kdf_params is only used when creating a new vault or changing the password."""
        self.db = db
        self.clock = clock
        self.kdf_params = crypto.validate_kdf_params(kdf_params or DEFAULT_KDF_PARAMS)

    def is_setup(self) -> bool:
        return self.db.get_meta("wrapped_key") is not None

    # ---------- setup ----------

    def setup(self, password: str, confirm: str | None = None) -> bytes:
        """Create a brand new vault. Returns the Vault Key."""
        if self.is_setup():
            raise RuntimeError("A vault already exists")
        if confirm is not None and password != confirm:
            raise ValueError("The passwords don't match.")
        ok, _ = is_acceptable_master(password)
        if not ok:
            raise WeakPasswordError("The master password must be rated Strong, or be 12+ characters and at least Medium.")

        vault_key = crypto.generate_key()
        self._store_wrapped_key(password, vault_key, extra={
            "failed_attempts": 0,
            "locked_until": 0.0,
            "created_at": self.clock(),
        })
        log.info("New vault created")
        return vault_key

    def _store_wrapped_key(self, password, vault_key, extra=None):
        salt = crypto.generate_salt()
        kek = crypto.derive_kek(password, salt, self.kdf_params)
        nonce, wrapped = crypto.wrap_vault_key(kek, vault_key)
        values = {
            "kdf_salt": salt,
            "kdf_params": json.dumps(self.kdf_params),
            "wrap_nonce": nonce,
            "wrapped_key": wrapped,
        }
        values.update(extra or {})
        self.db.set_meta_many(values)  # one transaction, so a crash can't leave half a key

    # ---------- unlock ----------

    @property
    def failed_attempts(self) -> int:
        return int(self.db.get_meta("failed_attempts", 0))

    def lockout_remaining(self) -> float:
        return max(0.0, float(self.db.get_meta("locked_until", 0.0)) - self.clock())

    def unlock(self, password: str) -> bytes:
        """Return the Vault Key if the password is right. Raises AuthError or LockedOutError."""
        if not self.is_setup():
            raise RuntimeError("No vault has been set up yet")
        remaining = self.lockout_remaining()
        if remaining > 0:
            raise LockedOutError(remaining)
        try:
            vault_key = self._try_unwrap(password)
        except crypto.DecryptionError:
            self._record_failure()
            raise AuthError() from None
        self.db.set_meta_many({"failed_attempts": 0, "locked_until": 0.0})
        log.info("Vault unlocked")
        return vault_key

    def _try_unwrap(self, password: str) -> bytes:
        params = json.loads(self.db.get_meta("kdf_params"))
        kek = crypto.derive_kek(password, self.db.get_meta("kdf_salt"), params)
        return crypto.unwrap_vault_key(kek, self.db.get_meta("wrap_nonce"), self.db.get_meta("wrapped_key"))

    def _record_failure(self):
        failures = self.failed_attempts + 1
        delay = lockout_delay(failures)
        locked_until = self.clock() + delay if delay else 0.0
        self.db.set_meta_many({"failed_attempts": failures, "locked_until": locked_until})
        if delay:
            log.warning("Failed unlock attempt %d, locked for %d seconds", failures, delay)
        else:
            log.warning("Failed unlock attempt %d", failures)

    # ---------- change password ----------

    def change_password(self, old_password: str, new_password: str, confirm: str | None = None):
        """Re-wrap the same Vault Key under a new password. Entries don't need re-encrypting."""
        if confirm is not None and new_password != confirm:
            raise ValueError("The new passwords don't match.")
        ok, _ = is_acceptable_master(new_password)
        if not ok:
            raise WeakPasswordError("The new master password must be rated Strong, or be 12+ characters and at least Medium.")
        vault_key = self.unlock(old_password)  # same lockout rules apply here
        self._store_wrapped_key(new_password, vault_key)  # fresh salt and fresh nonce
        log.info("Master password changed")
        return vault_key
