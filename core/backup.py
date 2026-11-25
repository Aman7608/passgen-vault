"""Encrypted backup and restore.

The vault file is already encrypted, so a backup is just a consistent copy made
with SQLite's backup API. Restoring checks the backup's master password first,
and keeps the current vault file next to it instead of deleting it.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime
from pathlib import Path

from core import crypto
from core.auth import AuthError

log = logging.getLogger(__name__)

REQUIRED_META = ("kdf_salt", "kdf_params", "wrap_nonce", "wrapped_key")


class BackupError(Exception):
    pass


def _same_file(a: Path, b: Path) -> bool:
    try:
        return a.resolve() == b.resolve() or (a.exists() and b.exists() and os.path.samefile(a, b))
    except OSError:
        return False


def export_backup(db, destination) -> Path:
    destination = Path(destination)
    if _same_file(destination, db.path):
        raise BackupError("Choose a different file than the live vault.")
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp = destination.with_name(destination.name + ".tmp")
    if temp.exists():
        temp.unlink()
    db.backup_to(temp)
    os.replace(temp, destination)  # only show the finished file, never a half-written one
    log.info("Backup exported")
    return destination


def _open_read_only(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def verify_backup(backup_path, password: str) -> int:
    """Check that the file is a PassGen vault, the password opens it, and every entry decrypts.

    Returns how many entries it holds. Raises BackupError or AuthError.
    """
    backup_path = Path(backup_path)
    if not backup_path.is_file():
        raise BackupError("Backup file not found.")
    try:
        conn = _open_read_only(backup_path)
    except sqlite3.Error:
        raise BackupError("This file is not a PassGen Vault backup.") from None
    try:
        try:
            if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise BackupError("The backup file is damaged.")
            meta = {row["key"]: row["value"] for row in conn.execute("SELECT key, value FROM meta")}
            rows = conn.execute("SELECT uuid, schema_version, nonce, ciphertext FROM entries").fetchall()
        except sqlite3.Error:
            raise BackupError("This file is not a PassGen Vault backup.") from None
        if any(key not in meta for key in REQUIRED_META):
            raise BackupError("This file is not a PassGen Vault backup.")

        try:
            params = json.loads(meta["kdf_params"])
            kek = crypto.derive_kek(password, meta["kdf_salt"], params)
        except (ValueError, TypeError):
            raise BackupError("The backup has invalid key settings.") from None
        try:
            vault_key = crypto.unwrap_vault_key(kek, meta["wrap_nonce"], meta["wrapped_key"])
        except crypto.DecryptionError:
            raise AuthError() from None
        try:
            for row in rows:
                crypto.decrypt_entry(vault_key, row["uuid"], row["nonce"], row["ciphertext"], row["schema_version"])
        except crypto.DecryptionError:
            raise BackupError("Some entries in the backup are damaged.") from None
        return len(rows)
    finally:
        conn.close()


def restore_backup(backup_path, password: str, vault_path) -> Path | None:
    """Replace the vault with the backup. The live database must be closed first.

    Returns where the previous vault was kept (or None if there wasn't one).
    """
    backup_path, vault_path = Path(backup_path), Path(vault_path)
    if _same_file(backup_path, vault_path):
        raise BackupError("That file is the current vault.")
    verify_backup(backup_path, password)

    temp = vault_path.with_name(vault_path.name + ".restore-tmp")
    if temp.exists():
        temp.unlink()
    source = _open_read_only(backup_path)
    target = sqlite3.connect(str(temp))
    try:
        source.backup(target)
        with target:
            # The password was just proven, so start the restored vault with a clean lockout.
            target.execute("UPDATE meta SET value = 0 WHERE key IN ('failed_attempts', 'locked_until')")
    finally:
        source.close()
        target.close()

    previous = None
    if vault_path.exists():
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        previous = vault_path.with_name(f"vault-before-restore-{stamp}.db")
        os.replace(vault_path, previous)
    os.replace(temp, vault_path)
    log.info("Vault restored from backup")
    return previous
