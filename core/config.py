"""Paths, default settings and Argon2id parameters used across the app."""

import os
from pathlib import Path

from platformdirs import user_data_dir

APP_NAME = "PassGenVault"
APP_TITLE = "PassGen Vault"

PROJECT_DIR = Path(__file__).resolve().parent.parent
ASSETS_DIR = PROJECT_DIR / "assets"
COMMON_PASSWORDS_FILE = ASSETS_DIR / "common_passwords.txt"

# Version of the JSON layout inside each encrypted entry. It is part of the AAD.
ENTRY_SCHEMA_VERSION = 1

# Argon2id settings for turning the master password into the key-encryption key.
# They are saved next to the salt in the vault, so they can be raised later
# without breaking old vaults.
DEFAULT_KDF_PARAMS = {
    "algorithm": "argon2id",
    "version": 19,
    "time_cost": 3,
    "memory_cost": 65536,  # KiB, so 64 MiB
    "parallelism": 4,
    "hash_len": 32,
}
SALT_SIZE = 16
KEY_SIZE = 32  # 256-bit keys
NONCE_SIZE = 12  # 96-bit nonce, the standard size for AES-GCM

# Login lockout: the first 3 wrong tries are free, then 30 s, doubling, capped at 15 min.
FREE_ATTEMPTS = 3
LOCKOUT_BASE_SECONDS = 30
LOCKOUT_MAX_SECONDS = 15 * 60

DEFAULT_AUTO_LOCK_SECONDS = 5 * 60
DEFAULT_CLIPBOARD_CLEAR_SECONDS = 20
OLD_PASSWORD_DAYS = 180

PRESET_CATEGORIES = ["General", "Email", "Social", "Work", "Banking", "Shopping", "Development", "Gaming"]


def data_dir() -> Path:
    """Folder that holds the vault and the log file.

    On Windows this is %APPDATA%\\PassGenVault. Setting PASSGEN_DATA_DIR
    moves it somewhere else (handy for trying the app without touching the real vault).
    """
    override = os.environ.get("PASSGEN_DATA_DIR")
    if override:
        path = Path(override)
    else:
        path = Path(user_data_dir(APP_NAME, appauthor=False, roaming=True))
    path.mkdir(parents=True, exist_ok=True)
    return path


def vault_path() -> Path:
    return data_dir() / "vault.db"


def log_path() -> Path:
    return data_dir() / "passgen_vault.log"
