"""App settings (auto-lock and clipboard timers). Saved as plain JSON in the meta table.
They are not secret, and they need to be readable before the vault is unlocked."""

import json

from core.config import DEFAULT_AUTO_LOCK_SECONDS, DEFAULT_CLIPBOARD_CLEAR_SECONDS

AUTO_LOCK_CHOICES = [60, 120, 300, 600, 900, 1800]  # seconds
CLIPBOARD_CHOICES = [10, 20, 30, 45, 60, 90]  # seconds

DEFAULTS = {
    "auto_lock_seconds": DEFAULT_AUTO_LOCK_SECONDS,
    "clipboard_clear_seconds": DEFAULT_CLIPBOARD_CLEAR_SECONDS,
}


def load_settings(db) -> dict:
    settings = dict(DEFAULTS)
    raw = db.get_meta("settings")
    if raw:
        try:
            saved = json.loads(raw)
        except (TypeError, ValueError):
            saved = {}
        if saved.get("auto_lock_seconds") in AUTO_LOCK_CHOICES:
            settings["auto_lock_seconds"] = saved["auto_lock_seconds"]
        if saved.get("clipboard_clear_seconds") in CLIPBOARD_CHOICES:
            settings["clipboard_clear_seconds"] = saved["clipboard_clear_seconds"]
    return settings


def save_settings(db, auto_lock_seconds: int, clipboard_clear_seconds: int) -> dict:
    if auto_lock_seconds not in AUTO_LOCK_CHOICES:
        raise ValueError("Invalid auto-lock time")
    if clipboard_clear_seconds not in CLIPBOARD_CHOICES:
        raise ValueError("Invalid clipboard clear time")
    settings = {"auto_lock_seconds": auto_lock_seconds, "clipboard_clear_seconds": clipboard_clear_seconds}
    db.set_meta("settings", json.dumps(settings))
    return settings
