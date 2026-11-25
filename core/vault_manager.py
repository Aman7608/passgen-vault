"""Add, edit, delete and search credentials, and work out dashboard stats.

All entries are decrypted into memory once after unlock. Search, filters and
stats run on that in-memory copy, because the database only holds ciphertext.
"""

import logging
import uuid
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone

from core import crypto
from core.config import ENTRY_SCHEMA_VERSION, OLD_PASSWORD_DAYS, PRESET_CATEGORIES
from core.strength import LEVELS, check, user_inputs_from_entry

log = logging.getLogger(__name__)

# The fields that get encrypted together as one JSON blob.
SECRET_FIELDS = ("name", "url", "username", "password", "category", "notes", "password_changed_at")


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class Entry:
    uuid: str
    name: str
    url: str = ""
    username: str = ""
    password: str = ""
    category: str = "General"
    notes: str = ""
    password_changed_at: str = ""  # inside the ciphertext, so the "old password" stat can't be faked
    created_at: str = ""  # stored in plaintext (see SECURITY.md)
    updated_at: str = ""
    id: int | None = None


@dataclass
class DashboardStats:
    total: int = 0
    strong: int = 0
    weak: int = 0
    reused: int = 0
    old: int = 0
    distribution: dict = field(default_factory=lambda: {level: 0 for level in LEVELS})
    recent: list = field(default_factory=list)
    security_score: int = 0


class VaultLockedError(Exception):
    pass


class VaultManager:
    def __init__(self, db, vault_key: bytes, now=utc_now):
        self.db = db
        self._key = vault_key
        self.now = now
        self._entries: dict[str, Entry] = {}
        self._strength_cache: dict = {}
        self._load()

    # ---------- helpers ----------

    def _require_key(self) -> bytes:
        if self._key is None:
            raise VaultLockedError("The vault is locked")
        return self._key

    def _load(self):
        key = self._require_key()
        for row in self.db.all_entries():
            fields = crypto.decrypt_entry(key, row["uuid"], row["nonce"], row["ciphertext"], row["schema_version"])
            data = {name: str(fields.get(name, "")) for name in SECRET_FIELDS}
            self._entries[row["uuid"]] = Entry(
                uuid=row["uuid"], id=row["id"], created_at=row["created_at"], updated_at=row["updated_at"], **data
            )

    @staticmethod
    def _clean(fields: dict) -> dict:
        clean = {}
        for name in ("name", "url", "username", "password", "category", "notes"):
            value = fields.get(name, "")
            clean[name] = "" if value is None else str(value)
        clean["name"] = clean["name"].strip()
        clean["url"] = clean["url"].strip()
        clean["category"] = clean["category"].strip() or "General"
        if not clean["name"]:
            raise ValueError("Please enter a name for this entry.")
        if not clean["password"]:
            raise ValueError("Please enter a password.")
        return clean

    def _encrypt(self, entry: Entry):
        fields = {name: getattr(entry, name) for name in SECRET_FIELDS}
        return crypto.encrypt_entry(self._require_key(), entry.uuid, fields, ENTRY_SCHEMA_VERSION)

    # ---------- CRUD ----------

    def add(self, **fields) -> Entry:
        self._require_key()
        clean = self._clean(fields)
        stamp = self.now().isoformat(timespec="seconds")
        entry = Entry(uuid=str(uuid.uuid4()), password_changed_at=stamp, created_at=stamp, updated_at=stamp, **clean)
        nonce, ciphertext = self._encrypt(entry)
        entry.id = self.db.insert_entry(entry.uuid, ENTRY_SCHEMA_VERSION, nonce, ciphertext, stamp, stamp)
        self._entries[entry.uuid] = entry
        log.info("Entry added (id=%s)", entry.id)
        return entry

    def update(self, entry_uuid: str, **fields) -> Entry:
        self._require_key()
        old = self.get(entry_uuid)
        merged = {name: fields.get(name, getattr(old, name)) for name in ("name", "url", "username", "password", "category", "notes")}
        clean = self._clean(merged)
        stamp = self.now().isoformat(timespec="seconds")
        changed_at = stamp if clean["password"] != old.password else old.password_changed_at
        entry = Entry(uuid=old.uuid, id=old.id, created_at=old.created_at, updated_at=stamp,
                      password_changed_at=changed_at, **clean)
        nonce, ciphertext = self._encrypt(entry)  # new nonce on every write
        if not self.db.update_entry(entry.uuid, ENTRY_SCHEMA_VERSION, nonce, ciphertext, stamp):
            raise KeyError("Entry not found")
        self._entries[entry.uuid] = entry
        log.info("Entry updated (id=%s)", entry.id)
        return entry

    def delete(self, entry_uuid: str):
        self._require_key()
        entry = self.get(entry_uuid)
        self.db.delete_entry(entry_uuid)
        del self._entries[entry_uuid]
        log.info("Entry deleted (id=%s)", entry.id)

    def get(self, entry_uuid: str) -> Entry:
        self._require_key()
        try:
            return self._entries[entry_uuid]
        except KeyError:
            raise KeyError("Entry not found") from None

    def list(self, query: str = "", category: str | None = None) -> list:
        """Entries sorted by name. query searches name, URL, username, category and notes."""
        self._require_key()
        query = query.strip().lower()
        results = []
        for entry in self._entries.values():
            if category and entry.category != category:
                continue
            if query:
                haystack = " ".join((entry.name, entry.url, entry.username, entry.category, entry.notes)).lower()
                if query not in haystack:
                    continue
            results.append(entry)
        return sorted(results, key=lambda e: (e.name.lower(), e.created_at))

    def categories(self) -> list:
        """Preset categories plus any custom ones in use."""
        custom = sorted({e.category for e in self._entries.values()} - set(PRESET_CATEGORIES), key=str.lower)
        return PRESET_CATEGORIES + custom

    # ---------- strength and stats ----------

    def strength_of(self, entry: Entry):
        cache_key = (entry.uuid, entry.updated_at, entry.password)
        result = self._strength_cache.get(cache_key)
        if result is None:
            result = check(entry.password, user_inputs_from_entry(entry.name, entry.url, entry.username))
            self._strength_cache[cache_key] = result
        return result

    def stats(self) -> DashboardStats:
        self._require_key()
        entries = list(self._entries.values())
        stats = DashboardStats(total=len(entries))
        if not entries:
            return stats

        password_counts = Counter(e.password for e in entries)
        cutoff = self.now() - timedelta(days=OLD_PASSWORD_DAYS)
        scores = []
        for entry in entries:
            result = self.strength_of(entry)
            stats.distribution[result.level] += 1
            scores.append(result.score)
            if password_counts[entry.password] > 1:
                stats.reused += 1
            changed = entry.password_changed_at or entry.created_at
            try:
                if datetime.fromisoformat(changed) < cutoff:
                    stats.old += 1
            except ValueError:
                pass
        stats.strong = stats.distribution["Strong"] + stats.distribution["Very Strong"]
        stats.weak = stats.distribution["Weak"] + stats.distribution["Very Weak"]
        stats.recent = sorted(entries, key=lambda e: e.updated_at, reverse=True)[:5]

        # Security score: average password strength, minus up to 25 points for
        # reused passwords and up to 15 for old ones.
        average = sum(scores) / len(scores)
        penalty = 25 * stats.reused / stats.total + 15 * stats.old / stats.total
        stats.security_score = max(0, min(100, round(average - penalty)))
        return stats

    # ---------- lock ----------

    def lock(self):
        """Drop the Vault Key and every decrypted entry.

        Python can't promise the old strings are wiped from memory (see SECURITY.md),
        but after this nothing in the app points to them any more.
        """
        self._key = None
        self._entries.clear()
        self._strength_cache.clear()
        log.info("Vault locked")

    @property
    def is_locked(self) -> bool:
        return self._key is None


def entry_to_dict(entry: Entry) -> dict:
    return asdict(entry)
