"""All the cryptography: Argon2id key derivation, key wrapping and entry encryption.

Key hierarchy (envelope encryption):

    master password --Argon2id(salt)--> KEK --AES-GCM wrap--> Vault Key --AES-GCM--> entries

The master password and the KEK are never stored. Only the salt, the Argon2id
settings and the wrapped Vault Key are saved.
"""

import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.config import DEFAULT_KDF_PARAMS, KEY_SIZE, NONCE_SIZE, SALT_SIZE

# Extra data bound to the wrapped Vault Key, so that blob can't be used as an entry.
VAULT_KEY_AAD = b"passgen-vault:vault-key:v1"

# Limits for KDF settings read from a vault file. A tampered file could try to set
# a huge memory cost (to hang the app) or a tiny one, so anything odd is refused.
_KDF_LIMITS = {
    "time_cost": (1, 20),
    "memory_cost": (8 * 1024, 2 * 1024 * 1024),
    "parallelism": (1, 16),
    "hash_len": (32, 32),
}


class DecryptionError(Exception):
    """Raised when data can't be decrypted: wrong key, or the data was changed."""


def generate_key() -> bytes:
    return os.urandom(KEY_SIZE)


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def validate_kdf_params(params: dict) -> dict:
    """Check KDF settings (for example ones loaded from disk) and return a clean copy."""
    if params.get("algorithm") != "argon2id":
        raise ValueError("Unsupported key derivation algorithm")
    clean = {"algorithm": "argon2id", "version": 19}
    for name, (low, high) in _KDF_LIMITS.items():
        value = params.get(name)
        if not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"KDF setting {name} is out of range")
        clean[name] = value
    return clean


def derive_kek(password: str, salt: bytes, params: dict | None = None) -> bytes:
    """Turn the master password into a 256-bit key-encryption key with Argon2id."""
    if len(salt) != SALT_SIZE:
        raise ValueError("Salt must be 16 bytes")
    params = validate_kdf_params(params or DEFAULT_KDF_PARAMS)
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params["hash_len"],
        type=Type.ID,
    )


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """AES-256-GCM encrypt. A fresh random 12-byte nonce is made on every call.

    Returns (nonce, ciphertext). The ciphertext includes the 16-byte GCM tag.
    """
    if len(key) != KEY_SIZE:
        raise ValueError("Key must be 32 bytes")
    nonce = os.urandom(NONCE_SIZE)
    return nonce, AESGCM(key).encrypt(nonce, plaintext, aad)


def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    """AES-256-GCM decrypt. Raises DecryptionError if anything was changed or the key is wrong."""
    if len(key) != KEY_SIZE or len(nonce) != NONCE_SIZE:
        raise DecryptionError("Could not decrypt data")
    try:
        return AESGCM(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag:
        raise DecryptionError("Could not decrypt data") from None


def wrap_vault_key(kek: bytes, vault_key: bytes) -> tuple[bytes, bytes]:
    """Encrypt the Vault Key under the KEK. Returns (nonce, wrapped_key)."""
    return encrypt(kek, vault_key, VAULT_KEY_AAD)


def unwrap_vault_key(kek: bytes, nonce: bytes, wrapped_key: bytes) -> bytes:
    """Decrypt the Vault Key. With a wrong password the GCM tag check fails here."""
    vault_key = decrypt(kek, nonce, wrapped_key, VAULT_KEY_AAD)
    if len(vault_key) != KEY_SIZE:
        raise DecryptionError("Could not decrypt data")
    return vault_key


def entry_aad(entry_uuid: str, schema_version: int) -> bytes:
    """AAD for one entry. It ties the ciphertext to its own row, so rows can't be swapped."""
    return f"passgen-vault:entry:{entry_uuid}:v{schema_version}".encode("utf-8")


def encrypt_entry(vault_key: bytes, entry_uuid: str, fields: dict, schema_version: int) -> tuple[bytes, bytes]:
    """Turn all user fields into JSON and encrypt them as one blob."""
    plaintext = json.dumps(fields, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return encrypt(vault_key, plaintext, entry_aad(entry_uuid, schema_version))


def decrypt_entry(vault_key: bytes, entry_uuid: str, nonce: bytes, ciphertext: bytes, schema_version: int) -> dict:
    plaintext = decrypt(vault_key, nonce, ciphertext, entry_aad(entry_uuid, schema_version))
    try:
        fields = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DecryptionError("Entry data is damaged") from None
    if not isinstance(fields, dict):
        raise DecryptionError("Entry data is damaged")
    return fields
