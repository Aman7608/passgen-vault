import pytest

from core import crypto
from core.config import DEFAULT_KDF_PARAMS
from tests.conftest import FAST_KDF


def test_round_trip():
    key = crypto.generate_key()
    nonce, ct = crypto.encrypt(key, b"hello", b"aad")
    assert crypto.decrypt(key, nonce, ct, b"aad") == b"hello"


def test_tampered_ciphertext_fails():
    key = crypto.generate_key()
    nonce, ct = crypto.encrypt(key, b"hello", b"aad")
    bad = bytearray(ct)
    bad[0] ^= 1
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, nonce, bytes(bad), b"aad")


def test_tampered_nonce_fails():
    key = crypto.generate_key()
    nonce, ct = crypto.encrypt(key, b"hello", b"aad")
    bad = bytearray(nonce)
    bad[0] ^= 1
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, bytes(bad), ct, b"aad")


def test_wrong_aad_and_wrong_key_fail():
    key = crypto.generate_key()
    nonce, ct = crypto.encrypt(key, b"hello", b"aad")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(key, nonce, ct, b"other")
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt(crypto.generate_key(), nonce, ct, b"aad")


def test_1000_unique_nonces():
    key = crypto.generate_key()
    nonces = {crypto.encrypt(key, b"same text", b"aad")[0] for _ in range(1000)}
    assert len(nonces) == 1000


def test_entry_cannot_be_moved_to_another_row():
    key = crypto.generate_key()
    nonce, ct = crypto.encrypt_entry(key, "uuid-a", {"name": "Mail"}, 1)
    assert crypto.decrypt_entry(key, "uuid-a", nonce, ct, 1) == {"name": "Mail"}
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_entry(key, "uuid-b", nonce, ct, 1)  # swapped into a different row
    with pytest.raises(crypto.DecryptionError):
        crypto.decrypt_entry(key, "uuid-a", nonce, ct, 2)  # different schema version


def test_wrap_and_unwrap_vault_key():
    salt = crypto.generate_salt()
    kek = crypto.derive_kek("correct horse", salt, FAST_KDF)
    vault_key = crypto.generate_key()
    nonce, wrapped = crypto.wrap_vault_key(kek, vault_key)
    assert crypto.unwrap_vault_key(kek, nonce, wrapped) == vault_key
    wrong = crypto.derive_kek("wrong horse", salt, FAST_KDF)
    with pytest.raises(crypto.DecryptionError):
        crypto.unwrap_vault_key(wrong, nonce, wrapped)


def test_kdf_is_deterministic_and_salted():
    salt = crypto.generate_salt()
    assert crypto.derive_kek("pw", salt, FAST_KDF) == crypto.derive_kek("pw", salt, FAST_KDF)
    assert crypto.derive_kek("pw", salt, FAST_KDF) != crypto.derive_kek("pw", crypto.generate_salt(), FAST_KDF)
    assert len(crypto.derive_kek("pw", salt, FAST_KDF)) == 32


def test_default_kdf_params_match_spec():
    assert DEFAULT_KDF_PARAMS["time_cost"] == 3
    assert DEFAULT_KDF_PARAMS["memory_cost"] == 65536
    assert DEFAULT_KDF_PARAMS["parallelism"] == 4
    assert DEFAULT_KDF_PARAMS["hash_len"] == 32


def test_bad_kdf_params_are_refused():
    with pytest.raises(ValueError):
        crypto.validate_kdf_params({**DEFAULT_KDF_PARAMS, "memory_cost": 10**9})
    with pytest.raises(ValueError):
        crypto.validate_kdf_params({**DEFAULT_KDF_PARAMS, "algorithm": "md5"})
