import os
import sys
import tempfile
from pathlib import Path

import pytest

# Safety net: even if some code asks for the default data folder, it gets a temp
# folder, never the real vault in %APPDATA%.
os.environ["PASSGEN_DATA_DIR"] = tempfile.mkdtemp(prefix="pgv_test_")
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.auth import AuthManager  # noqa: E402
from core.database import Database  # noqa: E402

MASTER = "Blue-Kettle-92-Orbit!x"
OTHER_MASTER = "Another-Strong-Pass-77!"
# Small Argon2id settings so the tests run fast. The app itself uses the real ones from config.py.
FAST_KDF = {"algorithm": "argon2id", "version": 19, "time_cost": 1, "memory_cost": 8 * 1024, "parallelism": 1, "hash_len": 32}


class FakeClock:
    def __init__(self, start=1_000_000.0):
        self.now = start

    def __call__(self):
        return self.now

    def advance(self, seconds):
        self.now += seconds


@pytest.fixture
def clock():
    return FakeClock()


@pytest.fixture
def db(tmp_path):
    database = Database(tmp_path / "vault.db")
    yield database
    database.close()


@pytest.fixture
def auth(db, clock):
    return AuthManager(db, clock=clock, kdf_params=FAST_KDF)
