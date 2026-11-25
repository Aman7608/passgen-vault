# 5-minute interview demo

## Before the interview

- Start the app with a demo folder so your real vault stays private:
  `$env:PASSGEN_DATA_DIR = "$env:TEMP\passgen-demo"; python main.py`
- Have the code open in VS Code on `core/crypto.py` and `core/auth.py`.
- Have a terminal ready for `python -m pytest -v`.

## Script

**0:00 – 0:30 · The problem**
"People reuse weak passwords, and notes files aren't safe. I built a local password manager to learn how the real ones protect a vault file, and I documented what it can and can't protect against."

**0:30 – 1:30 · First run and login**
- Show the setup screen. Type a weak password and point at the live strength meter and its tips. Then type a strong one.
- Point at the warning: there is no recovery, because the password is never stored.
- Lock, then enter a wrong password 3 times to show the lockout countdown. Mention that it is saved in the database, so restarting doesn't reset it.

**1:30 – 2:45 · Daily use**
- Generator: change the length, untick all types (it refuses), turn on "exclude look-alikes", click "Use this password". The add form opens with it filled in.
- Save an entry and show the vault: live search, category filter, masked password with Show/Copy. Say: "Copy clears the clipboard after 20 seconds, but only if it still holds my value."
- Dashboard: point at the reused and weak counts, the security score and the donut chart.

**2:45 – 4:00 · Under the hood (switch to code)**
- `core/crypto.py`: Argon2id → KEK → unwrap the Vault Key → AES-GCM per entry, with the AAD tied to the row's UUID.
- `core/auth.py`: "Login is just a successful unwrap. A wrong password fails the GCM tag check, so there is no password hash to crack offline. You'd have to run Argon2id for every guess."
- Open `vault.db` in a hex viewer or DB Browser for SQLite to show it's only ciphertext.

**4:00 – 5:00 · Tests and limits**
- Run `python -m pytest -v` (around 60 tests, about a second).
- Name two limitations from SECURITY.md: the lockout can be bypassed by copying the file, and Python can't wipe strings from memory.

## Likely interview questions

**Why Argon2id and not SHA-256 or bcrypt?**
SHA-256 is built to be fast, which helps an attacker try billions of guesses. Argon2id is deliberately slow and memory-hard (64 MiB per guess here), which hurts GPUs and ASICs. It won the Password Hashing Competition, and OWASP recommends it. bcrypt is fine, but it isn't memory-hard and it cuts passwords off at 72 bytes.

**Why have a separate Vault Key? Why not encrypt entries straight with the password key?**
That's envelope encryption. Changing the master password only re-wraps 32 bytes instead of re-encrypting every entry. It also means the Argon2id settings can be raised later without touching any entry.

**If no password hash is stored, how do you know the password is wrong?**
AES-GCM is authenticated encryption. Decrypting the wrapped key with the wrong KEK fails the 16-byte tag check and raises `InvalidTag`. The tag is the check.

**What is the AAD for?**
Associated data is authenticated but not encrypted. Using `uuid + schema_version` binds each ciphertext to its row. An attacker can't copy the "bank" ciphertext into the "email" row, because decryption would fail.

**What happens if a nonce is reused in GCM?**
It's catastrophic. An attacker can XOR two ciphertexts to learn the XOR of the plaintexts, and can recover the authentication key and forge messages. So every write uses a fresh 96-bit random nonce from `os.urandom`, and a test checks 1,000 of them are all different.

**Can't an attacker just bypass your lockout?**
Yes. The lockout only slows guessing inside the app. With a copy of `vault.db`, the real limits are the Argon2id cost and the master password's strength. That's why the app enforces a strong master password, and SECURITY.md says so openly.

**Why decrypt everything into memory? Isn't that risky?**
The fields are encrypted, so SQL can't search them. The other option would be blind indexes, which leak information. Decrypting in memory while unlocked is what most local password managers do. When the vault locks, all references are dropped. The limitation is that Python can't promise the memory is wiped.

**What is stored in plaintext?**
Row id, UUID, schema version, nonce, ciphertext, and the created/updated timestamps. Timestamps leak when entries were added or changed, and how many there are. That's documented.

**How does the strength checker work?**
It starts from an entropy estimate (length × log2(character pool)). Characters that are part of a weak pattern stop counting at full value, and each pattern is charged a small fixed number of bits instead. Patterns are: a common-password list (including l33t swaps), sequences, repeats, keyboard walks, years and dates, and the entry's own username or site name. The resulting bits decide the level.

**How do you stop SQL injection?**
Every query uses `?` placeholders, and user text is encrypted before it reaches the database anyway. A test stores `'; DROP TABLE entries;--` and reads it back unchanged.

**How would you improve it?**
A Have I Been Pwned k-anonymity check, TOTP, passphrase generation, a PyInstaller build, and hiding copied passwords from Windows Clipboard History. Also a signed counter or MAC over the whole vault to detect rollback.
