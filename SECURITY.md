# Security

This file explains what PassGen Vault protects against, what it does not, and the trade-offs I made. It is a student portfolio project. It has not had a professional security audit, so please don't rely on it for really important secrets.

## How the encryption works

1. When the vault is first created, the app generates a random 256-bit **Vault Key** with `os.urandom(32)`.
2. The master password goes through **Argon2id** (16-byte random salt, time_cost=3, memory_cost=64 MiB, parallelism=4, 32-byte output) to make a **Key-Encryption Key (KEK)**.
3. The Vault Key is encrypted ("wrapped") with **AES-256-GCM** under the KEK. The `meta` table stores the wrapped key, its nonce, the salt and the Argon2id settings. It never stores the KEK or the password.
4. **Logging in means unwrapping.** A wrong password gives a wrong KEK, and the GCM tag check fails (`InvalidTag`). There is no password hash to steal.
5. Each entry's fields (name, URL, username, password, category, notes) are turned into JSON and encrypted together with AES-256-GCM under the Vault Key. Each entry gets a **fresh random 12-byte nonce on every write**.
6. The **AAD** (extra authenticated data) of each entry is its UUID plus the schema version. If someone copies one row's ciphertext into another row, decryption fails.
7. Changing the master password only re-wraps the Vault Key, with a new salt and nonce. Entries are not re-encrypted.

Randomness comes only from `os.urandom` and `secrets`. The `random` module is never used.

**About nonce reuse:** nonces are 96 random bits. With random nonces, AES-GCM is considered safe for up to about 2^32 encryptions under one key. A personal vault will never get anywhere near that. A test checks that 1,000 encryptions give 1,000 different nonces.

## Threat model

### What it protects against

| Threat | Protection |
|---|---|
| Someone copies or steals `vault.db` (stolen laptop, cloud sync leak, backup USB lost) | Every user field is encrypted. Without the master password the file shows only random-looking bytes, plus row counts and timestamps. |
| A casual person at your PC while the app is **locked** | They need the master password. The app lockout slows down guessing in the UI. |
| You walk away and forget to lock | Auto-lock after inactivity (default 5 min) drops the key and all decrypted data. |
| A copied password sitting in the clipboard | The clipboard is cleared after 20 s (configurable), but only if it still holds the value the app copied. |
| Someone edits the vault file (swaps or changes ciphertexts) | AES-GCM detects any change, and the per-entry AAD stops rows being swapped. The app refuses to open a damaged vault. |
| SQL injection | Every query uses `?` placeholders. User text is also encrypted before it reaches SQL. A test stores `'; DROP TABLE entries;--` and reads it back unchanged. |
| Secrets in log files | Logs record events only ("Entry added (id=4)"). A test runs through the features and scans the log output for every secret used. |

### What it does NOT protect against

- **Malware or keyloggers on your PC.** If your computer is infected, the attacker can record your master password as you type it, or read the decrypted data from memory. No password manager can fix a compromised machine.
- **Screen capture or someone watching your screen.** Passwords are masked by default, but "Show" shows them.
- **An attacker at your PC while the vault is unlocked.** They can see and copy everything until it locks.
- **Offline brute force on a weak master password.** See below.

## Known limitations (honest list)

1. **Offline brute force is only slowed down by Argon2id and your master password.** The 3-strikes lockout only exists inside the app. Anyone with a copy of `vault.db` can skip the app and guess passwords directly, or just reset the counters in the `meta` table. What really stops them is that each guess costs one Argon2id run (64 MiB of memory) and that your master password is long and unique. That's why the app makes you pick a strong one.
2. **Python can't reliably wipe memory.** Python strings can't be changed in place, and the garbage collector decides when memory gets reused. When the vault locks, the app drops every reference to the Vault Key and the decrypted entries, but copies may stay in RAM (or in the page file) until the memory is reused. A memory dump taken while the app runs, or soon after, could show secrets.
3. **Windows Clipboard History (Win+V) and cloud clipboard sync** can keep their own copy of anything you copy. The auto-clear only clears the current clipboard, not those copies. If you use these features, consider turning them off, or type passwords in by hand for very important accounts.
4. **No recovery.** The master password is never stored and there is no backdoor. If you forget it, the data is gone. The setup screen warns about this, and you have to tick a box to confirm.
5. **Timestamps and entry count are not encrypted.** `created_at` and `updated_at` are stored in plaintext, so someone with the file can see how many entries you have and when they were added or changed. They can't see which sites they are for. The timestamps are also not part of the AAD, so someone could edit them. That only changes the dates shown in the list. The "old password" stat uses a `password_changed_at` value that is stored inside the ciphertext.
6. **Rollback and deletion.** Someone with write access to the file could replace it with an older copy, or delete whole rows. The app can't detect that, because AES-GCM only protects each blob on its own.
7. **Lockout uses the system clock.** Changing the PC clock affects the lockout timer. This doesn't matter much, because the lockout can be bypassed anyway (see point 1).
8. **Backups** are just copies of the encrypted vault. They open with the master password that was in use **when the backup was made**. Changing the password later doesn't change old backups, so an old backup with an old, weaker password is still a risk. Delete backups you don't need.
9. **The strength meter is an estimate.** It uses entropy, a common-password list and pattern checks, all offline. It can't know whether a password showed up in a recent breach. A Have I Been Pwned check is listed as a future feature.

## Files on disk

| File | Location (Windows) | Contents |
|---|---|---|
| `vault.db` | `%APPDATA%\PassGenVault\` | encrypted vault (SQLite) |
| `passgen_vault.log` | same folder | event log, no secrets |
| `vault-before-restore-*.db` | same folder | the previous vault, kept when a backup is restored |
| `*.pgvault` | wherever you save it | encrypted backup |

## Reporting a problem

If you find a security bug, please open a GitHub issue that describes the problem but leaves out exploit details, and I'll get in touch.
