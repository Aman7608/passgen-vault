# Architecture

PassGen Vault has two layers:

- **`core/`** holds all the security logic: crypto, login, storage, the vault, the generator, the strength checker, the clipboard timer and backups. It never imports a GUI library, so all of it can be tested with pytest without opening a window.
- **`gui/`** is the CustomTkinter interface. It only calls functions in `core/` and never touches keys or SQL directly.

## Module map

```mermaid
flowchart TD
    main[main.py] --> app[gui/app.py<br/>window, navigation, auto-lock]
    app --> login[gui/login.py]
    app --> dash[gui/dashboard.py]
    app --> vaultui[gui/vault.py]
    app --> genui[gui/generator.py]
    app --> setui[gui/settings.py]

    login --> auth[core/auth.py]
    setui --> auth
    setui --> backup[core/backup.py]
    vaultui --> vm[core/vault_manager.py]
    dash --> vm
    genui --> gen[core/generator.py]
    app --> clip[core/clipboard.py]

    auth --> crypto[core/crypto.py]
    vm --> crypto
    backup --> crypto
    vm --> strength[core/strength.py]
    auth --> strength
    auth --> db[core/database.py]
    vm --> db
    backup --> db
    db --> file[(vault.db<br/>SQLite)]
```

## Key hierarchy

```mermaid
flowchart LR
    pw[Master password<br/>never stored] -->|Argon2id<br/>salt, t=3, m=64 MiB, p=4| kek[KEK<br/>never stored]
    kek -->|AES-256-GCM unwrap| vk[Vault Key<br/>random 256-bit]
    wrapped[(wrapped key + nonce<br/>+ salt + KDF params<br/>meta table)] --> vk
    vk -->|AES-256-GCM<br/>AAD = uuid + schema version| e1[(entry 1 blob)]
    vk --> e2[(entry 2 blob)]
    vk --> e3[(entry N blob)]
```

## Unlock flow

```mermaid
sequenceDiagram
    participant U as User
    participant L as gui/login.py
    participant A as core/auth.py
    participant D as vault.db
    U->>L: types master password
    L->>A: unlock(password)
    A->>D: read locked_until
    alt still locked out
        A-->>L: LockedOutError (seconds left)
    else
        A->>D: read salt, KDF params, wrapped key
        A->>A: KEK = Argon2id(password, salt)
        A->>A: AES-GCM decrypt wrapped key
        alt tag check fails (wrong password)
            A->>D: failed_attempts += 1, maybe set locked_until
            A-->>L: AuthError("Incorrect master password")
        else works
            A->>D: reset counters
            A-->>L: Vault Key
            L->>L: VaultManager decrypts all entries into memory
        end
    end
```

## Database schema

| Table | Column | Stored as | Notes |
|---|---|---|---|
| `meta` | `key`, `value` | plaintext | salt, KDF params, wrapped key + nonce, lockout counters, timer settings |
| `entries` | `id` | plaintext | row number |
| | `uuid` | plaintext | random UUID, part of the AAD |
| | `schema_version` | plaintext | layout version of the JSON, part of the AAD |
| | `nonce` | plaintext | 12 random bytes, new on every write |
| | `ciphertext` | encrypted | JSON of name, URL, username, password, category, notes, password_changed_at |
| | `created_at`, `updated_at` | plaintext | metadata leak (see SECURITY.md) |
