# API Wallet

**Local encrypted API key manager.**

Store, access, and organize all your API keys behind a single master password — nothing ever leaves your machine.

---

## What It Does

API Wallet stores your API keys in an encrypted vault on disk (`~/.api_wallet/vault.enc`). Enter your master password to unlock — the password is never stored, used only to derive the encryption key in memory. Close the app, keys are locked.

---

## Security

| Layer | Method |
|-------|--------|
| Encryption | Fernet (AES-128-CBC + HMAC-SHA256) |
| Key derivation | PBKDF2HMAC — 100k iterations |
| Storage | `~/.api_wallet/vault.enc` — local only |
| Password | Never stored anywhere |

---

## Stack

Python · Flask · cryptography (Fernet + PBKDF2HMAC) · Vanilla JS

```bash
make run
```

---

*A Creative Konsoles project.*
