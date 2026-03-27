# API Wallet — Claude Re-Entry

**Re-entry: API Wallet**

## What This Is
Local encrypted API key manager. All keys stored encrypted at ~/.api_wallet/vault.enc.
Password is never stored anywhere — it's used to derive the encryption key on each unlock.

## Stack
- Flask, port 5564, host 127.0.0.1
- cryptography (Fernet + PBKDF2HMAC)
- GitHub: papjamzzz/api-wallet

## Run
cd ~/api-wallet && make run

## Security
- Vault: ~/.api_wallet/vault.enc (Fernet encrypted JSON)
- Salt: ~/.api_wallet/salt.bin
- Master password: never stored, entered on each open
- Session: random secret per boot, clears on lock

## First run
Creates ~/.api_wallet/ directory, prompts to set master password.

## Files
- app.py — Flask app, all routes
- templates/base.html — dark theme base, JS utilities (copyToClipboard, toggleShow, copyEnvExport)
- templates/unlock.html — setup + unlock screen
- templates/vault.html — main dashboard
- templates/key_row.html — individual key row partial (display + inline edit)
