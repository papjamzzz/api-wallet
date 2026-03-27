import os
import json
import uuid
import secrets
from pathlib import Path
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

VAULT_DIR = Path.home() / ".api_wallet"
VAULT_FILE = VAULT_DIR / "vault.enc"
SALT_FILE = VAULT_DIR / "salt.bin"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)  # Random per boot — sessions clear on restart
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'


def get_or_create_salt():
    VAULT_DIR.mkdir(exist_ok=True)
    if not SALT_FILE.exists():
        salt = os.urandom(16)
        SALT_FILE.write_bytes(salt)
    return SALT_FILE.read_bytes()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_vault(fernet_key: bytes) -> dict:
    if not VAULT_FILE.exists():
        return {"keys": []}
    try:
        f = Fernet(fernet_key)
        data = f.decrypt(VAULT_FILE.read_bytes())
        return json.loads(data)
    except InvalidToken:
        return None  # Wrong password


def save_vault(vault: dict, fernet_key: bytes):
    VAULT_DIR.mkdir(exist_ok=True)
    f = Fernet(fernet_key)
    VAULT_FILE.write_bytes(f.encrypt(json.dumps(vault).encode()))


def get_fernet_key():
    return session.get('fernet_key')


def require_unlock(fn):
    from functools import wraps
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('unlocked'):
            return redirect(url_for('unlock'))
        return fn(*args, **kwargs)
    return wrapper


@app.route('/')
def index():
    if not VAULT_FILE.exists() and not SALT_FILE.exists():
        return redirect(url_for('setup'))
    if not session.get('unlocked'):
        return redirect(url_for('unlock'))
    return redirect(url_for('vault'))


@app.route('/setup', methods=['GET', 'POST'])
def setup():
    if VAULT_FILE.exists():
        return redirect(url_for('unlock'))
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm', '')
        if not password:
            error = 'Password cannot be empty.'
        elif password != confirm:
            error = 'Passwords do not match.'
        else:
            salt = get_or_create_salt()
            key = derive_key(password, salt)
            save_vault({"keys": []}, key)
            session['unlocked'] = True
            session['fernet_key'] = key.decode()
            return redirect(url_for('vault'))
    return render_template('unlock.html', mode='setup', error=error)


@app.route('/unlock', methods=['GET', 'POST'])
def unlock():
    if not SALT_FILE.exists():
        return redirect(url_for('setup'))
    error = None
    if request.method == 'POST':
        password = request.form.get('password', '')
        salt = get_or_create_salt()
        key = derive_key(password, salt)
        vault = load_vault(key)
        if vault is None:
            error = 'Wrong password. Try again.'
        else:
            session['unlocked'] = True
            session['fernet_key'] = key.decode()
            return redirect(url_for('vault'))
    return render_template('unlock.html', mode='unlock', error=error)


@app.route('/lock', methods=['POST'])
def lock():
    session.clear()
    return redirect(url_for('unlock'))


@app.route('/vault')
@require_unlock
def vault():
    key = session['fernet_key'].encode()
    data = load_vault(key)
    keys = data.get('keys', [])
    projects = sorted(set(k['project'] for k in keys))
    project_filter = request.args.get('project', 'all')
    if project_filter != 'all':
        displayed = [k for k in keys if k['project'] == project_filter]
    else:
        displayed = keys
    return render_template('vault.html', keys=displayed, projects=projects, current_project=project_filter, all_keys=keys)


@app.route('/add', methods=['POST'])
@require_unlock
def add_key():
    key_enc = session['fernet_key'].encode()
    vault = load_vault(key_enc)
    project = request.form.get('project', '').strip() or request.form.get('new_project', '').strip()
    name = request.form.get('name', '').strip()
    value = request.form.get('value', '').strip()
    if project and name and value:
        vault['keys'].append({'id': str(uuid.uuid4()), 'project': project, 'name': name, 'value': value})
        save_vault(vault, key_enc)
    return redirect(url_for('vault', project=project if project else 'all'))


@app.route('/delete', methods=['POST'])
@require_unlock
def delete_key():
    key_enc = session['fernet_key'].encode()
    vault = load_vault(key_enc)
    key_id = request.form.get('id')
    vault['keys'] = [k for k in vault['keys'] if k['id'] != key_id]
    save_vault(vault, key_enc)
    return redirect(url_for('vault'))


@app.route('/edit', methods=['POST'])
@require_unlock
def edit_key():
    key_enc = session['fernet_key'].encode()
    vault = load_vault(key_enc)
    key_id = request.form.get('id')
    name = request.form.get('name', '').strip()
    value = request.form.get('value', '').strip()
    project = request.form.get('project', '').strip()
    for k in vault['keys']:
        if k['id'] == key_id:
            if name: k['name'] = name
            if value: k['value'] = value
            if project: k['project'] = project
    save_vault(vault, key_enc)
    return redirect(url_for('vault'))


@app.route('/export/<project>')
@require_unlock
def export_project(project):
    key_enc = session['fernet_key'].encode()
    vault = load_vault(key_enc)
    keys = [k for k in vault['keys'] if k['project'] == project]
    lines = '\n'.join(f"{k['name']}={k['value']}" for k in keys)
    return Response(lines, mimetype='text/plain')


if __name__ == '__main__':
    VAULT_DIR.mkdir(exist_ok=True)
    print("API Wallet running at http://127.0.0.1:5564")
    app.run(host='127.0.0.1', port=5564, debug=False)
