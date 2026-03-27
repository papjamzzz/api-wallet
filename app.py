import os
import json
import uuid
import secrets
import re
from pathlib import Path
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, Response

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

VAULT_DIR = Path.home() / ".api_wallet"
VAULT_FILE = VAULT_DIR / "vault.enc"
SALT_FILE = VAULT_DIR / "salt.bin"

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_SAMESITE'] = 'Strict'

# ── Service detection ──────────────────────────────────────────────────────────

SERVICES = {
    'openai':      {'color': '#10a37f', 'bg': 'rgba(16,163,127,0.12)', 'initials': 'OA', 'label': 'OpenAI'},
    'anthropic':   {'color': '#d97706', 'bg': 'rgba(217,119,6,0.12)',  'initials': 'AN', 'label': 'Anthropic'},
    'gemini':      {'color': '#4285f4', 'bg': 'rgba(66,133,244,0.12)', 'initials': 'GM', 'label': 'Google'},
    'google':      {'color': '#4285f4', 'bg': 'rgba(66,133,244,0.12)', 'initials': 'GG', 'label': 'Google'},
    'xai':         {'color': '#e2e8f0', 'bg': 'rgba(226,232,240,0.10)','initials': 'XA', 'label': 'xAI'},
    'mistral':     {'color': '#ff6b35', 'bg': 'rgba(255,107,53,0.12)', 'initials': 'MI', 'label': 'Mistral'},
    'stripe':      {'color': '#635bff', 'bg': 'rgba(99,91,255,0.12)',  'initials': 'ST', 'label': 'Stripe'},
    'github':      {'color': '#a78bfa', 'bg': 'rgba(167,139,250,0.12)','initials': 'GH', 'label': 'GitHub'},
    'railway':     {'color': '#b847ff', 'bg': 'rgba(184,71,255,0.12)', 'initials': 'RW', 'label': 'Railway'},
    'aws':         {'color': '#ff9900', 'bg': 'rgba(255,153,0,0.12)',  'initials': 'AW', 'label': 'AWS'},
    'vercel':      {'color': '#f1f5f9', 'bg': 'rgba(241,245,249,0.08)','initials': 'VC', 'label': 'Vercel'},
    'supabase':    {'color': '#3ecf8e', 'bg': 'rgba(62,207,142,0.12)', 'initials': 'SB', 'label': 'Supabase'},
    'elevenlabs':  {'color': '#ef4444', 'bg': 'rgba(239,68,68,0.12)',  'initials': 'EL', 'label': 'ElevenLabs'},
    'eleven':      {'color': '#ef4444', 'bg': 'rgba(239,68,68,0.12)',  'initials': 'EL', 'label': 'ElevenLabs'},
    'replicate':   {'color': '#a855f7', 'bg': 'rgba(168,85,247,0.12)', 'initials': 'RP', 'label': 'Replicate'},
    'huggingface': {'color': '#fbbf24', 'bg': 'rgba(251,191,36,0.12)', 'initials': 'HF', 'label': 'HuggingFace'},
    'cohere':      {'color': '#39d353', 'bg': 'rgba(57,211,83,0.12)',  'initials': 'CO', 'label': 'Cohere'},
    'stability':   {'color': '#7c3aed', 'bg': 'rgba(124,58,237,0.12)', 'initials': 'SA', 'label': 'Stability AI'},
    'pinecone':    {'color': '#00d1b2', 'bg': 'rgba(0,209,178,0.12)',  'initials': 'PC', 'label': 'Pinecone'},
    'deepseek':    {'color': '#06b6d4', 'bg': 'rgba(6,182,212,0.12)',  'initials': 'DS', 'label': 'DeepSeek'},
    'groq':        {'color': '#f472b6', 'bg': 'rgba(244,114,182,0.12)','initials': 'GQ', 'label': 'Groq'},
    'together':    {'color': '#818cf8', 'bg': 'rgba(129,140,248,0.12)','initials': 'TA', 'label': 'Together AI'},
    'perplexity':  {'color': '#22d3ee', 'bg': 'rgba(34,211,238,0.12)', 'initials': 'PP', 'label': 'Perplexity'},
}

VALUE_PREFIXES = {
    'sk-proj-':   'openai',
    'sk-ant-api': 'anthropic',
    'AIzaSy':     'google',
    'xai-':       'xai',
    'gsk_':       'groq',
    'r8_':        'replicate',
    'hf_':        'huggingface',
    'sk_':        'stripe',
}

DEFAULT_SERVICE = {'color': '#7c3aed', 'bg': 'rgba(124,58,237,0.12)', 'initials': '??', 'label': ''}


def detect_service(name: str, value: str = '') -> dict:
    name_lower = name.lower()
    for svc_key, svc in SERVICES.items():
        if svc_key in name_lower:
            return {**svc, 'key': svc_key}
    for prefix, svc_key in VALUE_PREFIXES.items():
        if value.startswith(prefix):
            svc = SERVICES[svc_key]
            return {**svc, 'key': svc_key}
    return {**DEFAULT_SERVICE, 'key': 'default'}


def mask_value(value: str) -> str:
    if len(value) <= 8:
        return '•' * len(value)
    return value[:4] + '•' * min(len(value) - 8, 24) + value[-4:]


# ── Crypto ─────────────────────────────────────────────────────────────────────

def get_or_create_salt():
    VAULT_DIR.mkdir(exist_ok=True)
    if not SALT_FILE.exists():
        SALT_FILE.write_bytes(os.urandom(16))
    return SALT_FILE.read_bytes()


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=480000)
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))


def load_vault(fernet_key: bytes):
    if not VAULT_FILE.exists():
        return {"keys": []}
    try:
        data = Fernet(fernet_key).decrypt(VAULT_FILE.read_bytes())
        return json.loads(data)
    except InvalidToken:
        return None


def save_vault(vault: dict, fernet_key: bytes):
    VAULT_DIR.mkdir(exist_ok=True)
    VAULT_FILE.write_bytes(Fernet(fernet_key).encrypt(json.dumps(vault).encode()))


def require_unlock(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        if not session.get('unlocked'):
            return redirect(url_for('unlock'))
        return fn(*args, **kwargs)
    return wrapper


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if not SALT_FILE.exists():
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
            error = 'Wrong password.'
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
    key_enc = session['fernet_key'].encode()
    data = load_vault(key_enc)
    raw_keys = data.get('keys', [])

    # Enrich with service detection
    keys = []
    for k in raw_keys:
        svc = detect_service(k.get('name', ''), k.get('value', ''))
        keys.append({**k, 'service': svc, 'masked': mask_value(k.get('value', ''))})

    projects = sorted(set(k['project'] for k in keys))
    counts = {p: sum(1 for k in keys if k['project'] == p) for p in projects}
    counts['all'] = len(keys)

    return render_template('vault.html',
        keys=keys,
        projects=projects,
        counts=counts,
        current_project='all',
    )


@app.route('/add', methods=['POST'])
@require_unlock
def add_key():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    project = (request.form.get('project', '').strip() or request.form.get('new_project', '').strip()).strip()
    name = request.form.get('name', '').strip().upper().replace(' ', '_')
    value = request.form.get('value', '').strip()
    if project and name and value:
        vault_data['keys'].append({'id': str(uuid.uuid4()), 'project': project, 'name': name, 'value': value})
        save_vault(vault_data, key_enc)
    return redirect(url_for('vault'))


@app.route('/delete', methods=['POST'])
@require_unlock
def delete_key():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    key_id = request.form.get('id')
    vault_data['keys'] = [k for k in vault_data['keys'] if k['id'] != key_id]
    save_vault(vault_data, key_enc)
    return redirect(url_for('vault'))


@app.route('/edit', methods=['POST'])
@require_unlock
def edit_key():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    key_id = request.form.get('id')
    for k in vault_data['keys']:
        if k['id'] == key_id:
            if request.form.get('name'): k['name'] = request.form['name'].strip().upper().replace(' ', '_')
            if request.form.get('value'): k['value'] = request.form['value'].strip()
            if request.form.get('project'): k['project'] = request.form['project'].strip()
    save_vault(vault_data, key_enc)
    return redirect(url_for('vault'))


@app.route('/import_env', methods=['POST'])
@require_unlock
def import_env():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    project = request.form.get('project', 'Imported').strip() or 'Imported'
    raw_text = request.form.get('env_text', '')
    existing_names = {k['name'] for k in vault_data['keys']}
    added = 0
    for line in raw_text.splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        match = re.match(r'^([A-Z0-9_]+)\s*=\s*(.+)$', line, re.IGNORECASE)
        if match:
            name = match.group(1).strip().upper()
            value = match.group(2).strip().strip('"').strip("'")
            if name not in existing_names:
                vault_data['keys'].append({'id': str(uuid.uuid4()), 'project': project, 'name': name, 'value': value})
                existing_names.add(name)
                added += 1
    save_vault(vault_data, key_enc)
    return redirect(url_for('vault'))


@app.route('/export/<project>')
@require_unlock
def export_project(project):
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    if project == 'all':
        keys = vault_data['keys']
    else:
        keys = [k for k in vault_data['keys'] if k['project'] == project]
    lines = '\n'.join(f"{k['name']}={k['value']}" for k in keys)
    return Response(lines, mimetype='text/plain')


NETWORKS = [
    {'name': 'Ethereum',  'icon': '⟠',  'color': '#627eea', 'explorer': 'https://etherscan.io',                'explorer_short': 'etherscan.io'},
    {'name': 'Solana',    'icon': '◎',  'color': '#9945ff', 'explorer': 'https://solscan.io',                  'explorer_short': 'solscan.io'},
    {'name': 'Bitcoin',   'icon': '₿',  'color': '#f7931a', 'explorer': 'https://mempool.space',               'explorer_short': 'mempool.space'},
    {'name': 'Polygon',   'icon': '⬡',  'color': '#8247e5', 'explorer': 'https://polygonscan.com',            'explorer_short': 'polygonscan.com'},
    {'name': 'Base',      'icon': '🔵', 'color': '#0052ff', 'explorer': 'https://basescan.org',                'explorer_short': 'basescan.org'},
    {'name': 'Arbitrum',  'icon': '🔷', 'color': '#12aaff', 'explorer': 'https://arbiscan.io',                 'explorer_short': 'arbiscan.io'},
    {'name': 'Optimism',  'icon': '🔴', 'color': '#ff0420', 'explorer': 'https://optimistic.etherscan.io',     'explorer_short': 'optimistic.etherscan.io'},
    {'name': 'BSC',       'icon': '🟡', 'color': '#f0b90b', 'explorer': 'https://bscscan.com',                 'explorer_short': 'bscscan.com'},
    {'name': 'Avalanche', 'icon': '🔺', 'color': '#e84142', 'explorer': 'https://snowtrace.io',                'explorer_short': 'snowtrace.io'},
    {'name': 'Fantom',    'icon': '👻', 'color': '#1969ff', 'explorer': 'https://ftmscan.com',                 'explorer_short': 'ftmscan.com'},
]

TOOLS = [
    {'name': 'ETH Gas Tracker',   'icon': '⛽', 'desc': 'Live gas prices',         'url': 'https://etherscan.io/gastracker'},
    {'name': 'Solana Gas',        'icon': '⚡', 'desc': 'Priority fees',            'url': 'https://solanacompass.com/statistics/fees'},
    {'name': 'DeFiLlama',         'icon': '🦙', 'desc': 'TVL + protocol stats',    'url': 'https://defillama.com'},
    {'name': 'CoinGecko',         'icon': '🦎', 'desc': 'Prices + market data',    'url': 'https://www.coingecko.com'},
    {'name': 'Uniswap',           'icon': '🦄', 'desc': 'Swap on Ethereum',        'url': 'https://app.uniswap.org'},
    {'name': 'Jupiter (Solana)',   'icon': '🪐', 'desc': 'Solana DEX aggregator',  'url': 'https://jup.ag'},
    {'name': 'ENS Lookup',        'icon': '🔍', 'desc': 'Resolve .eth names',      'url': 'https://app.ens.domains'},
    {'name': 'ABI Decoder',       'icon': '⚙️', 'desc': 'Decode contract calls',   'url': 'https://abi.hashex.org'},
    {'name': 'Tenderly',          'icon': '🔬', 'desc': 'Simulate + debug txs',    'url': 'https://dashboard.tenderly.co'},
    {'name': 'CryptoFees',        'icon': '💸', 'desc': 'Protocol fee analytics',  'url': 'https://cryptofees.info'},
]


@app.route('/web3')
@require_unlock
def web3():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    addresses = vault_data.get('addresses', [])
    return render_template('web3.html', networks=NETWORKS, tools=TOOLS, addresses=addresses)


@app.route('/web3/addr/add', methods=['POST'])
@require_unlock
def add_address():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    label = request.form.get('label', '').strip()
    address = request.form.get('address', '').strip()
    network = request.form.get('network', 'Ethereum')
    if 'addresses' not in vault_data:
        vault_data['addresses'] = []
    if label and address:
        vault_data['addresses'].append({'id': str(uuid.uuid4()), 'label': label, 'address': address, 'network': network})
        save_vault(vault_data, key_enc)
    return redirect(url_for('web3'))


@app.route('/web3/addr/delete', methods=['POST'])
@require_unlock
def delete_address():
    key_enc = session['fernet_key'].encode()
    vault_data = load_vault(key_enc)
    addr_id = request.form.get('id')
    vault_data['addresses'] = [a for a in vault_data.get('addresses', []) if a['id'] != addr_id]
    save_vault(vault_data, key_enc)
    return redirect(url_for('web3'))


if __name__ == '__main__':
    VAULT_DIR.mkdir(exist_ok=True)
    print("\n  API Wallet  →  http://127.0.0.1:5564\n")
    app.run(host='127.0.0.1', port=5564, debug=False)
