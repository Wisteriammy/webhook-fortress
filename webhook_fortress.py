import secrets
import json
import sqlite3
import os
from flask import Flask, request, jsonify, Response
from flask_cors import CORS
from datetime import datetime, timedelta
from functools import wraps
import requests
import threading
import re

app = Flask(__name__)
CORS(app, origins='*')

BRAND_NAME = "KUNI"
BRAND_HEADER = f"WEBHOOK PROTECTED BY {BRAND_NAME}"
BASE_URL = os.environ.get('RENDER_EXTERNAL_URL', 'https://webhook-fortress.onrender.com')

class WebhookFortress:
    def __init__(self):
        self.db = sqlite3.connect('webhook_fortress.db', check_same_thread=False)
        self.init_db()
        self.proxy_links = {}
        self.lock = threading.Lock()

    def init_db(self):
        cursor = self.db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS webhooks (id TEXT PRIMARY KEY, original_url TEXT NOT NULL, proxy_path TEXT UNIQUE NOT NULL, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, expires_at TIMESTAMP, is_active BOOLEAN DEFAULT 1)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS requests (id INTEGER PRIMARY KEY AUTOINCREMENT, webhook_id TEXT, ip_address TEXT, timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        self.db.commit()

    def generate_proxy_path(self):
        return secrets.token_urlsafe(16)

    def create_proxy_link(self, original_url, expires_in_hours=72):
        webhook_id = secrets.token_hex(16)
        proxy_path = self.generate_proxy_path()
        expires_at = datetime.now() + timedelta(hours=expires_in_hours) if expires_in_hours else None
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO webhooks (id, original_url, proxy_path, expires_at) VALUES (?, ?, ?, ?)', (webhook_id, original_url, proxy_path, expires_at))
        self.db.commit()
        proxy_link = f"{BASE_URL}/proxy/{proxy_path}"
        with self.lock:
            self.proxy_links[proxy_path] = {'webhook_id': webhook_id, 'original_url': original_url}
        return {'proxy_link': proxy_link, 'webhook_id': webhook_id, 'expires_at': expires_at.isoformat() if expires_at else None}

    def verify_proxy_path(self, proxy_path):
        cursor = self.db.cursor()
        cursor.execute('SELECT id, original_url, expires_at, is_active FROM webhooks WHERE proxy_path = ?', (proxy_path,))
        result = cursor.fetchone()
        if not result:
            return None, "Invalid proxy path"
        webhook_id, original_url, expires_at, is_active = result
        if not is_active:
            return None, "Webhook is deactivated"
        if expires_at and datetime.now() > datetime.fromisoformat(expires_at):
            return None, "Webhook has expired"
        return {'webhook_id': webhook_id, 'original_url': original_url}, None

    def log_request(self, webhook_id, ip):
        cursor = self.db.cursor()
        cursor.execute('INSERT INTO requests (webhook_id, ip_address) VALUES (?, ?)', (webhook_id, ip))
        self.db.commit()

fortress = WebhookFortress()

def verify_proxy(f):
    @wraps(f)
    def decorated(proxy_path, *args, **kwargs):
        ip = request.remote_addr
        webhook_data, error = fortress.verify_proxy_path(proxy_path)
        if error:
            return jsonify({'error': error}), 404
        fortress.log_request(webhook_data['webhook_id'], ip)
        return f(webhook_data=webhook_data, proxy_path=proxy_path, *args, **kwargs)
    return decorated

@app.route('/', methods=['GET'])
def home():
    return BRAND_HEADER, 200, {'Content-Type': 'text/plain'}

@app.route('/ping', methods=['GET'])
def ping():
    return jsonify({'status': 'alive', 'timestamp': datetime.now().isoformat()})

@app.route('/create', methods=['POST'])
def create_proxy():
    try:
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        data = request.get_json()
        original_url = data.get('url')
        if not original_url:
            return jsonify({'error': 'Webhook URL is required'}), 400
        if not re.match(r'^https://discord\.com/api/webhooks/[\w-]+/[\w-]+$', original_url):
            return jsonify({'error': 'Invalid Discord webhook URL format'}), 400
        expires_in = data.get('expires_in', 72)
        result = fortress.create_proxy_link(original_url, expires_in)
        return jsonify(result), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/proxy/<proxy_path>', methods=['GET', 'POST'])
@verify_proxy
def proxy_webhook(webhook_data, proxy_path):
    try:
        if request.method == 'GET':
            return BRAND_HEADER, 200, {'Content-Type': 'text/plain'}
        if not request.is_json:
            return jsonify({'error': 'Content-Type must be application/json'}), 415
        payload = request.get_json()
        if isinstance(payload, dict):
            payload['_brand'] = BRAND_NAME
            payload['_protected_by'] = BRAND_HEADER
        headers = {'Content-Type': 'application/json', 'User-Agent': f'WebhookFortress/{BRAND_NAME}'}
        response = requests.post(webhook_data['original_url'], json=payload, headers=headers, timeout=10)
        return Response(response.content, status=response.status_code, headers=dict(response.headers))
    except requests.exceptions.Timeout:
        return jsonify({'error': 'Webhook request timed out'}), 504
    except requests.exceptions.ConnectionError:
        return jsonify({'error': 'Could not connect to webhook'}), 502
    except requests.exceptions.RequestException as e:
        return jsonify({'error': f'Webhook request failed: {str(e)}'}), 502

@app.route('/deactivate/<webhook_id>', methods=['POST'])
def deactivate_webhook(webhook_id):
    try:
        cursor = fortress.db.cursor()
        cursor.execute('UPDATE webhooks SET is_active = 0 WHERE id = ?', (webhook_id,))
        fortress.db.commit()
        return jsonify({'status': 'deactivated', 'webhook_id': webhook_id}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/list', methods=['GET'])
def list_webhooks():
    try:
        cursor = fortress.db.cursor()
        cursor.execute('SELECT id, original_url, proxy_path, created_at, expires_at, is_active FROM webhooks ORDER BY created_at DESC LIMIT 50')
        results = cursor.fetchall()
        webhooks = []
        for row in results:
            webhooks.append({'id': row[0], 'original_url': row[1][:50] + '...' if len(row[1]) > 50 else row[1], 'proxy_path': row[2], 'created_at': row[3], 'expires_at': row[4], 'is_active': bool(row[5])})
        return jsonify({'webhooks': webhooks}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/brand', methods=['GET'])
def get_brand():
    return jsonify({'brand': BRAND_NAME, 'header': BRAND_HEADER, 'protected_by': f"Webhook Protected by: {BRAND_NAME}"})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
