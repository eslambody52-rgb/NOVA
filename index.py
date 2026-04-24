import os
from flask import Flask, request, jsonify
from flask_cors import CORS
import hashlib
import psycopg2 # For Postgres (Supabase/Neon)
from datetime import datetime
import secrets
import string

app = Flask(__name__)
CORS(app)

# ══════════════════════════════════════════════════════
#  ⚙  CONFIG
# ══════════════════════════════════════════════════════
SECRET_KEY = os.environ.get('NOVA_SECRET', 'NOVA_SECRET_2024_SFX_BROWSER_V28')
# DATABASE_URL: احصل عليه من Supabase أو Neon.tech وضعه في Vercel Env Vars
DB_URL = os.environ.get('DATABASE_URL')

def get_db_connection():
    conn = psycopg2.connect(DB_URL)
    return conn

# ══════════════════════════════════════════════════════
#  🔑  SERIAL ENGINE (HMAC)
# ══════════════════════════════════════════════════════
def _sha256(text):
    return hashlib.sha256(text.encode()).hexdigest().upper()

def generate_serial():
    chars = string.ascii_uppercase + '0123456789'
    body = ''.join(secrets.choice(chars) for _ in range(12))
    check = _sha256(body + SECRET_KEY)[:4]
    return f'{body[:4]}-{body[4:8]}-{body[8:12]}-{check}'

# ══════════════════════════════════════════════════════
#  📡  API ENDPOINTS (FOR PLUGIN)
# ══════════════════════════════════════════════════════

@app.route('/api/activate', methods=['POST'])
def activate():
    data = request.get_json()
    serial = data.get('serial', '').upper()
    hwid = data.get('hwid')
    
    if not serial or not hwid:
        return jsonify({'status': 'error', 'message': 'Missing data'}), 400

    conn = get_db_connection()
    cur = conn.cursor()
    
    cur.execute("SELECT status, hwid FROM serials WHERE serial = %s", (serial,))
    row = cur.fetchone()

    if not row:
        return jsonify({'status': 'invalid'}), 200
    
    status, saved_hwid = row
    
    if status == 'revoked':
        return jsonify({'status': 'revoked'}), 200
        
    if saved_hwid and saved_hwid != hwid:
        return jsonify({'status': 'hwid_taken'}), 200

    # Activate
    ts = datetime.now()
    cur.execute("UPDATE serials SET status = 'active', hwid = %s, activated_at = %s, last_ping = %s, ping_count = ping_count + 1 WHERE serial = %s",
                (hwid, ts, ts, serial))
    conn.commit()
    cur.close()
    conn.close()
    
    return jsonify({'status': 'activated'}), 200

@app.route('/api/ping', methods=['POST'])
def ping():
    data = request.get_json()
    serial = data.get('serial', '').upper()
    hwid = data.get('hwid')
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT status, hwid FROM serials WHERE serial = %s", (serial,))
    row = cur.fetchone()
    
    if not row or row[0] == 'revoked' or (row[1] and row[1] != hwid):
        cur.close()
        conn.close()
        return jsonify({'status': 'revoked'}), 200

    cur.execute("UPDATE serials SET last_ping = %s, ping_count = ping_count + 1 WHERE serial = %s",
                (datetime.now(), serial))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'status': 'active'}), 200

# ══════════════════════════════════════════════════════
#  📊  DASHBOARD API (FOR WEB UI)
# ══════════════════════════════════════════════════════

@app.route('/api/list', methods=['GET'])
def list_serials():
    # ملاحظة: في النسخة النهائية يجب إضافة باسوورد هنا للـ Dashboard
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT * FROM serials ORDER BY id DESC")
    columns = [desc[0] for desc in cur.description]
    results = [dict(zip(columns, row)) for row in cur.fetchall()]
    cur.close()
    conn.close()
    return jsonify(results)

@app.route('/api/generate', methods=['POST'])
def create_key():
    data = request.get_json()
    client = data.get('client', 'Unknown')
    new_key = generate_serial()
    
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO serials (serial, client_name, status, created_at) VALUES (%s, %s, %s, %s)",
                (new_key, client, 'pending', datetime.now()))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'serial': new_key})

@app.route('/api/revoke', methods=['POST'])
def revoke_key():
    serial = request.get_json().get('serial')
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("UPDATE serials SET status = 'revoked' WHERE serial = %s", (serial,))
    conn.commit()
    cur.close()
    conn.close()
    return jsonify({'success': True})

if __name__ == '__main__':
    app.run(debug=True)
