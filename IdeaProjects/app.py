import sqlite3
from flask import Flask, jsonify, request, send_from_directory
from datetime import datetime, timezone
import os
from werkzeug.security import generate_password_hash, check_password_hash
from auth_utils import validate_email, validate_password, validate_role, create_token, token_required

DB_PATH = os.path.join(os.path.dirname(__file__), 'milk.db')

app = Flask(__name__, static_folder='public', static_url_path='')


def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            approved INTEGER NOT NULL DEFAULT 0,
            created_at TEXT NOT NULL
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS milk_collections (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            farmer_id INTEGER,
            milk_type TEXT,
            liters REAL,
            created_at TEXT
        )
    ''')
    # add milk_type column to existing schema if missing
    c.execute("PRAGMA table_info(milk_collections)")
    cols = [r[1] for r in c.fetchall()]
    if 'milk_type' not in cols:
        c.execute('ALTER TABLE milk_collections ADD COLUMN milk_type TEXT')
    c.execute('''
        CREATE TABLE IF NOT EXISTS orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            liters REAL,
            price_per_liter REAL,
            status TEXT,
            delivery_lat REAL,
            delivery_lon REAL,
            created_at TEXT
        )
    ''')
    c.execute('''
        CREATE TABLE IF NOT EXISTS history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            type TEXT,
            message TEXT,
            created_at TEXT
        )
    ''')
    # Ensure admin exists
    now = datetime.now(timezone.utc).isoformat()
    c.execute('SELECT id FROM users WHERE email = ?', ('admin@milk.com',))
    if not c.fetchone():
        c.execute('INSERT INTO users (name,email,password,role,approved,created_at) VALUES (?,?,?,?,?,?)',
                  ('Admin', 'admin@milk.com', generate_password_hash('admin123'), 'admin', 1, now))
    c.execute('SELECT value FROM settings WHERE key = ?', ('price_per_liter',))
    if not c.fetchone():
        c.execute('INSERT INTO settings (key, value) VALUES (?,?)', ('price_per_liter', '35'))
    conn.commit()
    conn.close()


def db_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route('/api/ping')
def ping():
    return jsonify(success=True, message='pong')


@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json() or {}
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role')
    if not name or not email or not password or not role:
        return jsonify(success=False, message='Missing fields'), 400
    if not validate_email(email):
        return jsonify(success=False, message='Invalid email address'), 400
    if not validate_password(password):
        return jsonify(success=False, message='Password must be at least 6 characters'), 400
    if not validate_role(role):
        return jsonify(success=False, message='Role must be farmer, customer, or admin'), 400
    approved = 0 if role == 'farmer' else 1
    now = datetime.now(timezone.utc).isoformat()
    hashed_pass = generate_password_hash(password)
    try:
        conn = db_conn()
        c = conn.cursor()
        c.execute('INSERT INTO users (name, email, password, role, approved, created_at) VALUES (?,?,?,?,?,?)',
                  (name, email, hashed_pass, role, approved, now))
        user_id = c.lastrowid
        c.execute('INSERT INTO history (user_id, type, message, created_at) VALUES (?,?,?,?)',
                  (user_id, 'register', f'{name} registered as {role}', now))
        conn.commit()
        token = create_token(user_id, role)
        user = {'id': user_id, 'name': name, 'email': email, 'role': role, 'approved': approved, 'token': token}
        return jsonify(success=True, user=user)
    except sqlite3.IntegrityError:
        return jsonify(success=False, message='User already exists'), 400
    finally:
        conn.close()


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = data.get('email')
    password = data.get('password')
    if not email or not password:
        return jsonify(success=False, message='Missing credentials'), 400
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT id,name,email,password,role,approved,created_at FROM users WHERE email=?', (email,))
    row = c.fetchone()
    conn.close()
    if not row or not check_password_hash(row['password'], password):
        return jsonify(success=False, message='Invalid credentials'), 401
    user = dict(row)
    token = create_token(user['id'], user['role'])
    user['token'] = token
    del user['password']
    return jsonify(success=True, user=user)


@app.route('/api/farmers/pending')
@token_required(role='admin')
def farmers_pending():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT id,name,email,role,approved,created_at FROM users WHERE role = ?', ('farmer',))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(success=True, farmers=rows)


@app.route('/api/admin/approve', methods=['POST'])
@token_required(role='admin')
def admin_approve():
    data = request.get_json() or {}
    farmer_id = data.get('farmerId')
    approve = data.get('approve')
    if not farmer_id:
        return jsonify(success=False, message='Missing farmerId'), 400
    try:
        fid = int(farmer_id)
    except Exception:
        return jsonify(success=False, message='Invalid farmerId'), 400
    conn = db_conn()
    c = conn.cursor()
    c.execute('UPDATE users SET approved = ? WHERE id = ? AND role = ?', (1 if approve else 0, fid, 'farmer'))
    conn.commit()
    updated = c.rowcount
    conn.close()
    return jsonify(success=True, updated=updated)


@app.route('/api/collection', methods=['POST'])
@token_required(role='farmer')
def api_collection():
    data = request.get_json() or {}
    liters = data.get('liters')
    milk_type = data.get('milkType', 'Cow')
    if liters is None:
        return jsonify(success=False, message='Missing liters'), 400
    try:
        amt = float(liters)
    except Exception:
        return jsonify(success=False, message='Invalid liters value'), 400
    farmer_id = request.user.get('sub')
    now = datetime.now(timezone.utc).isoformat()
    conn = db_conn()
    c = conn.cursor()
    c.execute('INSERT INTO milk_collections (farmer_id, milk_type, liters, created_at) VALUES (?,?,?,?)',
              (farmer_id, milk_type, amt, now))
    cid = c.lastrowid
    c.execute('INSERT INTO history (user_id, type, message, created_at) VALUES (?,?,?,?)',
              (farmer_id, 'collection', f'Collected {amt}L of {milk_type}', now))
    conn.commit()
    conn.close()
    return jsonify(success=True, id=cid)


@app.route('/api/collections')
def api_collections():
    conn = db_conn()
    c = conn.cursor()
    c.execute('''
      SELECT m.id, m.milk_type AS milkType, m.liters, m.created_at AS createdAt, u.name as farmer
      FROM milk_collections m
      LEFT JOIN users u ON u.id = m.farmer_id
      ORDER BY m.created_at DESC
    ''')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(success=True, collections=rows)


@app.route('/api/collections/delete', methods=['POST'])
@token_required(role='admin')
def api_collections_delete():
    conn = db_conn()
    c = conn.cursor()
    c.execute('DELETE FROM milk_collections')
    c.execute("DELETE FROM history WHERE type = 'collection'")
    deleted = conn.total_changes
    conn.commit()
    conn.close()
    return jsonify(success=True, deleted=deleted)


@app.route('/api/settings/price')
def api_price_get():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT value FROM settings WHERE key = ?', ('price_per_liter',))
    row = c.fetchone()
    conn.close()
    price = float(row['value']) if row else 35.0
    return jsonify(success=True, price=price)


@app.route('/api/settings/price', methods=['POST'])
def api_price_post():
    data = request.get_json() or {}
    price = data.get('price')
    if price is None:
        return jsonify(success=False, message='Missing price'), 400
    try:
        val = float(price)
    except Exception:
        return jsonify(success=False, message='Invalid price'), 400
    conn = db_conn()
    c = conn.cursor()
    c.execute('INSERT INTO settings (key, value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value',
              ('price_per_liter', str(val)))
    conn.commit()
    conn.close()
    return jsonify(success=True)


@app.route('/api/order', methods=['POST'])
@token_required(role='customer')
def api_order():
    data = request.get_json() or {}
    liters = data.get('liters')
    delivery_lat = data.get('deliveryLat')
    delivery_lon = data.get('deliveryLon')
    if liters is None:
        return jsonify(success=False, message='Missing liters'), 400
    try:
        qty = float(liters)
    except Exception:
        return jsonify(success=False, message='Invalid liters'), 400
    user_id = request.user.get('sub')
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT value FROM settings WHERE key = ?', ('price_per_liter',))
    row = c.fetchone()
    price = float(row['value']) if row else 35.0
    now = datetime.now(timezone.utc).isoformat()
    c.execute('INSERT INTO orders (user_id, liters, price_per_liter, status, delivery_lat, delivery_lon, created_at) VALUES (?,?,?,?,?,?,?)',
              (user_id, qty, price, 'pending', float(delivery_lat or 12.935), float(delivery_lon or 77.615), now))
    oid = c.lastrowid
    conn.commit()
    conn.close()
    return jsonify(success=True, id=oid)


@app.route('/api/orders')
@token_required()
def api_orders():
    conn = db_conn()
    c = conn.cursor()
    c.execute('''
      SELECT o.id, o.liters, o.price_per_liter AS pricePerLiter, o.status, o.delivery_lat AS deliveryLat, o.delivery_lon AS deliveryLon, o.created_at AS createdAt, u.name as customer
      FROM orders o
      LEFT JOIN users u ON u.id = o.user_id
      ORDER BY o.created_at DESC
    ''')
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(success=True, orders=rows)


@app.route('/api/history/<int:user_id>')
@token_required()
def api_history(user_id):
    token_user = request.user
    if token_user.get('role') != 'admin' and token_user.get('sub') != user_id:
        return jsonify(success=False, message='Unauthorized'), 403
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT id, type, message, created_at AS createdAt FROM history WHERE user_id = ? ORDER BY created_at DESC LIMIT 30', (user_id,))
    rows = [dict(r) for r in c.fetchall()]
    conn.close()
    return jsonify(success=True, history=rows)


@app.route('/api/report')
def api_report():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT COALESCE(SUM(liters),0) AS total FROM milk_collections')
    total_collected = c.fetchone()['total']
    c.execute('SELECT COUNT(*) AS total FROM orders')
    total_orders = c.fetchone()['total']
    c.execute('SELECT COALESCE(SUM(liters * price_per_liter),0) AS total FROM orders')
    total_revenue = c.fetchone()['total']
    c.execute('SELECT COUNT(*) AS total FROM users WHERE role = ?', ('farmer',))
    total_farmers = c.fetchone()['total']
    c.execute('SELECT COUNT(*) AS total FROM users WHERE role = ?', ('customer',))
    total_customers = c.fetchone()['total']
    conn.close()
    return jsonify(success=True, report={
        'totalCollected': total_collected,
        'totalOrders': total_orders,
        'totalRevenue': total_revenue,
        'totalFarmers': total_farmers,
        'totalCustomers': total_customers
    })


@app.route('/api/totals')
def api_totals():
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT COALESCE(SUM(liters),0) AS liters_collected FROM milk_collections')
    liters_collected = c.fetchone()['liters_collected']
    c.execute('SELECT COALESCE(SUM(liters * price_per_liter),0) AS revenue FROM orders')
    revenue = c.fetchone()['revenue']
    c.execute('SELECT COUNT(*) AS farmers FROM users WHERE role = ?', ('farmer',))
    farmers = c.fetchone()['farmers']
    c.execute('SELECT COUNT(*) AS customers FROM users WHERE role = ?', ('customer',))
    customers = c.fetchone()['customers']
    c.execute('SELECT COUNT(*) AS pending FROM orders WHERE status = ?', ('pending',))
    pending_orders = c.fetchone()['pending']
    conn.close()
    return jsonify(success=True, totals={
        'litersCollected': liters_collected,
        'revenue': revenue,
        'farmers': farmers,
        'customers': customers,
        'pendingOrders': pending_orders
    })


@app.route('/api/farmers/<int:farmer_id>/totals')
@token_required()
def farmer_totals(farmer_id):
    token_user = request.user
    if token_user.get('role') != 'admin' and token_user.get('sub') != farmer_id:
        return jsonify(success=False, message='Unauthorized'), 403
    conn = db_conn()
    c = conn.cursor()
    c.execute('SELECT COALESCE(SUM(liters),0) AS liters_collected, COUNT(*) AS entries FROM milk_collections WHERE farmer_id = ?', (farmer_id,))
    row = c.fetchone()
    liters_collected = row['liters_collected']
    entries = row['entries']
    c.execute('SELECT COALESCE(SUM(liters * price_per_liter),0) AS revenue, COUNT(*) AS orders FROM orders WHERE user_id = ?', (farmer_id,))
    row2 = c.fetchone()
    revenue = row2['revenue']
    orders = row2['orders']
    conn.close()
    return jsonify(success=True, farmerTotals={'litersCollected': liters_collected, 'collections': entries, 'revenue': revenue, 'orders': orders})


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve(path):
    root = os.path.dirname(__file__)
    if path != '' and os.path.exists(os.path.join(root, path)):
        return send_from_directory(root, path)
    index_path = os.path.join(root, 'index.html')
    if os.path.exists(index_path):
        return send_from_directory(root, 'index.html')
    return jsonify(success=False, message='Not found'), 404


if __name__ == '__main__':
    init_db()
    app.run(host='0.0.0.0', port=8080, debug=True)
