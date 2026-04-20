import sqlite3
import os
import threading
import time
from flask import Flask, jsonify, request, send_from_directory, redirect, session
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from datetime import timedelta

# Determine static folder dynamically
base_dir = os.path.dirname(os.path.abspath(__file__))
potential_folders = [os.path.join(base_dir, 'mobile_app'), base_dir]
static_folder = potential_folders[0] # Default

for folder in potential_folders:
    if os.path.exists(os.path.join(folder, 'index.html')) or os.path.exists(os.path.join(folder, 'login.html')):
        static_folder = folder
        break

app = Flask(__name__, static_folder=static_folder, static_url_path='')
app.secret_key = os.environ.get('SECRET_KEY', 'super-secret-guardian-key')
app.permanent_session_lifetime = timedelta(days=30)

# Database Configuration
DATABASE_URL = os.environ.get('DATABASE_URL')
IS_POSTGRES = DATABASE_URL is not None

class DBWrapper:
    def __init__(self, conn):
        self.conn = conn
    def execute(self, query, params=()):
        if IS_POSTGRES:
            from psycopg2.extras import RealDictCursor
            query = query.replace('?', '%s')
            cursor = self.conn.cursor(cursor_factory=RealDictCursor)
            cursor.execute(query, params)
            return cursor
        else:
            return self.conn.execute(query, params)
    def commit(self): self.conn.commit()
    def close(self): self.conn.close()

def get_db_connection():
    if IS_POSTGRES:
        import psycopg2
        url = DATABASE_URL
        if url.startswith("postgres://"):
            url = url.replace("postgres://", "postgresql://", 1)
        return DBWrapper(psycopg2.connect(url))
    else:
        db_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'database.db')
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        return DBWrapper(conn)

def init_db():
    conn = get_db_connection()
    id_type = "SERIAL PRIMARY KEY" if IS_POSTGRES else "INTEGER PRIMARY KEY AUTOINCREMENT"
    bool_true = "TRUE" if IS_POSTGRES else "1"
    bool_false = "FALSE" if IS_POSTGRES else "0"

    queries = [
        f"CREATE TABLE IF NOT EXISTS users (id {id_type}, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL)",
        f"CREATE TABLE IF NOT EXISTS children (id {id_type}, user_id INTEGER NOT NULL, name TEXT NOT NULL, age INTEGER NOT NULL, grade TEXT NOT NULL, daily_goal_seconds INTEGER DEFAULT 7200)",
        f"CREATE TABLE IF NOT EXISTS devices (id {id_type}, name TEXT NOT NULL, type TEXT NOT NULL, child_id INTEGER, status TEXT DEFAULT 'active')",
        f"CREATE TABLE IF NOT EXISTS pairing_sessions (id {id_type}, code TEXT UNIQUE NOT NULL, device_name TEXT, status TEXT DEFAULT 'pending', linked_device_id INTEGER, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        f"CREATE TABLE IF NOT EXISTS usage_stats (id {id_type}, device_id INTEGER NOT NULL, app_name TEXT NOT NULL, duration_seconds INTEGER NOT NULL, log_date DATE DEFAULT CURRENT_DATE, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        f"CREATE TABLE IF NOT EXISTS app_limits (id {id_type}, child_id INTEGER NOT NULL, app_name TEXT NOT NULL, max_duration_seconds INTEGER, is_blocked BOOLEAN DEFAULT {bool_false})",
        f"CREATE TABLE IF NOT EXISTS ai_rules (id {id_type}, child_id INTEGER UNIQUE NOT NULL, smart_supervision BOOLEAN DEFAULT {bool_true}, response_timeout_mins INTEGER DEFAULT 30, action_rule TEXT DEFAULT 'soft_warning')",
        f"CREATE TABLE IF NOT EXISTS notifications (id {id_type}, user_id INTEGER NOT NULL, title TEXT NOT NULL, message TEXT NOT NULL, is_read BOOLEAN DEFAULT {bool_false}, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)",
        f"CREATE TABLE IF NOT EXISTS app_policies (id {id_type}, child_id INTEGER NOT NULL, app_name TEXT NOT NULL, policy_type TEXT NOT NULL)"
    ]
    
    for q in queries:
        try:
            conn.execute(q)
        except Exception as e:
            print(f"Migration/Init warning: {e}")
            
    # Conditional column additions for SQLite (Postgres will have them from CREATE TABLE IF NOT EXISTS above)
    if not IS_POSTGRES:
        try:
            conn.execute('ALTER TABLE devices ADD COLUMN status TEXT DEFAULT "active"')
        except: pass
        try:
            conn.execute('ALTER TABLE children ADD COLUMN daily_goal_seconds INTEGER DEFAULT 7200')
        except: pass

    conn.commit()
    conn.close()

@app.route('/')
def home():
    """Serve index.html at the root."""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve any static file if it exists, otherwise fall back to index.html (SPA style)."""
    if os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    # If the file isn't found, try without a leading slash just in case
    clean_path = path.lstrip('/')
    if os.path.exists(os.path.join(app.static_folder, clean_path)):
        return send_from_directory(app.static_folder, clean_path)
    
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/api/status')
def status():
    """Debug endpoint to check server health and file visibility."""
    files = []
    if os.path.exists(app.static_folder):
        files = os.listdir(app.static_folder)
    return jsonify({
        'status': 'online',
        'database': 'postgresql' if IS_POSTGRES else 'sqlite',
        'static_folder': app.static_folder,
        'static_folder_exists': os.path.exists(app.static_folder),
        'files_found': files[:10], # Show first 10 files
        'current_time': time.ctime()
    })

def get_auth_user_id():
    auth_header = request.headers.get('Authorization')
    if auth_header and auth_header.startswith('Bearer '):
        token = auth_header.split(' ')[1]
        try:
            return int(token)
        except:
            return None
    return session.get('user_id')

# -------------- AUTH API --------------

@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'parent')

    if not email or not password:
        return jsonify({'error': 'Email and password required'}), 400

    hashed_pw = generate_password_hash(password)
    conn = get_db_connection()
    try:
        cursor = conn.execute('INSERT INTO users (email, password, role) VALUES (?, ?, ?)', (email, hashed_pw, role))
        conn.commit()
        user_id = cursor.lastrowid
        session.permanent = True
        session['user_id'] = user_id
        session['email'] = email
        session['role'] = role
        return jsonify({'success': True, 'user_id': user_id, 'token': str(user_id), 'role': role}), 201
    except sqlite3.IntegrityError:
        return jsonify({'error': 'Email already exists'}), 409
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
    conn.close()

    if user and check_password_hash(user['password'], password):
        session.permanent = True
        session['user_id'] = user['id']
        session['email'] = user['email']
        session['role'] = user['role']
        return jsonify({'success': True, 'role': user['role'], 'token': str(user['id'])}), 200
    
    return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/api/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True}), 200

@app.route('/api/me', methods=['GET'])
def get_me():
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db_connection()
    user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    conn.close()
    
    if user:
        return jsonify({
            'user_id': user['id'],
            'email': user['email'],
            'role': user['role']
        })
    return jsonify({'error': 'User not found'}), 404

# -------------- APP API --------------

@app.route('/api/children', methods=['GET'])
def get_children():
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    children = conn.execute('SELECT * FROM children WHERE user_id = ?', (user_id,)).fetchall()
    
    result = []
    for c in children:
        child_dict = dict(c)
        devices = conn.execute('SELECT * FROM devices WHERE child_id = ?', (c['id'],)).fetchall()
        child_dict['devices'] = [dict(d) for d in devices]
        result.append(child_dict)
        
    conn.close()
    return jsonify(result)

@app.route('/api/children', methods=['POST'])
def add_child():
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    new_child = request.get_json()
    name = new_child.get('name')
    age = new_child.get('age')
    grade = new_child.get('grade')
    
    if not name or not age or not grade:
        return jsonify({'error': 'Missing required fields'}), 400
        
    conn = get_db_connection()
    cursor = conn.execute('INSERT INTO children (user_id, name, age, grade) VALUES (?, ?, ?, ?)', (user_id, name, age, grade))
    conn.commit()
    child_id = cursor.lastrowid
    conn.close()
    return jsonify({'id': child_id, 'name': name, 'age': age, 'grade': grade}), 201

@app.route('/api/children/<int:child_id>', methods=['DELETE'])
def delete_child(child_id):
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    # Ensure the child belongs to the logged in user
    child = conn.execute('SELECT * FROM children WHERE id = ? AND user_id = ?', (child_id, user_id)).fetchone()
    if not child:
        conn.close()
        return jsonify({'error': 'Not found or permission denied'}), 404
        
    # Cascade delete all related data
    conn.execute('DELETE FROM usage_stats WHERE device_id IN (SELECT id FROM devices WHERE child_id = ?)', (child_id,))
    conn.execute('DELETE FROM app_limits WHERE child_id = ?', (child_id,))
    conn.execute('DELETE FROM ai_rules WHERE child_id = ?', (child_id,))
    conn.execute('DELETE FROM devices WHERE child_id = ?', (child_id,))
    conn.execute('DELETE FROM children WHERE id = ?', (child_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 200

@app.route('/api/devices/<int:device_id>', methods=['DELETE'])
def delete_device(device_id):
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    
    # Check permission
    device = conn.execute('''
        SELECT d.id FROM devices d
        JOIN children c ON d.child_id = c.id
        WHERE d.id = ? AND c.user_id = ?
    ''', (device_id, user_id)).fetchone()
    
    if not device:
        conn.close()
        return jsonify({'error': 'Not found or permission denied'}), 404
        
    conn.execute('DELETE FROM devices WHERE id = ?', (device_id,))
    conn.commit()
    conn.close()
    return jsonify({'success': True}), 200

# -------------- PAIRING API --------------

def generate_pairing_code():
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=6))

@app.route('/api/pairing/generate', methods=['POST'])
def generate_pairing():
    code = generate_pairing_code()
    conn = get_db_connection()
    while conn.execute('SELECT id FROM pairing_sessions WHERE code = ?', (code,)).fetchone():
        code = generate_pairing_code()
    
    conn.execute('INSERT INTO pairing_sessions (code, status) VALUES (?, ?)', (code, 'pending'))
    conn.commit()
    conn.close()
    return jsonify({'success': True, 'code': code}), 201

@app.route('/api/pairing/status/<code>', methods=['GET'])
def pairing_status(code):
    conn = get_db_connection()
    # Join with devices and children to get the child's name if linked
    session_data = conn.execute('''
        SELECT ps.*, c.name as child_name 
        FROM pairing_sessions ps
        LEFT JOIN devices d ON ps.linked_device_id = d.id
        LEFT JOIN children c ON d.child_id = c.id
        WHERE ps.code = ?
    ''', (code,)).fetchone()
    conn.close()
    
    if not session_data:
        return jsonify({'error': 'Invalid code'}), 404
        
    if session_data['status'] == 'linked':
        return jsonify({
            'success': True, 
            'status': 'linked', 
            'device_id': session_data['linked_device_id'],
            'child_name': session_data['child_name']
        })
    
    return jsonify({'success': True, 'status': 'pending'})

@app.route('/api/pairing/link', methods=['POST'])
def link_pairing():
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    data = request.get_json()
    code = data.get('code')
    child_id = data.get('child_id')
    device_name = data.get('device_name', 'Child Device')
    
    if not code or not child_id:
        return jsonify({'error': 'Missing code or child_id'}), 400
        
    print(f"DEBUG: Linking attempt - Code: {code}, ChildID: {child_id}, UserID: {session.get('user_id')}")
        
    conn = get_db_connection()
    pairing = conn.execute('SELECT * FROM pairing_sessions WHERE code = ? AND status = ?', (code, 'pending')).fetchone()
    
    if not pairing:
        print(f"DEBUG: Pairing code {code} not found or not pending")
        conn.close()
        return jsonify({'error': 'Invalid or expired code'}), 400
        
    # Use get_auth_user_id instead of session directly
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Not authenticated'}), 401

    conn = get_db_connection()
    child = conn.execute('SELECT id FROM children WHERE id = ? AND user_id = ?', (int(child_id), user_id)).fetchone()
    if not child:
        print(f"DEBUG: Child {child_id} not found for user {user_id}")
        conn.close()
        return jsonify({'error': 'Invalid child or unauthorized'}), 404
        
    cursor = conn.execute('INSERT INTO devices (name, type, child_id) VALUES (?, ?, ?)', (device_name, 'Mobile', int(child_id)))
    device_id = cursor.lastrowid
    
    conn.execute('UPDATE pairing_sessions SET status = ?, linked_device_id = ? WHERE code = ?', ('linked', device_id, code))
    conn.commit()
    conn.close()
    
    print(f"DEBUG: Successfully linked device {device_id} to child {child_id}")
    return jsonify({'success': True, 'device_id': device_id})

# -------------- STATS API --------------

@app.route('/api/stats', methods=['POST'])
def post_stats():
    data = request.get_json()
    device_id = data.get('device_id')
    stats = data.get('stats', [])
    
    if not device_id or not stats:
        return jsonify({'error': 'Invalid data'}), 400
        
    conn = get_db_connection()
    for stat in stats:
        app_name = stat.get('app_name')
        duration = stat.get('duration_seconds', 0)
        conn.execute('INSERT INTO usage_stats (device_id, app_name, duration_seconds) VALUES (?, ?, ?)', 
                     (device_id, app_name, duration))
    conn.commit()
    conn.close()
    return jsonify({'success': True})

@app.route('/api/stats/<int:child_id>', methods=['GET'])
def get_stats(child_id):
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
    
    period = request.args.get('period')
        
    conn = get_db_connection()
    child = conn.execute('SELECT id FROM children WHERE id = ? AND user_id = ?', (child_id, user_id)).fetchone()
    
    if not child:
        conn.close()
        return jsonify({'error': 'Unauthorized access'}), 403
        
    query = '''
        SELECT u.app_name, SUM(u.duration_seconds) as total_duration
        FROM usage_stats u
        JOIN devices d ON u.device_id = d.id
        WHERE d.child_id = ?
    '''
    params = [child_id]
    
    if period == 'today':
        query += " AND date(u.log_date) = date('now', 'localtime')"
        
    query += " GROUP BY u.app_name ORDER BY total_duration DESC"
    
    stats = conn.execute(query, params).fetchall()
    
    conn.close()
    return jsonify([dict(row) for row in stats])

@app.route('/api/stats/timeline/<int:child_id>', methods=['GET'])
def get_timeline(child_id):
    user_id = get_auth_user_id()
    if not user_id:
        return jsonify({'error': 'Unauthorized'}), 401
        
    conn = get_db_connection()
    child = conn.execute('SELECT * FROM children WHERE id = ? AND user_id = ?', (child_id, user_id)).fetchone()
    
    if not child:
        conn.close()
        return jsonify({'error': 'Unauthorized access'}), 403
        
    rows = conn.execute('''
        SELECT u.id, u.app_name, u.duration_seconds, u.log_date, u.created_at, d.name as device_name,
        (SELECT COUNT(*) FROM usage_stats s JOIN devices dev ON s.device_id = dev.id WHERE s.app_name = u.app_name AND date(s.log_date) = date(u.log_date) AND dev.child_id = ?) as frequency
        FROM usage_stats u
        JOIN devices d ON u.device_id = d.id
        WHERE d.child_id = ?
        ORDER BY u.created_at DESC
        LIMIT 50
    ''', (child_id, child_id)).fetchall()
    
    conn.close()
    return jsonify([dict(row) for row in rows])

@app.route('/api/policies/<int:child_id>', methods=['GET', 'POST', 'DELETE'])
def app_policies(child_id):
    user_id = get_auth_user_id()
    if not user_id: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        app_name = data.get('app_name')
        policy_type = data.get('policy_type') # 'always_allowed' or 'blocked_category'
        if not app_name or not policy_type:
            conn.close()
            return jsonify({'error': 'Missing data'}), 400
        conn.execute('INSERT INTO app_policies (child_id, app_name, policy_type) VALUES (?, ?, ?)', (child_id, app_name, policy_type))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    elif request.method == 'DELETE':
        data = request.get_json()
        app_name = data.get('app_name')
        policy_type = data.get('policy_type')
        conn.execute('DELETE FROM app_policies WHERE child_id=? AND app_name=? AND policy_type=?', (child_id, app_name, policy_type))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    else:
        policies = conn.execute('SELECT * FROM app_policies WHERE child_id=?', (child_id,)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in policies])

# -------------- ADVANCED DASHBOARD API --------------

@app.route('/api/devices/<int:device_id>/status', methods=['GET', 'POST'])
def device_status(device_id):
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        status = data.get('status', 'active')
        conn.execute('UPDATE devices SET status = ? WHERE id = ?', (status, device_id))
        conn.commit()
        conn.close()
        return jsonify({'success': True, 'status': status})
    else:
        # device = conn.execute('SELECT d.status, d.child_id FROM devices d WHERE d.id = ?', (device_id,)).fetchone()
        # Updated to join with children to get name and goal
        device = conn.execute('''
            SELECT d.status, d.child_id, c.name as child_name, c.daily_goal_seconds
            FROM devices d
            LEFT JOIN children c ON d.child_id = c.id
            WHERE d.id = ?
        ''', (device_id,)).fetchone()
        
        if device:
            child_id = device['child_id']
            limits = conn.execute('SELECT * FROM app_limits WHERE child_id=?', (child_id,)).fetchall() if child_id else []
            
            # Fetch today's total stats
            total_dur = 0
            app_stats = []
            if child_id:
                stats = conn.execute("SELECT SUM(duration_seconds) as total FROM usage_stats JOIN devices d ON usage_stats.device_id=d.id WHERE d.child_id=? AND date(log_date)=date('now', 'localtime')", (child_id,)).fetchone()
                if stats and stats['total']:
                    total_dur = stats['total']
                
                app_stats_rows = conn.execute('''
                    SELECT u.app_name, SUM(u.duration_seconds) as total_duration
                    FROM usage_stats u
                    JOIN devices d ON u.device_id = d.id
                    WHERE d.child_id = ? AND date(u.log_date) = date('now', 'localtime')
                    GROUP BY u.app_name
                    ORDER BY total_duration DESC
                ''', (child_id,)).fetchall()
                app_stats = [dict(row) for row in app_stats_rows]
                    
            conn.close()
            return jsonify({
                'status': device['status'], 
                'child_id': child_id, 
                'child_name': device['child_name'] or 'Child',
                'daily_goal_seconds': device['daily_goal_seconds'] or 7200,
                'total_duration_seconds': total_dur,
                'app_stats': app_stats,
                'limits': [dict(l) for l in limits] if limits else []
            })
        conn.close()
        return jsonify({'error': 'Device not found'}), 404

@app.route('/api/limits/<int:child_id>', methods=['GET', 'POST', 'DELETE'])
def app_limits(child_id):
    user_id = get_auth_user_id()
    if not user_id: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        app_name = data.get('app_name')
        max_duration = data.get('max_duration_seconds')
        is_blocked = data.get('is_blocked', False)
        existing = conn.execute('SELECT id FROM app_limits WHERE child_id=? AND app_name=?', (child_id, app_name)).fetchone()
        if existing:
            conn.execute('UPDATE app_limits SET max_duration_seconds=?, is_blocked=? WHERE id=?', (max_duration, is_blocked, existing['id']))
        else:
            conn.execute('INSERT INTO app_limits (child_id, app_name, max_duration_seconds, is_blocked) VALUES (?, ?, ?, ?)', (child_id, app_name, max_duration, is_blocked))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    elif request.method == 'DELETE':
        data = request.get_json()
        app_name = data.get('app_name')
        conn.execute('DELETE FROM app_limits WHERE child_id=? AND app_name=?', (child_id, app_name))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    else:
        limits = conn.execute('SELECT * FROM app_limits WHERE child_id=?', (child_id,)).fetchall()
        conn.close()
        return jsonify([dict(row) for row in limits])

@app.route('/api/ai_rules/<int:child_id>', methods=['GET', 'POST'])
def ai_rules(child_id):
    user_id = get_auth_user_id()
    if not user_id: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    if request.method == 'POST':
        data = request.get_json()
        smart = data.get('smart_supervision', True)
        timeout = data.get('response_timeout_mins', 30)
        rule = data.get('action_rule', 'soft_warning')
        existing = conn.execute('SELECT id FROM ai_rules WHERE child_id=?', (child_id,)).fetchone()
        if existing:
            conn.execute('UPDATE ai_rules SET smart_supervision=?, response_timeout_mins=?, action_rule=? WHERE id=?', (smart, timeout, rule, existing['id']))
        else:
            conn.execute('INSERT INTO ai_rules (child_id, smart_supervision, response_timeout_mins, action_rule) VALUES (?, ?, ?, ?)', (child_id, smart, timeout, rule))
        conn.commit()
        conn.close()
        return jsonify({'success': True})
    else:
        rules = conn.execute('SELECT * FROM ai_rules WHERE child_id=?', (child_id,)).fetchone()
        conn.close()
        if rules:
            return jsonify(dict(rules))
        return jsonify({'smart_supervision': True, 'response_timeout_mins': 30, 'action_rule': 'soft_warning'})

@app.route('/api/notifications', methods=['GET'])
def get_notifications():
    user_id = get_auth_user_id()
    if not user_id: return jsonify({'error': 'Unauthorized'}), 401
    conn = get_db_connection()
    notifs = conn.execute('SELECT * FROM notifications WHERE user_id=? ORDER BY created_at DESC LIMIT 10', (user_id,)).fetchall()
    conn.close()
    return jsonify([dict(n) for n in notifs])

# -------------- BACKGROUND USAGE SIMULATOR --------------
# Generates small usage increments for ALL devices every 15 seconds
# so every child's stats grow live on both parent and child dashboards.

SIM_APPS = ['YouTube', 'Roblox', 'Sketchbook', 'Duolingo Kids', 'TikTok', 'Chrome']
SIM_WEIGHTS = [4, 3, 2, 2, 1, 1]  # YouTube most frequent

def background_usage_simulator():
    """Runs in a background thread. Posts usage for every active device."""
    while True:
        time.sleep(15)
        try:
            conn = get_db_connection()
            devices = conn.execute("SELECT id, status FROM devices WHERE child_id IS NOT NULL").fetchall()
            
            for dev in devices:
                if dev['status'] == 'paused':
                    continue  # Don't generate stats for paused devices
                
                # Pick a random app (weighted)
                chosen_app = random.choices(SIM_APPS, weights=SIM_WEIGHTS, k=1)[0]
                duration = random.randint(10, 40)  # 10-40 seconds per tick
                
                conn.execute(
                    'INSERT INTO usage_stats (device_id, app_name, duration_seconds) VALUES (?, ?, ?)',
                    (dev['id'], chosen_app, duration)
                )
                conn.commit()
            
            conn.close()
        except Exception as e:
            print(f'Simulator error: {e}')

# Start background simulator thread (placed at module level for Gunicorn/production)
sim_thread = threading.Thread(target=background_usage_simulator, daemon=True)
sim_thread.start()
print('Background usage simulator started for all devices.')

if __name__ == '__main__':
    init_db()
    
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True, use_reloader=False)
else:
    # Ensure DB is initialized when running via Gunicorn
    init_db()
