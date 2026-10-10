#!/usr/bin/env python3
"""XNet Cloud TEST server. Prototype only; deploy behind HTTPS (e.g. Render)."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import os, json, sqlite3, secrets, hashlib, hmac, time

PORT = int(os.environ.get('PORT', '8080'))
DB_PATH = Path(os.environ.get('XNET_CLOUD_DB', 'xnet_cloud.db'))
ITERATIONS = 250_000
TOKENS = {}  # token -> username; memory-only sessions


def db():
    con = sqlite3.connect(DB_PATH, timeout=10)
    con.row_factory = sqlite3.Row
    con.execute('''CREATE TABLE IF NOT EXISTS users(
        username TEXT PRIMARY KEY COLLATE NOCASE, salt BLOB NOT NULL, password_hash BLOB NOT NULL,
        created REAL NOT NULL, last_seen REAL NOT NULL DEFAULT 0)''')
    con.execute('''CREATE TABLE IF NOT EXISTS messages(
        id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL,
        body TEXT NOT NULL, created REAL NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)''')
    con.commit()
    return con


def derive(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)

class Handler(BaseHTTPRequestHandler):
    server_version = 'XNetCloudTest/0.7'
    def log_message(self, fmt, *args):
        print('[HTTP]', fmt % args)

    def reply(self, status, data):
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status)
        self.send_header('Content-Type', 'application/json; charset=utf-8')
        self.send_header('Content-Length', str(len(raw)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(raw)

    def body(self):
        length = min(int(self.headers.get('Content-Length', '0')), 16_000)
        if length <= 0: return {}
        return json.loads(self.rfile.read(length).decode('utf-8'))

    def user(self):
        token = self.headers.get('Authorization', '').removeprefix('Bearer ').strip()
        return TOKENS.get(token)

    def do_GET(self):
        username = self.user()
        if not username:
            return self.reply(401, {'ok': False, 'error': 'login_required'})
        if self.path == '/users':
            con = db()
            rows = con.execute('SELECT username,last_seen FROM users WHERE username != ? ORDER BY username COLLATE NOCASE', (username,)).fetchall()
            con.close()
            now = time.time()
            return self.reply(200, {'ok': True, 'users': [{'username': r['username'], 'online': now-r['last_seen'] < 35} for r in rows]})
        if self.path == '/poll':
            con = db()
            rows = con.execute('SELECT id,sender,body,created FROM messages WHERE recipient=? AND delivered=0 ORDER BY id LIMIT 100', (username,)).fetchall()
            if rows:
                con.executemany('UPDATE messages SET delivered=1 WHERE id=?', [(r['id'],) for r in rows])
                con.commit()
            con.close()
            return self.reply(200, {'ok': True, 'messages': [{'id': r['id'], 'sender': r['sender'], 'body': r['body'], 'created': r['created']} for r in rows]})
        return self.reply(404, {'ok': False, 'error': 'not_found'})

    def do_POST(self):
        try:
            data = self.body()
        except Exception:
            return self.reply(400, {'ok': False, 'error': 'bad_json'})
        if self.path in ('/register', '/login'):
            username = str(data.get('username', '')).strip()
            password = str(data.get('password', ''))
            import re
            if not re.fullmatch(r'[A-Za-zА-Яа-яЁё0-9_-]{3,20}', username):
                return self.reply(400, {'ok': False, 'error': 'bad_username'})
            if len(password) < 8 or len(password) > 256:
                return self.reply(400, {'ok': False, 'error': 'bad_password'})
            con = db()
            row = con.execute('SELECT username,salt,password_hash FROM users WHERE username=? COLLATE NOCASE', (username,)).fetchone()
            if self.path == '/register':
                if row:
                    con.close(); return self.reply(409, {'ok': False, 'error': 'username_taken'})
                salt = secrets.token_bytes(16); digest = derive(password, salt)
                con.execute('INSERT INTO users(username,salt,password_hash,created,last_seen) VALUES(?,?,?,?,?)', (username,salt,digest,time.time(),time.time()))
                con.commit(); actual = username
            else:
                if not row or not hmac.compare_digest(derive(password, row['salt']), row['password_hash']):
                    con.close(); return self.reply(401, {'ok': False, 'error': 'bad_login'})
                actual = row['username']
                con.execute('UPDATE users SET last_seen=? WHERE username=?', (time.time(), actual)); con.commit()
            con.close()
            token = secrets.token_urlsafe(32); TOKENS[token] = actual
            return self.reply(200, {'ok': True, 'username': actual, 'token': token})
        username = self.user()
        if not username:
            return self.reply(401, {'ok': False, 'error': 'login_required'})
        if self.path == '/heartbeat':
            con = db(); con.execute('UPDATE users SET last_seen=? WHERE username=?', (time.time(), username)); con.commit(); con.close()
            return self.reply(200, {'ok': True})
        if self.path == '/send':
            recipient = str(data.get('recipient', '')).strip()
            body = str(data.get('body', ''))
            if not body or len(body) > 4000:
                return self.reply(400, {'ok': False, 'error': 'bad_message'})
            con = db()
            row = con.execute('SELECT username FROM users WHERE username=? COLLATE NOCASE', (recipient,)).fetchone()
            if not row:
                con.close(); return self.reply(404, {'ok': False, 'error': 'no_user'})
            con.execute('INSERT INTO messages(sender,recipient,body,created) VALUES(?,?,?,?)', (username,row['username'],body,time.time()))
            con.execute('UPDATE users SET last_seen=? WHERE username=?', (time.time(), username))
            con.commit(); con.close()
            return self.reply(200, {'ok': True})
        return self.reply(404, {'ok': False, 'error': 'not_found'})

if __name__ == '__main__':
    db().close()
    print(f'XNet Cloud TEST listening on 0.0.0.0:{PORT}')
    ThreadingHTTPServer(('0.0.0.0', PORT), Handler).serve_forever()
