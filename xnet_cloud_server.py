#!/usr/bin/env python3
"""XNet Cloud v0.8 TEST server. HTTPS is provided by the hosting platform."""
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from pathlib import Path
import os, json, sqlite3, secrets, hashlib, hmac, time, re

PORT = int(os.environ.get('PORT', '8080'))
DB_PATH = Path(os.environ.get('XNET_CLOUD_DB', 'xnet_cloud.db'))
ITERATIONS = 250_000
TOKENS = {}

def db():
    con = sqlite3.connect(DB_PATH, timeout=15)
    con.row_factory = sqlite3.Row
    con.execute('''CREATE TABLE IF NOT EXISTS users(username TEXT PRIMARY KEY COLLATE NOCASE, salt BLOB NOT NULL, password_hash BLOB NOT NULL, created REAL NOT NULL, last_seen REAL NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT '')''')
    # Migrate existing v0.7 database safely.
    cols = {r['name'] for r in con.execute('PRAGMA table_info(users)')}
    if 'status' not in cols:
        con.execute("ALTER TABLE users ADD COLUMN status TEXT NOT NULL DEFAULT ''")
    con.execute('''CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, recipient TEXT NOT NULL, body TEXT NOT NULL, created REAL NOT NULL, delivered INTEGER NOT NULL DEFAULT 0)''')
    con.execute('''CREATE TABLE IF NOT EXISTS contacts(owner TEXT NOT NULL, contact TEXT NOT NULL, created REAL NOT NULL, PRIMARY KEY(owner,contact))''')
    con.commit(); return con

def derive(password, salt):
    return hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, ITERATIONS)

class Handler(BaseHTTPRequestHandler):
    server_version = 'XNetCloud/0.8'
    def log_message(self, fmt, *args): print('[HTTP]', fmt % args)
    def reply(self, status, data):
        raw = json.dumps(data, ensure_ascii=False).encode('utf-8')
        self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(raw))); self.send_header('Cache-Control','no-store'); self.end_headers(); self.wfile.write(raw)
    def body(self):
        length = int(self.headers.get('Content-Length','0'))
        if length < 0 or length > 20000: raise ValueError('body_too_large')
        return json.loads(self.rfile.read(length).decode('utf-8')) if length else {}
    def user(self): return TOKENS.get(self.headers.get('Authorization','').removeprefix('Bearer ').strip())
    def do_GET(self):
        if self.path == '/healthz': return self.reply(200, {'ok':True,'version':'0.8'})
        username = self.user()
        if not username: return self.reply(401, {'ok':False,'error':'login_required'})
        con = db(); now = time.time()
        if self.path == '/users':
            rows = con.execute('SELECT username,last_seen,status FROM users WHERE username != ? ORDER BY username COLLATE NOCASE',(username,)).fetchall(); con.close()
            return self.reply(200, {'ok':True,'users':[{'username':r['username'],'online':now-r['last_seen']<40,'status':r['status']} for r in rows]})
        if self.path == '/contacts':
            rows = con.execute('SELECT u.username,u.last_seen,u.status FROM contacts c JOIN users u ON u.username=c.contact WHERE c.owner=? ORDER BY u.username COLLATE NOCASE',(username,)).fetchall(); con.close()
            return self.reply(200, {'ok':True,'contacts':[{'username':r['username'],'online':now-r['last_seen']<40,'status':r['status']} for r in rows]})
        if self.path == '/profile':
            r=con.execute('SELECT username,status,created,last_seen FROM users WHERE username=?',(username,)).fetchone(); con.close()
            return self.reply(200, {'ok':True,'profile':dict(r)})
        if self.path == '/poll':
            rows=con.execute('SELECT id,sender,body,created FROM messages WHERE recipient=? AND delivered=0 ORDER BY id LIMIT 100',(username,)).fetchall()
            if rows: con.executemany('UPDATE messages SET delivered=1 WHERE id=?',[(r['id'],) for r in rows]); con.commit()
            con.close(); return self.reply(200,{'ok':True,'messages':[dict(r) for r in rows]})
        con.close(); return self.reply(404,{'ok':False,'error':'not_found'})
    def do_POST(self):
        try: data=self.body()
        except Exception: return self.reply(400,{'ok':False,'error':'bad_json_or_too_large'})
        if self.path in ('/register','/login'):
            username=str(data.get('username','')).strip(); password=str(data.get('password',''))
            if not re.fullmatch(r'[A-Za-zА-Яа-яЁё0-9_-]{3,20}',username): return self.reply(400,{'ok':False,'error':'bad_username'})
            if len(password)<8 or len(password)>256: return self.reply(400,{'ok':False,'error':'bad_password'})
            con=db(); row=con.execute('SELECT username,salt,password_hash FROM users WHERE username=? COLLATE NOCASE',(username,)).fetchone()
            if self.path=='/register':
                if row: con.close(); return self.reply(409,{'ok':False,'error':'username_taken'})
                salt=secrets.token_bytes(16); digest=derive(password,salt); actual=username
                con.execute('INSERT INTO users(username,salt,password_hash,created,last_seen) VALUES(?,?,?,?,?)',(actual,salt,digest,time.time(),time.time()))
            else:
                if not row or not hmac.compare_digest(derive(password,row['salt']),row['password_hash']): con.close(); return self.reply(401,{'ok':False,'error':'bad_login'})
                actual=row['username']; con.execute('UPDATE users SET last_seen=? WHERE username=?',(time.time(),actual))
            con.commit(); con.close(); token=secrets.token_urlsafe(32); TOKENS[token]=actual
            return self.reply(200,{'ok':True,'username':actual,'token':token})
        username=self.user()
        if not username: return self.reply(401,{'ok':False,'error':'login_required'})
        con=db()
        if self.path=='/heartbeat':
            con.execute('UPDATE users SET last_seen=? WHERE username=?',(time.time(),username)); con.commit(); con.close(); return self.reply(200,{'ok':True})
        if self.path=='/profile':
            status=str(data.get('status','')).strip()
            if len(status)>120: con.close(); return self.reply(400,{'ok':False,'error':'status_too_long'})
            con.execute('UPDATE users SET status=?,last_seen=? WHERE username=?',(status,time.time(),username)); con.commit(); con.close(); return self.reply(200,{'ok':True,'status':status})
        if self.path in ('/contacts/add','/contacts/remove'):
            target=str(data.get('username','')).strip()
            row=con.execute('SELECT username FROM users WHERE username=? COLLATE NOCASE',(target,)).fetchone()
            if not row: con.close(); return self.reply(404,{'ok':False,'error':'no_user'})
            target=row['username']
            if target.casefold()==username.casefold(): con.close(); return self.reply(400,{'ok':False,'error':'self_contact'})
            if self.path.endswith('/add'): con.execute('INSERT OR IGNORE INTO contacts(owner,contact,created) VALUES(?,?,?)',(username,target,time.time()))
            else: con.execute('DELETE FROM contacts WHERE owner=? AND contact=?',(username,target))
            con.commit(); con.close(); return self.reply(200,{'ok':True})
        if self.path=='/history':
            target=str(data.get('username','')).strip(); before=int(data.get('before',0) or 0)
            exists=con.execute('SELECT 1 FROM users WHERE username=? COLLATE NOCASE',(target,)).fetchone()
            if not exists: con.close(); return self.reply(404,{'ok':False,'error':'no_user'})
            rows=con.execute('SELECT id,sender,recipient,body,created FROM messages WHERE ((sender=? AND recipient=?) OR (sender=? AND recipient=?)) AND (?=0 OR id<?) ORDER BY id DESC LIMIT 50',(username,target,target,username,before,before)).fetchall(); con.close()
            return self.reply(200,{'ok':True,'messages':[dict(r) for r in reversed(rows)]})
        if self.path=='/send':
            recipient=str(data.get('recipient','')).strip(); body=str(data.get('body',''))
            if not body.strip() or len(body)>4000: con.close(); return self.reply(400,{'ok':False,'error':'bad_message'})
            row=con.execute('SELECT username FROM users WHERE username=? COLLATE NOCASE',(recipient,)).fetchone()
            if not row: con.close(); return self.reply(404,{'ok':False,'error':'no_user'})
            recipient=row['username']
            if recipient.casefold()==username.casefold(): con.close(); return self.reply(400,{'ok':False,'error':'self_message'})
            con.execute('INSERT INTO messages(sender,recipient,body,created) VALUES(?,?,?,?)',(username,recipient,body,time.time())); con.execute('UPDATE users SET last_seen=? WHERE username=?',(time.time(),username)); con.commit(); con.close(); return self.reply(200,{'ok':True})
        con.close(); return self.reply(404,{'ok':False,'error':'not_found'})

if __name__=='__main__':
    db().close(); print(f'XNet Cloud v0.8 listening on 0.0.0.0:{PORT}'); ThreadingHTTPServer(('0.0.0.0',PORT),Handler).serve_forever()
