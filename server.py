"""Notesly application server. Python standard library only."""
from __future__ import annotations
import base64, hashlib, hmac, html, json, mimetypes, os, re, secrets, sqlite3, time
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
DATA = Path(os.environ.get('NOTESLY_DATA_DIR', ROOT / 'data')).resolve()
UPLOADS = DATA / 'uploads'
DB = DATA / 'notesly.sqlite3'
HOST = os.environ.get('NOTESLY_HOST', '127.0.0.1')
PORT = int(os.environ.get('PORT', '8000'))
MAX_BODY = 15 * 1024 * 1024
DATA.mkdir(parents=True, exist_ok=True); UPLOADS.mkdir(parents=True, exist_ok=True)

def connect():
    db = sqlite3.connect(DB, timeout=15); db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON'); return db

def initialize():
    with connect() as db:
        db.executescript('''
        CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, name TEXT NOT NULL, email TEXT UNIQUE NOT NULL, salt BLOB NOT NULL, password_hash BLOB NOT NULL, role TEXT NOT NULL DEFAULT 'student', created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS notes(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), title TEXT NOT NULL, grade TEXT NOT NULL, subject TEXT NOT NULL, topic TEXT NOT NULL DEFAULT '', description TEXT NOT NULL DEFAULT '', file_name TEXT NOT NULL DEFAULT '', file_path TEXT NOT NULL DEFAULT '', file_type TEXT NOT NULL DEFAULT '', status TEXT NOT NULL DEFAULT 'pending', created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP, likes INTEGER NOT NULL DEFAULT 0, duplicate_of INTEGER REFERENCES notes(id));
        CREATE TABLE IF NOT EXISTS likes(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE, PRIMARY KEY(user_id,note_id));
        CREATE TABLE IF NOT EXISTS saves(user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE, PRIMARY KEY(user_id,note_id));
        CREATE TABLE IF NOT EXISTS follows(follower_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, followed_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, PRIMARY KEY(follower_id,followed_id));
        CREATE TABLE IF NOT EXISTS comments(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), note_id INTEGER NOT NULL REFERENCES notes(id) ON DELETE CASCADE, body TEXT NOT NULL, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE TABLE IF NOT EXISTS notifications(id INTEGER PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, message TEXT NOT NULL, href TEXT NOT NULL DEFAULT '#home', read INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP);
        CREATE INDEX IF NOT EXISTS notes_feed ON notes(status,created); CREATE INDEX IF NOT EXISTS comments_note ON comments(note_id,created);
        ''')
        email=os.environ.get('NOTESLY_ADMIN_EMAIL','').strip().lower(); password=os.environ.get('NOTESLY_ADMIN_PASSWORD','')
        if email and password:
            row=db.execute('SELECT id FROM users WHERE email=?',(email,)).fetchone()
            if row: db.execute("UPDATE users SET role='admin' WHERE id=?",(row['id'],))
            else:
                salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000)
                db.execute("INSERT INTO users(name,email,salt,password_hash,role) VALUES(?,?,?,?, 'admin')",(os.environ.get('NOTESLY_ADMIN_NAME','Notesly Admin'),email,salt,digest))

def fail(message, status=400): raise ApiError(message,status)
class ApiError(Exception):
    def __init__(self,message,status): self.message,self.status=message,status

def clean(value, limit=240): return re.sub(r'\s+',' ',str(value or '')).strip()[:limit]
def public_user(row): return {'id':row['id'],'name':row['name'],'initials':''.join(p[0] for p in row['name'].split()[:2]).upper(),'role':row['role']}
def title_match(title, subject, grade, db):
    tokens=set(re.findall(r'[a-z0-9]{4,}',title.lower()))
    if not tokens:return None
    for row in db.execute("SELECT id,title FROM notes WHERE status='published' AND subject=? AND grade=?",(subject,grade)):
        other=set(re.findall(r'[a-z0-9]{4,}',row['title'].lower())); union=tokens|other
        if union and len(tokens&other)/len(union)>=0.55:return row['id']
    return None

class Handler(BaseHTTPRequestHandler):
    server_version='Notesly/1.0'
    def log_message(self, fmt,*args): print('%s - %s'%(self.address_string(),fmt%args))
    def respond(self,data,status=200,headers=None):
        payload=json.dumps(data,ensure_ascii=False).encode(); self.send_response(status); self.send_header('Content-Type','application/json; charset=utf-8'); self.send_header('Content-Length',str(len(payload))); self.send_header('Cache-Control','no-store'); self.send_header('X-Content-Type-Options','nosniff'); self.send_header('Content-Security-Policy',"default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        for key,value in (headers or {}).items():self.send_header(key,value)
        self.end_headers(); self.wfile.write(payload)
    def body(self):
        size=int(self.headers.get('Content-Length','0'))
        if size>MAX_BODY:fail('Request exceeds the 15 MB limit.',413)
        try:return json.loads(self.rfile.read(size) or b'{}')
        except (ValueError,UnicodeDecodeError):fail('Invalid JSON request.')
    def current(self,db):
        jar=cookies.SimpleCookie(self.headers.get('Cookie','')); morsel=jar.get('notesly_session')
        if not morsel:return None
        digest=hashlib.sha256(morsel.value.encode()).hexdigest()
        row=db.execute('SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires>?',(digest,int(time.time()))).fetchone()
        return row
    def require_user(self,db):
        user=self.current(db)
        if not user:fail('Please sign in to continue.',401)
        return user
    def require_admin(self,db):
        user=self.require_user(db)
        if user['role']!='admin':fail('Administrator access is required.',403)
        return user
    def do_GET(self):
        path=urlparse(self.path).path
        if path.startswith('/api/'):
            try:
                with connect() as db:self.api_get(path,parse_qs(urlparse(self.path).query),db)
            except ApiError as e:self.respond({'error':e.message},e.status)
            return
        upload=re.fullmatch(r'/uploads/([a-f0-9]{32}\.[a-z0-9]{1,8})',path)
        if upload:
            try:
                with connect() as db:
                    user=self.require_user(db); row=db.execute('SELECT user_id,status FROM notes WHERE file_path=?',(upload.group(1),)).fetchone()
                    if not row or (row['status']!='published' and row['user_id']!=user['id'] and user['role']!='admin'):fail('Attachment not found.',404)
                target=UPLOADS/upload.group(1)
                if not target.is_file():fail('Attachment not found.',404)
                content=target.read_bytes();self.send_response(200);self.send_header('Content-Type',mimetypes.guess_type(target.name)[0] or 'application/octet-stream');self.send_header('Content-Length',str(len(content)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Content-Disposition','inline');self.end_headers();self.wfile.write(content)
            except ApiError as e:self.respond({'error':e.message},e.status)
            return
        relative=unquote(path.lstrip('/')) or 'index.html'
        if relative not in ('index.html','app.js','styles.css'):self.send_error(404);return
        target=ROOT/relative
        content=target.read_bytes(); kind=mimetypes.guess_type(target.name)[0] or 'application/octet-stream'
        self.send_response(200);self.send_header('Content-Type',kind+('; charset=utf-8' if kind.startswith('text/') or kind in ('application/javascript','application/json') else ''));self.send_header('Content-Length',str(len(content)));self.send_header('X-Content-Type-Options','nosniff');self.send_header('Referrer-Policy','strict-origin-when-cross-origin');self.send_header('Content-Security-Policy',"default-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'");self.end_headers();self.wfile.write(content)
    def api_get(self,path,q,db):
        user=self.current(db)
        if path=='/api/session':self.respond({'user':public_user(user) if user else None});return
        if path=='/api/notes':
            self.require_user(db); grade=clean(q.get('grade',[''])[0],40);subject=clean(q.get('subject',[''])[0],60);search=clean(q.get('q',[''])[0],100); mode=q.get('mode',[''])[0]; saved=q.get('saved',[''])[0]=='1'; following=q.get('following',[''])[0]=='1'
            clauses=["n.status='published'"];args=[]
            if grade:clauses.append('n.grade=?');args.append(grade)
            if subject:clauses.append('n.subject=?');args.append(subject)
            if search:clauses.append('(n.title LIKE ? OR n.topic LIKE ? OR n.description LIKE ? OR n.subject LIKE ?)');args.extend([f'%{search}%']*4)
            if saved:clauses.append('EXISTS(SELECT 1 FROM saves s WHERE s.note_id=n.id AND s.user_id=?)');args.append(user['id'])
            if following:clauses.append('EXISTS(SELECT 1 FROM follows f WHERE f.followed_id=n.user_id AND f.follower_id=?)');args.append(user['id'])
            order='n.likes DESC,n.created DESC' if mode=='popular' else 'n.created DESC'
            rows=db.execute(f"SELECT n.*,u.name,u.id author_id,(SELECT COUNT(*) FROM comments c WHERE c.note_id=n.id) comments,EXISTS(SELECT 1 FROM likes l WHERE l.note_id=n.id AND l.user_id=?) liked,EXISTS(SELECT 1 FROM saves s WHERE s.note_id=n.id AND s.user_id=?) saved FROM notes n JOIN users u ON u.id=n.user_id WHERE {' AND '.join(clauses)} ORDER BY {order}",(user['id'],user['id'],*args)).fetchall()
            result=[]
            for n in rows:result.append({'id':n['id'],'title':n['title'],'grade':n['grade'],'subject':n['subject'],'topic':n['topic'],'description':n['description'],'author':n['name'],'authorId':n['author_id'],'initials':''.join(x[0] for x in n['name'].split()[:2]).upper(),'created':n['created'],'likes':n['likes'],'comments':n['comments'],'liked':bool(n['liked']),'saved':bool(n['saved']),'fileName':n['file_name'],'fileType':n['file_type'],'fileUrl':('/uploads/'+Path(n['file_path']).name) if n['file_path'] else ''})
            self.respond({'notes':result});return
        if path=='/api/trending':
            self.require_user(db); self.respond({'topics':[dict(r) for r in db.execute("SELECT topic,subject,COUNT(*) count FROM notes WHERE status='published' GROUP BY topic,subject ORDER BY count DESC LIMIT 5")]});return
        if path=='/api/stats':
            self.require_user(db);stats=db.execute("SELECT (SELECT COUNT(*) FROM notes WHERE status='published') notes,(SELECT COUNT(DISTINCT grade) FROM notes WHERE status='published') classes,(SELECT COUNT(*) FROM users WHERE role='student') students").fetchone();self.respond(dict(stats));return
        if path=='/api/people':
            self.require_user(db); rows=db.execute("SELECT u.id,u.name,(SELECT COUNT(*) FROM follows f WHERE f.followed_id=u.id) followers,EXISTS(SELECT 1 FROM follows f WHERE f.follower_id=? AND f.followed_id=u.id) following FROM users u WHERE u.role='student' AND u.id<>? ORDER BY followers DESC,u.created DESC LIMIT 8",(user['id'],user['id'])).fetchall();self.respond({'people':[{'id':r['id'],'name':r['name'],'initials':''.join(x[0] for x in r['name'].split()[:2]).upper(),'followers':r['followers'],'following':bool(r['following'])} for r in rows]});return
        if path=='/api/notifications':
            user=self.require_user(db);rows=db.execute('SELECT id,message,href,read,created FROM notifications WHERE user_id=? ORDER BY id DESC LIMIT 30',(user['id'],)).fetchall();self.respond({'notifications':[dict(r) for r in rows]});return
        if path=='/api/admin/reviews':
            self.require_admin(db); rows=db.execute("SELECT n.*,u.name,(SELECT title FROM notes d WHERE d.id=n.duplicate_of) duplicate_title FROM notes n JOIN users u ON u.id=n.user_id WHERE n.status='pending' ORDER BY n.created").fetchall();self.respond({'reviews':[dict(r) for r in rows]});return
        match=re.fullmatch(r'/api/notes/(\d+)/comments',path)
        if match:
            self.require_user(db); note_id=int(match.group(1));rows=db.execute('SELECT c.id,c.body,c.created,u.name FROM comments c JOIN users u ON u.id=c.user_id WHERE c.note_id=? ORDER BY c.id',(note_id,)).fetchall();self.respond({'comments':[{'id':r['id'],'body':r['body'],'created':r['created'],'author':r['name']} for r in rows]});return
        self.respond({'error':'Not found.'},404)
    def do_POST(self): self.mutate()
    def do_PUT(self): self.mutate()
    def do_DELETE(self): self.mutate()
    def mutate(self):
        path=urlparse(self.path).path;method=self.command
        try:
            data=self.body()
            with connect() as db:self.api_mutate(path,method,data,db)
        except ApiError as e:self.respond({'error':e.message},e.status)
        except (sqlite3.IntegrityError,ValueError) as e:self.respond({'error':'That request could not be saved.'},400)
    def api_mutate(self,path,method,data,db):
        if path=='/api/register' and method=='POST':
            name=clean(data.get('name'),60);email=clean(data.get('email'),254).lower();password=str(data.get('password') or '')
            if len(name)<2 or not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+',email):fail('Enter your name and a valid email address.')
            if len(password)<10:fail('Use a password with at least 10 characters.')
            salt=secrets.token_bytes(16); digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,310000);cur=db.execute('INSERT INTO users(name,email,salt,password_hash) VALUES(?,?,?,?)',(name,email,salt,digest));db.commit();self.make_session(cur.lastrowid);self.respond({'user':public_user(db.execute('SELECT * FROM users WHERE id=?',(cur.lastrowid,)).fetchone())},201);return
        if path=='/api/login' and method=='POST':
            email=clean(data.get('email'),254).lower();row=db.execute('SELECT * FROM users WHERE email=?',(email,)).fetchone();candidate=hashlib.pbkdf2_hmac('sha256',str(data.get('password') or '').encode(),row['salt'] if row else b'notesly-invalid-salt',310000)
            if not row or not hmac.compare_digest(candidate,row['password_hash']):fail('Email or password is incorrect.',401)
            self.make_session(row['id']);self.respond({'user':public_user(row)});return
        if path=='/api/logout' and method=='POST':
            jar=cookies.SimpleCookie(self.headers.get('Cookie',''));m=jar.get('notesly_session')
            if m:db.execute('DELETE FROM sessions WHERE token_hash=?',(hashlib.sha256(m.value.encode()).hexdigest(),))
            self.respond({'ok':True},headers={'Set-Cookie':'notesly_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'});return
        user=self.require_user(db)
        if path=='/api/notes' and method=='POST':
            title=clean(data.get('title'),90);grade=clean(data.get('grade'),40);subject=clean(data.get('subject'),60);topic=clean(data.get('topic'),60);description=clean(data.get('description'),500)
            if len(title)<4 or not grade or not subject:fail('Add a title, class, and subject.')
            filename='';stored='';mime=''
            upload=data.get('file')
            if upload:
                mime=str(upload.get('type','')).lower();filename=Path(clean(upload.get('name'),180)).name; raw=str(upload.get('data',''))
                if mime not in ('image/jpeg','image/png','image/webp','image/gif','application/pdf'):fail('Upload a JPG, PNG, WebP, GIF, or PDF.')
                if not raw.startswith('data:'+mime+';base64,'):fail('The selected file could not be read.')
                try:blob=base64.b64decode(raw.split(',',1)[1],validate=True)
                except Exception:fail('The selected file is not valid.')
                if not blob or len(blob)>10*1024*1024:fail('Files must be smaller than 10 MB.')
                ext={'image/jpeg':'jpg','image/png':'png','image/webp':'webp','image/gif':'gif','application/pdf':'pdf'}[mime];stored=secrets.token_hex(16)+'.'+ext;(UPLOADS/stored).write_bytes(blob)
            duplicate=title_match(title,subject,grade,db);cur=db.execute("INSERT INTO notes(user_id,title,grade,subject,topic,description,file_name,file_path,file_type,status,duplicate_of) VALUES(?,?,?,?,?,?,?,?,?,'pending',?)",(user['id'],title,grade,subject,topic,description,filename,stored,mime,duplicate));db.execute('INSERT INTO notifications(user_id,message,href) VALUES(?,?,?)',(user['id'],'Your note was submitted and is waiting for a review.','#review'));self.respond({'id':cur.lastrowid,'duplicate':bool(duplicate)},201);return
        match=re.fullmatch(r'/api/notes/(\d+)/(like|save|comments)',path)
        if match:
            note_id=int(match.group(1));action=match.group(2)
            if not db.execute("SELECT id FROM notes WHERE id=? AND status='published'",(note_id,)).fetchone():fail('Note not found.',404)
            if action in ('like','save'):
                table='likes' if action=='like' else 'saves';found=db.execute(f'SELECT 1 FROM {table} WHERE user_id=? AND note_id=?',(user['id'],note_id)).fetchone()
                if found:db.execute(f'DELETE FROM {table} WHERE user_id=? AND note_id=?',(user['id'],note_id));active=False
                else:db.execute(f'INSERT INTO {table}(user_id,note_id) VALUES(?,?)',(user['id'],note_id));active=True
                if action=='like':db.execute('UPDATE notes SET likes=(SELECT COUNT(*) FROM likes WHERE note_id=?) WHERE id=?',(note_id,note_id))
                self.respond({'active':active,'count':db.execute('SELECT likes FROM notes WHERE id=?',(note_id,)).fetchone()['likes']});return
            body=clean(data.get('body'),500)
            if len(body)<1:fail('Write a comment first.')
            cur=db.execute('INSERT INTO comments(user_id,note_id,body) VALUES(?,?,?)',(user['id'],note_id,body));owner=db.execute('SELECT user_id FROM notes WHERE id=?',(note_id,)).fetchone()['user_id']
            if owner!=user['id']:db.execute('INSERT INTO notifications(user_id,message,href) VALUES(?,?,?)',(owner,f"{user['name']} commented on your note: {title if (title:=db.execute('SELECT title FROM notes WHERE id=?',(note_id,)).fetchone()['title']) else 'your note'}",f'#note-{note_id}'))
            self.respond({'id':cur.lastrowid,'body':body,'author':user['name']},201);return
        match=re.fullmatch(r'/api/people/(\d+)/follow',path)
        if match:
            target=int(match.group(1))
            if target==user['id']:fail('You cannot follow yourself.')
            if not db.execute('SELECT id FROM users WHERE id=?',(target,)).fetchone():fail('Student not found.',404)
            found=db.execute('SELECT 1 FROM follows WHERE follower_id=? AND followed_id=?',(user['id'],target)).fetchone()
            if found:db.execute('DELETE FROM follows WHERE follower_id=? AND followed_id=?',(user['id'],target));active=False
            else:db.execute('INSERT INTO follows(follower_id,followed_id) VALUES(?,?)',(user['id'],target));active=True
            self.respond({'following':active});return
        if path=='/api/notifications/read' and method=='POST':db.execute('UPDATE notifications SET read=1 WHERE user_id=?',(user['id'],));self.respond({'ok':True});return
        match=re.fullmatch(r'/api/admin/reviews/(\d+)',path)
        if match and method=='PUT':
            self.require_admin(db);note_id=int(match.group(1));action=data.get('action')
            if action not in ('approve','decline'):fail('Choose approve or decline.')
            row=db.execute("SELECT * FROM notes WHERE id=? AND status='pending'",(note_id,)).fetchone()
            if not row:fail('Review item not found.',404)
            db.execute('UPDATE notes SET status=? WHERE id=?',('published' if action=='approve' else 'declined',note_id));db.execute('INSERT INTO notifications(user_id,message,href) VALUES(?,?,?)',(row['user_id'],'Your note was approved and published.' if action=='approve' else 'Your note was not approved for the community feed.',f'#note-{note_id}'));self.respond({'ok':True});return
        if path=='/api/profile' and method=='DELETE':
            confirm=str(data.get('password') or '');row=db.execute('SELECT * FROM users WHERE id=?',(user['id'],)).fetchone();candidate=hashlib.pbkdf2_hmac('sha256',confirm.encode(),row['salt'],310000)
            if not hmac.compare_digest(candidate,row['password_hash']):fail('Password did not match.',401)
            files=[r['file_path'] for r in db.execute('SELECT file_path FROM notes WHERE user_id=? AND file_path<>\'\'',(user['id'],))];db.execute('DELETE FROM comments WHERE user_id=?',(user['id'],));db.execute('DELETE FROM notes WHERE user_id=?',(user['id'],));db.execute('DELETE FROM users WHERE id=?',(user['id'],))
            for name in files:
                try:(UPLOADS/name).unlink(missing_ok=True)
                except OSError:pass
            self.respond({'ok':True},headers={'Set-Cookie':'notesly_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0'});return
        fail('Not found.',404)
    def make_session(self,user_id):
        token=secrets.token_urlsafe(36);digest=hashlib.sha256(token.encode()).hexdigest()
        with connect() as db:db.execute('INSERT INTO sessions(token_hash,user_id,expires) VALUES(?,?,?)',(digest,user_id,int(time.time())+60*60*24*30))
        secure='; Secure' if os.environ.get('NOTESLY_COOKIE_SECURE')=='1' else ''
        self._session_cookie='notesly_session='+token+'; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000'+secure
        original=self.respond
        def with_cookie(data,status=200,headers=None):
            headers=dict(headers or {});headers['Set-Cookie']=self._session_cookie;original(data,status,headers)
        self.respond=with_cookie

initialize()
print(f'Notesly running at http://{HOST}:{PORT}  (database: {DB})',flush=True)
ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
