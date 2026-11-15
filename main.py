import os, sqlite3, time, uuid, hashlib, secrets, jwt
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Form, Header, Query, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from google.oauth2 import id_token as gid
from google.auth.transport import requests as greq

DIR = os.path.dirname(os.path.abspath(__file__))
SECRET = os.getenv("SECRET_KEY", "change-me-in-production")
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID", "")
DB = os.getenv("DB_PATH", os.path.join(DIR, "app.db"))
UP = os.path.join(DIR, "uploads")
os.makedirs(UP, exist_ok=True)
app = FastAPI()


def q(sql, a=(), one=False, commit=False):
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    cur = c.execute(sql, a)
    if commit:
        c.commit()
        r = cur.lastrowid
    else:
        rows = [dict(x) for x in cur.fetchall()]
        r = (rows[0] if rows else None) if one else rows
    c.close()
    return r


for s in [
    "CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, username TEXT UNIQUE, pw TEXT, name TEXT, bio TEXT DEFAULT '', avatar TEXT DEFAULT '', private INT DEFAULT 0)",
    "CREATE TABLE IF NOT EXISTS follows(follower INT, followee INT, PRIMARY KEY(follower, followee))",
    "CREATE TABLE IF NOT EXISTS posts(id INTEGER PRIMARY KEY, user_id INT, text TEXT, media TEXT, kind TEXT, created REAL)",
    "CREATE TABLE IF NOT EXISTS likes(user_id INT, post_id INT, PRIMARY KEY(user_id, post_id))",
    "CREATE TABLE IF NOT EXISTS stories(id INTEGER PRIMARY KEY, user_id INT, text TEXT, media TEXT, created REAL)",
    "CREATE TABLE IF NOT EXISTS messages(id INTEGER PRIMARY KEY, sender INT, receiver INT, text TEXT, created REAL)",
]:
    q(s, commit=True)
for col in ("google_sub TEXT", "email TEXT"):
    try:
        q(f"ALTER TABLE users ADD COLUMN {col}", commit=True)
    except Exception:
        pass


# ---------- auth ----------
def hash_pw(p, salt=None):
    salt = salt or secrets.token_hex(8)
    return salt + "$" + hashlib.pbkdf2_hmac("sha256", p.encode(), salt.encode(), 100000).hex()


def check_pw(p, h):
    if not h:
        return False
    return secrets.compare_digest(hash_pw(p, h.split("$")[0]), h)


def make_token(uid):
    return jwt.encode({"uid": uid, "exp": int(time.time()) + 30 * 86400}, SECRET, "HS256")


def user_from(t):
    try:
        uid = jwt.decode(t, SECRET, ["HS256"])["uid"]
    except Exception:
        raise HTTPException(401, "غير مسجّل")
    u = q("SELECT * FROM users WHERE id=?", (uid,), one=True)
    if not u:
        raise HTTPException(401, "غير مسجّل")
    return u


def me(authorization: str = Header("")):
    return user_from(authorization.replace("Bearer ", ""))


def pub(u):
    return {k: u[k] for k in ("id", "username", "name", "bio", "avatar", "private")}


class Auth(BaseModel):
    username: str
    password: str
    name: str = ""


@app.post("/api/register")
def register(a: Auth):
    u = a.username.strip().lower()
    if not (3 <= len(u) <= 20) or not u.replace("_", "").isalnum() or len(a.password) < 6:
        raise HTTPException(400, "اسم المستخدم 3-20 حرف/رقم وكلمة السر 6 على الأقل")
    if q("SELECT 1 FROM users WHERE username=?", (u,), one=True):
        raise HTTPException(400, "اسم المستخدم مستخدم")
    uid = q("INSERT INTO users(username,pw,name) VALUES(?,?,?)", (u, hash_pw(a.password), a.name.strip()[:40] or u), commit=True)
    return {"token": make_token(uid)}


@app.post("/api/login")
def login(a: Auth):
    u = q("SELECT * FROM users WHERE username=?", (a.username.strip().lower(),), one=True)
    if not u or not check_pw(a.password, u["pw"]):
        raise HTTPException(400, "بيانات الدخول غلط")
    return {"token": make_token(u["id"])}


class G(BaseModel):
    credential: str


@app.get("/api/config")
def config():
    return {"google_client_id": GOOGLE_CLIENT_ID}


@app.post("/api/google")
def google_login(g: G):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(400, "تسجيل قوقل غير مفعّل")
    try:
        info = gid.verify_oauth2_token(g.credential, greq.Request(), GOOGLE_CLIENT_ID)
    except Exception:
        raise HTTPException(400, "فشل التحقق من حساب قوقل")
    if not info.get("email_verified"):
        raise HTTPException(400, "البريد غير مؤكد")
    sub, email = info["sub"], info["email"].lower()
    u = q("SELECT * FROM users WHERE google_sub=?", (sub,), one=True)
    if u:
        return {"token": make_token(u["id"])}
    base = "".join(c for c in email.split("@")[0].lower() if c.isalnum() or c == "_")[:16] or "user"
    name, n = base, 1
    while q("SELECT 1 FROM users WHERE username=?", (name,), one=True):
        n += 1
        name = f"{base}{n}"
    uid = q("INSERT INTO users(username,pw,name,avatar,google_sub,email) VALUES(?,?,?,?,?,?)",
            (name, "", (info.get("name") or name)[:40], info.get("picture", ""), sub, email), commit=True)
    return {"token": make_token(uid)}


# ---------- files ----------
async def save(f, kinds=("image", "video")):
    t = (f.content_type or "").split("/")[0]
    if t not in kinds:
        raise HTTPException(400, "نوع الملف غير مدعوم")
    data = await f.read()
    if len(data) > 50 * 1024 * 1024:
        raise HTTPException(400, "الملف أكبر من 50MB")
    name = uuid.uuid4().hex + os.path.splitext(f.filename or "")[1].lower()[:6]
    with open(os.path.join(UP, name), "wb") as fh:
        fh.write(data)
    return "/uploads/" + name, t


# ---------- profile ----------
class Prof(BaseModel):
    name: str = ""
    bio: str = ""
    private: bool = False


@app.get("/api/me")
def get_me(u=Depends(me)):
    return pub(u)


@app.put("/api/me")
def upd(p: Prof, u=Depends(me)):
    q("UPDATE users SET name=?,bio=?,private=? WHERE id=?", (p.name[:40], p.bio[:200], int(p.private), u["id"]), commit=True)
    return {"ok": 1}


@app.post("/api/avatar")
async def avatar(f: UploadFile = File(...), u=Depends(me)):
    url, _ = await save(f, ("image",))
    q("UPDATE users SET avatar=? WHERE id=?", (url, u["id"]), commit=True)
    return {"avatar": url}


def following(uid):
    return [r["followee"] for r in q("SELECT followee FROM follows WHERE follower=?", (uid,))]


def is_following(a, b):
    return bool(q("SELECT 1 FROM follows WHERE follower=? AND followee=?", (a, b), one=True))


@app.post("/api/follow/{username}")
def follow(username: str, u=Depends(me)):
    t = q("SELECT id FROM users WHERE username=?", (username,), one=True)
    if not t or t["id"] == u["id"]:
        raise HTTPException(400, "غير ممكن")
    if is_following(u["id"], t["id"]):
        q("DELETE FROM follows WHERE follower=? AND followee=?", (u["id"], t["id"]), commit=True)
    else:
        q("INSERT INTO follows VALUES(?,?)", (u["id"], t["id"]), commit=True)
    return {"ok": 1}


def decorate(rows, uid):
    for r in rows:
        r.update(q("SELECT username,name,avatar FROM users WHERE id=?", (r["user_id"],), one=True))
        r["likes"] = q("SELECT COUNT(*) c FROM likes WHERE post_id=?", (r["id"],), one=True)["c"]
        r["liked"] = bool(q("SELECT 1 FROM likes WHERE post_id=? AND user_id=?", (r["id"], uid), one=True))
    return rows


@app.get("/api/users/{username}")
def profile(username: str, u=Depends(me)):
    t = q("SELECT * FROM users WHERE username=?", (username,), one=True)
    if not t:
        raise HTTPException(404, "غير موجود")
    f = is_following(u["id"], t["id"])
    can = (not t["private"]) or f or t["id"] == u["id"]
    posts = decorate(q("SELECT * FROM posts WHERE user_id=? ORDER BY id DESC", (t["id"],)), u["id"]) if can else []
    return {
        **pub(t), "following": f, "can_view": can, "posts": posts,
        "followers": q("SELECT COUNT(*) c FROM follows WHERE followee=?", (t["id"],), one=True)["c"],
        "following_count": q("SELECT COUNT(*) c FROM follows WHERE follower=?", (t["id"],), one=True)["c"],
    }


@app.get("/api/search")
def search(term: str = Query("", alias="q"), u=Depends(me)):
    t = f"%{term}%"
    return q("SELECT username,name,avatar FROM users WHERE username LIKE ? OR name LIKE ? LIMIT 20", (t, t))


# ---------- posts / videos ----------
@app.post("/api/posts")
async def new_post(text: str = Form(""), f: UploadFile = File(None), u=Depends(me)):
    media, kind = "", "post"
    if f and f.filename:
        media, t = await save(f)
        kind = "video" if t == "video" else "post"
    if not text.strip() and not media:
        raise HTTPException(400, "المنشور فاضي")
    q("INSERT INTO posts(user_id,text,media,kind,created) VALUES(?,?,?,?,?)", (u["id"], text.strip()[:2000], media, kind, time.time()), commit=True)
    return {"ok": 1}


@app.get("/api/feed")
def feed(u=Depends(me)):
    ids = following(u["id"]) + [u["id"]]
    ph = ",".join("?" * len(ids))
    return decorate(q(f"SELECT * FROM posts WHERE kind='post' AND user_id IN ({ph}) ORDER BY id DESC LIMIT 50", ids), u["id"])


@app.get("/api/videos")
def videos(u=Depends(me)):
    rows = q("SELECT * FROM posts WHERE kind='video' AND user_id IN (SELECT id FROM users WHERE private=0) ORDER BY RANDOM() LIMIT 20")
    return decorate(rows, u["id"])


@app.post("/api/like/{pid}")
def like(pid: int, u=Depends(me)):
    if q("SELECT 1 FROM likes WHERE user_id=? AND post_id=?", (u["id"], pid), one=True):
        q("DELETE FROM likes WHERE user_id=? AND post_id=?", (u["id"], pid), commit=True)
    else:
        q("INSERT INTO likes VALUES(?,?)", (u["id"], pid), commit=True)
    return {"ok": 1}


# ---------- stories (24h) ----------
@app.post("/api/stories")
async def new_story(text: str = Form(""), f: UploadFile = File(None), u=Depends(me)):
    media = ""
    if f and f.filename:
        media, _ = await save(f)
    if not text.strip() and not media:
        raise HTTPException(400, "القصة فاضية")
    q("INSERT INTO stories(user_id,text,media,created) VALUES(?,?,?,?)", (u["id"], text.strip()[:300], media, time.time()), commit=True)
    return {"ok": 1}


@app.get("/api/stories")
def stories(u=Depends(me)):
    ids = following(u["id"]) + [u["id"]]
    ph = ",".join("?" * len(ids))
    return q(f"SELECT s.*, x.username, x.name FROM stories s JOIN users x ON x.id=s.user_id WHERE s.user_id IN ({ph}) AND s.created>? ORDER BY s.id", ids + [time.time() - 86400])


# ---------- chat ----------
@app.get("/api/chats")
def chats(u=Depends(me)):
    i = u["id"]
    rows = q("SELECT DISTINCT CASE WHEN sender=? THEN receiver ELSE sender END AS o FROM messages WHERE sender=? OR receiver=?", (i, i, i))
    return [q("SELECT username,name,avatar FROM users WHERE id=?", (r["o"],), one=True) for r in rows]


@app.get("/api/messages/{username}")
def msgs(username: str, u=Depends(me)):
    t = q("SELECT id FROM users WHERE username=?", (username,), one=True)
    if not t:
        raise HTTPException(404, "غير موجود")
    a, b = u["id"], t["id"]
    rows = q("SELECT * FROM messages WHERE (sender=? AND receiver=?) OR (sender=? AND receiver=?) ORDER BY id", (a, b, b, a))
    return [{"mine": r["sender"] == a, "text": r["text"]} for r in rows]


conns = {}


@app.websocket("/ws")
async def ws(sock: WebSocket, token: str):
    try:
        u = user_from(token)
    except HTTPException:
        await sock.close()
        return
    await sock.accept()
    conns.setdefault(u["id"], set()).add(sock)
    try:
        while True:
            d = await sock.receive_json()
            t = q("SELECT id FROM users WHERE username=?", (d.get("to"),), one=True)
            text = str(d.get("text", "")).strip()[:2000]
            if not t or not text:
                continue
            q("INSERT INTO messages(sender,receiver,text,created) VALUES(?,?,?,?)", (u["id"], t["id"], text, time.time()), commit=True)
            for s in list(conns.get(t["id"], [])):
                try:
                    await s.send_json({"from": u["username"], "text": text})
                except Exception:
                    conns[t["id"]].discard(s)
    except WebSocketDisconnect:
        pass
    finally:
        conns[u["id"]].discard(sock)


app.mount("/uploads", StaticFiles(directory=UP), name="uploads")


@app.get("/")
def index():
    return FileResponse(os.path.join(DIR, "static", "index.html"))
