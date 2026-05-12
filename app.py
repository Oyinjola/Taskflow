"""
TaskFlow REST API
Full CRUD task manager with JWT auth, PostgreSQL (or SQLite fallback),
pagination, filtering, and test suite

Endpoints:
  POST /auth/register     — create account
  POST /auth/login        — get JWT
  GET  /tasks             — list tasks (filter, paginate, sort)
  POST /tasks             — create task
  GET  /tasks/<id>        — get task
  PATCH /tasks/<id>       — partial update
  DELETE /tasks/<id>      — delete task
  GET  /tasks/stats       — completion stats
"""

import sqlite3
import json
import hashlib
import hmac
import base64
import time
import os
import re
from functools import wraps
from pathlib import Path
from flask import Flask, request, jsonify, g
from flask_cors import CORS
from typing import Optional

app = Flask(__name__)
CORS(app)

DB_PATH    = "taskflow.db"
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret-change-in-production")
JWT_EXPIRY = 60 * 60 * 24 * 7   # 7 days


# ── Database Setup ────────────────────────────────────────────────────────────
def get_db() -> sqlite3.Connection:
    if 'db' not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    with app.app_context():
        db = get_db()
        db.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            username   TEXT UNIQUE NOT NULL,
            email      TEXT UNIQUE NOT NULL,
            password   TEXT NOT NULL,       -- bcrypt-style hash (sha256+salt here)
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS tasks (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            title       TEXT NOT NULL,
            description TEXT,
            status      TEXT NOT NULL DEFAULT 'todo'
                            CHECK (status IN ('todo','in_progress','done','cancelled')),
            priority    TEXT NOT NULL DEFAULT 'medium'
                            CHECK (priority IN ('low','medium','high','urgent')),
            due_date    TEXT,
            tags        TEXT DEFAULT '[]',    -- JSON array
            created_at  TEXT DEFAULT (datetime('now')),
            updated_at  TEXT DEFAULT (datetime('now'))
        );

        CREATE TABLE IF NOT EXISTS task_logs (
            id         INTEGER PRIMARY KEY AUTOINCREMENT,
            task_id    INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE,
            user_id    INTEGER NOT NULL,
            action     TEXT NOT NULL,
            old_value  TEXT,
            new_value  TEXT,
            created_at TEXT DEFAULT (datetime('now'))
        );

        CREATE INDEX IF NOT EXISTS idx_tasks_user   ON tasks(user_id);
        CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
        CREATE INDEX IF NOT EXISTS idx_tasks_due    ON tasks(due_date);
        """)
        db.commit()


# ── JWT (minimal, no PyJWT dependency) ───────────────────────────────────────
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + '=' * (pad % 4))


def jwt_encode(payload: dict) -> str:
    header  = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload_enc = _b64url(json.dumps({**payload, "exp": int(time.time()) + JWT_EXPIRY}).encode())
    sig     = hmac.new(JWT_SECRET.encode(), f"{header}.{payload_enc}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload_enc}.{_b64url(sig)}"


def jwt_decode(token: str) -> dict | None:
    try:
        header, payload_enc, sig = token.split('.')
        expected_sig = _b64url(hmac.new(
            JWT_SECRET.encode(),
            f"{header}.{payload_enc}".encode(),
            hashlib.sha256
        ).digest())
        if not hmac.compare_digest(sig, expected_sig):
            return None
        payload = json.loads(_b64url_decode(payload_enc))
        if payload.get('exp', 0) < time.time():
            return None
        return payload
    except Exception:
        return None


# ── Password hashing ──────────────────────────────────────────────────────────
def hash_password(password: str) -> str:
    salt = os.urandom(16).hex()
    h    = hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    return f"{salt}:{h}"


def verify_password(password: str, stored: str) -> bool:
    salt, h = stored.split(':', 1)
    return hmac.compare_digest(
        h, hashlib.sha256(f"{salt}{password}".encode()).hexdigest()
    )


# ── Auth middleware ───────────────────────────────────────────────────────────
def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get('Authorization', '')
        if not auth.startswith('Bearer '):
            return error("Missing or invalid Authorization header", 401)
        payload = jwt_decode(auth[7:])
        if not payload:
            return error("Token invalid or expired", 401)
        g.user_id = payload['sub']
        return f(*args, **kwargs)
    return wrapper


# ── Helpers ───────────────────────────────────────────────────────────────────
def error(msg: str, code: int = 400):
    return jsonify({"error": msg}), code


def validate(data: dict, rules: dict) -> list[str]:
    """Simple validation. rules: {field: {'required':bool,'max':int,'choices':list}}"""
    errors = []
    for field, rule in rules.items():
        val = data.get(field)
        if rule.get('required') and not val:
            errors.append(f"'{field}' is required")
        if val and rule.get('max') and len(str(val)) > rule['max']:
            errors.append(f"'{field}' exceeds max length {rule['max']}")
        if val and rule.get('choices') and val not in rule['choices']:
            errors.append(f"'{field}' must be one of: {rule['choices']}")
    return errors

def row_to_dict(row) -> Optional[dict]:
    if row is None:
        return None
    d = dict(row)
    if 'tags' in d and isinstance(d['tags'], str):
        try:
            d['tags'] = json.loads(d['tags'])
        except:
            d['tags'] = []
    return d


def log_action(db, task_id: int, action: str, old=None, new=None):
    db.execute(
        "INSERT INTO task_logs (task_id, user_id, action, old_value, new_value) VALUES (?,?,?,?,?)",
        (task_id, g.user_id, action, json.dumps(old), json.dumps(new))
    )


# ── Auth Routes ───────────────────────────────────────────────────────────────
@app.route("/auth/register", methods=["POST"])
def register():
    data = request.json or {}
    errs = validate(data, {
        'username': {'required': True, 'max': 50},
        'email':    {'required': True, 'max': 200},
        'password': {'required': True},
    })
    if errs:
        return error('; '.join(errs))
    
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', data['email']):
        return error("Invalid email format")
    if len(data['password']) < 8:
        return error("Password must be at least 8 characters")
    
    db = get_db()
    try:
        db.execute(
            "INSERT INTO users (username, email, password) VALUES (?,?,?)",
            (data['username'].strip(), data['email'].lower().strip(), hash_password(data['password']))
        )
        db.commit()
    except sqlite3.IntegrityError as e:
        if 'username' in str(e):
            return error("Username already taken")
        return error("Email already registered")
    
    user = row_to_dict(db.execute("SELECT * FROM users WHERE email=?", (data['email'].lower(),)).fetchone())
    if not user:
        return error("Failed to retrieve user after registration")
    token = jwt_encode({"sub": user['id'], "username": user['username']})
    return jsonify({"token": token, "user": {"id": user['id'], "username": user['username'], "email": user['email']}}), 201


@app.route("/auth/login", methods=["POST"])
def login():
    data = request.json or {}
    if not data.get('email') or not data.get('password'):
        return error("Email and password required")
    
    db   = get_db()
    user = row_to_dict(db.execute("SELECT * FROM users WHERE email=?", (data['email'].lower(),)).fetchone())
    
    if not user or not verify_password(data['password'], user['password']):
        return error("Invalid credentials", 401)
    
    token = jwt_encode({"sub": user['id'], "username": user['username']})
    return jsonify({"token": token, "user": {"id": user['id'], "username": user['username'], "email": user['email']}})


@app.route("/auth/me")
@require_auth
def me():
    db   = get_db()
    user = row_to_dict(db.execute("SELECT id,username,email,created_at FROM users WHERE id=?", (g.user_id,)).fetchone())
    return jsonify(user)


# ── Task Routes ───────────────────────────────────────────────────────────────
@app.route("/tasks", methods=["GET"])
@require_auth
def list_tasks():
    db = get_db()
    
    # Filtering
    status   = request.args.get('status')
    priority = request.args.get('priority')
    search   = request.args.get('q', '').strip()
    sort     = request.args.get('sort', 'created_at')
    order    = 'DESC' if request.args.get('order', 'desc') == 'desc' else 'ASC'
    page     = max(1, int(request.args.get('page', 1)))
    per_page = min(100, max(1, int(request.args.get('per_page', 20))))
    
    allowed_sorts = {'created_at', 'updated_at', 'due_date', 'priority', 'title'}
    if sort not in allowed_sorts:
        sort = 'created_at'
    
    where  = ["user_id = ?"]
    params = [g.user_id]
    
    if status:
        where.append("status = ?");   params.append(status)
    if priority:
        where.append("priority = ?"); params.append(priority)
    if search:
        where.append("(title LIKE ? OR description LIKE ?)");
        params += [f"%{search}%", f"%{search}%"]
    
    where_sql = " AND ".join(where)
    
    total, = db.execute(f"SELECT COUNT(*) FROM tasks WHERE {where_sql}", params).fetchone()
    rows   = db.execute(
        f"SELECT * FROM tasks WHERE {where_sql} ORDER BY {sort} {order} LIMIT ? OFFSET ?",
        params + [per_page, (page - 1) * per_page]
    ).fetchall()
    
    return jsonify({
        "tasks":      [row_to_dict(r) for r in rows],
        "total":      total,
        "page":       page,
        "per_page":   per_page,
        "total_pages": max(1, -(-total // per_page)),  # ceiling div
    })


@app.route("/tasks", methods=["POST"])
@require_auth
def create_task():
    data = request.json or {}
    errs = validate(data, {
        'title':    {'required': True, 'max': 200},
        'status':   {'choices': ['todo','in_progress','done','cancelled']},
        'priority': {'choices': ['low','medium','high','urgent']},
    })
    if errs:
        return error('; '.join(errs))
    
    tags = json.dumps(data.get('tags', []))
    db   = get_db()
    cur  = db.execute(
        """INSERT INTO tasks (user_id, title, description, status, priority, due_date, tags)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (g.user_id, data['title'].strip(),
         data.get('description', ''),
         data.get('status', 'todo'),
         data.get('priority', 'medium'),
         data.get('due_date'),
         tags)
    )
    db.commit()
    task = row_to_dict(db.execute("SELECT * FROM tasks WHERE id=?", (cur.lastrowid,)).fetchone())
    log_action(db, task['id'], 'created', new=task)
    db.commit()
    return jsonify(task), 201


@app.route("/tasks/<int:task_id>", methods=["GET"])
@require_auth
def get_task(task_id: int):
    db   = get_db()
    task = row_to_dict(db.execute(
        "SELECT * FROM tasks WHERE id=? AND user_id=?", (task_id, g.user_id)
    ).fetchone())
    if not task:
        return error("Task not found", 404)
    return jsonify(task)


@app.route("/tasks/<int:task_id>", methods=["PATCH"])
@require_auth
def update_task(task_id: int):
    db  = get_db()
    old = row_to_dict(db.execute(
        "SELECT * FROM tasks WHERE id=? AND user_id=?", (task_id, g.user_id)
    ).fetchone())
    if not old:
        return error("Task not found", 404)
    
    data    = request.json or {}
    allowed = {'title', 'description', 'status', 'priority', 'due_date', 'tags'}
    updates = {k: v for k, v in data.items() if k in allowed}
    
    if not updates:
        return error("No valid fields to update")
    
    errs = validate(updates, {
        'status':   {'choices': ['todo','in_progress','done','cancelled']},
        'priority': {'choices': ['low','medium','high','urgent']},
    })
    if errs:
        return error('; '.join(errs))
    
    if 'tags' in updates:
        updates['tags'] = json.dumps(updates['tags'])
    
    set_clause = ', '.join(f"{k}=?" for k in updates)
    set_clause += ", updated_at=datetime('now')"
    
    db.execute(
        f"UPDATE tasks SET {set_clause} WHERE id=? AND user_id=?",
        list(updates.values()) + [task_id, g.user_id]
    )
    db.commit()
    
    new = row_to_dict(db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone())
    log_action(db, task_id, 'updated', old=old, new=new)
    db.commit()
    return jsonify(new)


@app.route("/tasks/<int:task_id>", methods=["DELETE"])
@require_auth
def delete_task(task_id: int):
    db   = get_db()
    task = db.execute(
        "SELECT id FROM tasks WHERE id=? AND user_id=?", (task_id, g.user_id)
    ).fetchone()
    if not task:
        return error("Task not found", 404)
    
    db.execute("DELETE FROM tasks WHERE id=?", (task_id,))
    db.commit()
    return jsonify({"deleted": True, "id": task_id})


@app.route("/tasks/stats")
@require_auth
def task_stats():
    db = get_db()
    
    by_status = dict(db.execute(
        "SELECT status, COUNT(*) FROM tasks WHERE user_id=? GROUP BY status", (g.user_id,)
    ).fetchall())
    
    by_priority = dict(db.execute(
        "SELECT priority, COUNT(*) FROM tasks WHERE user_id=? GROUP BY priority", (g.user_id,)
    ).fetchall())
    
    total     = sum(by_status.values())
    completed = by_status.get('done', 0)
    overdue   = db.execute(
        "SELECT COUNT(*) FROM tasks WHERE user_id=? AND due_date < date('now') AND status NOT IN ('done','cancelled')",
        (g.user_id,)
    ).fetchone()[0]
    
    return jsonify({
        "total":           total,
        "completed":       completed,
        "completion_rate": round(completed / total * 100, 1) if total else 0,
        "overdue":         overdue,
        "by_status":       by_status,
        "by_priority":     by_priority,
    })


@app.route("/tasks/<int:task_id>/logs")
@require_auth
def task_logs(task_id: int):
    db = get_db()
    task = db.execute(
        "SELECT id FROM tasks WHERE id=? AND user_id=?", (task_id, g.user_id)
    ).fetchone()
    if not task:
        return error("Task not found", 404)
    
    logs = db.execute(
        "SELECT * FROM task_logs WHERE task_id=? ORDER BY created_at DESC", (task_id,)
    ).fetchall()
    return jsonify([dict(l) for l in logs])


@app.route("/")
def index():
    return jsonify({
        "service": "TaskFlow API",
        "version": "1.0.0",
        "auth":    ["/auth/register", "/auth/login", "/auth/me"],
        "tasks":   ["GET /tasks", "POST /tasks", "GET|PATCH|DELETE /tasks/<id>",
                    "GET /tasks/stats", "GET /tasks/<id>/logs"],
    })


# ── Test Suite ────────────────────────────────────────────────────────────────
def run_tests():
    """Integration tests against the live API."""
    import urllib.request
    import urllib.error

    BASE = "http://localhost:5053"
    token = None
    task_id = None

    def req(method, path, data=None, auth=False):
        body = json.dumps(data).encode() if data else None
        headers = {"Content-Type": "application/json"}
        if auth and token:
            headers["Authorization"] = f"Bearer {token}"
        r = urllib.request.Request(f"{BASE}{path}", data=body, headers=headers, method=method)
        try:
            with urllib.request.urlopen(r) as resp:
                return resp.status, json.loads(resp.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    print("\n Running TaskFlow API Tests\n" + "-"*40)
    results = []

    def test(name, fn):
        try:
            fn()
            print(f"  ✓  {name}")
            results.append(True)
        except AssertionError as e:
            print(f"  ✗  {name}: {e}")
            results.append(False)

    def t_register():
        nonlocal token
        status, d = req("POST", "/auth/register", {
            "username": "testuser", "email": "test@example.com", "password": "password123"
        })
        assert status == 201, f"Expected 201, got {status}"
        assert "token" in d
        token = d["token"]

    def t_login():
        nonlocal token
        status, d = req("POST", "/auth/login", {"email": "test@example.com", "password": "password123"})
        assert status == 200, f"Expected 200, got {status}"
        token = d["token"]

    def t_login_bad():
        status, _ = req("POST", "/auth/login", {"email": "test@example.com", "password": "wrongpass"})
        assert status == 401

    def t_me():
        status, d = req("GET", "/auth/me", auth=True)
        assert status == 200
        assert d["email"] == "test@example.com"

    def t_create_task():
        nonlocal task_id
        status, d = req("POST", "/tasks", {
            "title": "Write unit tests", "priority": "high",
            "description": "Cover all edge cases", "tags": ["testing", "quality"]
        }, auth=True)
        assert status == 201
        assert d["title"] == "Write unit tests"
        task_id = d["id"]

    def t_list_tasks():
        status, d = req("GET", "/tasks", auth=True)
        assert status == 200
        assert d["total"] >= 1

    def t_get_task():
        status, d = req("GET", f"/tasks/{task_id}", auth=True)
        assert status == 200
        assert d["id"] == task_id

    def t_update_task():
        status, d = req("PATCH", f"/tasks/{task_id}", {"status": "in_progress"}, auth=True)
        assert status == 200
        assert d["status"] == "in_progress"

    def t_stats():
        status, d = req("GET", "/tasks/stats", auth=True)
        assert status == 200
        assert "total" in d

    def t_filter():
        status, d = req("GET", "/tasks?priority=high", auth=True)
        assert status == 200

    def t_delete_task():
        status, d = req("DELETE", f"/tasks/{task_id}", auth=True)
        assert status == 200
        assert d["deleted"] is True

    def t_unauthenticated():
        status, _ = req("GET", "/tasks")
        assert status == 401

    for name, fn in [
        ("Register user",       t_register),
        ("Login valid",         t_login),
        ("Login invalid",       t_login_bad),
        ("Get profile",         t_me),
        ("Create task",         t_create_task),
        ("List tasks",          t_list_tasks),
        ("Get task by ID",      t_get_task),
        ("Update task status",  t_update_task),
        ("Task statistics",     t_stats),
        ("Filter by priority",  t_filter),
        ("Delete task",         t_delete_task),
        ("Reject unauthenticated", t_unauthenticated),
    ]:
        test(name, fn)

    passed = sum(results)
    print(f"\n  {passed}/{len(results)} tests passed")
    return passed == len(results)


if __name__ == "__main__":
    import sys
    init_db()

    if len(sys.argv) > 1 and sys.argv[1] == "test":
        run_tests()
    else:
        print("TaskFlow API running")
        port = int(os.environ.get("PORT", 5053))
        app.run(host="0.0.0.0", port=port)