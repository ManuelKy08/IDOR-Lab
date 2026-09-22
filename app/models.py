import os
import sqlite3
import threading
import time
from contextlib import contextmanager

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'database', 'lab.db')

FLAG = 'IDOR-LAB{Flag_IDOR_Horizontal_Vertical_Bypass_2217}'

_db_lock = threading.Lock()

# profil in-memory (respawn tiap restart)
USERS = [
    {'id': 1, 'username': 'admin', 'role': 'admin', 'email': 'admin@bank.test',
     'phone': '0812-0000-0001', 'password': 'adm!n2026', 'flag': FLAG},
    {'id': 2, 'username': 'victim', 'role': 'user', 'email': 'victim@bank.test',
     'phone': '0812-7777-8888', 'password': 'victimpass', 'flag': ''},
    {'id': 3, 'username': 'attacker', 'role': 'user', 'email': 'attacker@evil.com',
     'phone': '0812-9999-0000', 'password': 'atkpass', 'flag': ''},
]

SESSION_USER = 3  # attacker login


def reset_users():
    global USERS
    USERS = [
        {'id': 1, 'username': 'admin', 'role': 'admin', 'email': 'admin@bank.test',
         'phone': '0812-0000-0001', 'password': 'adm!n2026', 'flag': FLAG},
        {'id': 2, 'username': 'victim', 'role': 'user', 'email': 'victim@bank.test',
         'phone': '0812-7777-8888', 'password': 'victimpass', 'flag': ''},
        {'id': 3, 'username': 'attacker', 'role': 'user', 'email': 'attacker@evil.com',
         'phone': '0812-9999-0000', 'password': 'atkpass', 'flag': ''},
    ]
    globals()['SESSION_USER'] = 3


def find_user(uuid):
    for u in USERS:
        if u['id'] == uuid:
            return u
    return None


@contextmanager
def conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    c = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=10)
    c.row_factory = sqlite3.Row
    try:
        yield c
        c.commit()
    finally:
        c.close()


def init_db():
    with _db_lock, conn() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS settings(
          key TEXT PRIMARY KEY,
          vulnerable INTEGER DEFAULT 1
        );
        CREATE TABLE IF NOT EXISTS logs(
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          ts TEXT,
          source TEXT,
          msg TEXT
        );
        ''')


def seed():
    init_db()
    with _db_lock, conn() as c:
        if os.environ.get('LAB_RESET') == '1':
            c.execute('DELETE FROM settings')
        for k in ('s1', 's2', 's3', 's4'):
            c.execute('INSERT OR IGNORE INTO settings(key,vulnerable) VALUES(?,1)', (k,))


def setting(key):
    with _db_lock, conn() as c:
        row = c.execute('SELECT vulnerable FROM settings WHERE key=?', (key,)).fetchone()
        return row['vulnerable'] == 1 if row else True


def set_setting(key, vuln):
    with _db_lock, conn() as c:
        cur = c.execute('UPDATE settings SET vulnerable=? WHERE key=?', (1 if vuln else 0, key))
        if cur.rowcount == 0:
            c.execute('INSERT OR REPLACE INTO settings(key,vulnerable) VALUES(?,?)', (key, 1 if vuln else 0))


def all_settings():
    with _db_lock, conn() as c:
        rows = c.execute('SELECT key, vulnerable FROM settings').fetchall()
        return {r['key']: bool(r['vulnerable']) for r in rows}


def log(source, msg):
    with _db_lock, conn() as c:
        c.execute('INSERT INTO logs(ts,source,msg) VALUES(?,?,?)',
                  (time.strftime('%Y-%m-%d %H:%M:%S'), source, msg))


def last_logs(n=80):
    with _db_lock, conn() as c:
        rows = c.execute('SELECT ts,source,msg FROM logs ORDER BY id DESC LIMIT ?', (n,)).fetchall()
        return [{'ts': r['ts'], 'source': r['source'], 'msg': r['msg']} for r in rows]