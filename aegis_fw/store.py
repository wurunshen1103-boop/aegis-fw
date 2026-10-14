import json
import sqlite3
import time
from .core import canonical, digest, Denied, transition


class Store:
    """Each CLI operation holds a write transaction; budget reservations commit before I/O."""
    def __init__(self, path):
        self.db = sqlite3.connect(str(path), timeout=10)
        self.db.executescript('''
        PRAGMA journal_mode=WAL;
        PRAGMA synchronous=FULL;
        CREATE TABLE IF NOT EXISTS audit(seq INTEGER PRIMARY KEY, payload TEXT, hash TEXT);
        CREATE TABLE IF NOT EXISTS cases(id TEXT PRIMARY KEY, state TEXT, body TEXT);
        CREATE TABLE IF NOT EXISTS cache(key TEXT PRIMARY KEY, expires REAL, body TEXT);
        CREATE TABLE IF NOT EXISTS spend(day TEXT PRIMARY KEY, reserved REAL, calls INTEGER);
        ''')

    def audit(self, event, **details):
        self.db.execute('BEGIN IMMEDIATE')
        try:
            prev = self.db.execute('SELECT hash FROM audit ORDER BY seq DESC LIMIT 1').fetchone()
            body = canonical(dict(time=time.time(), event=event, details=details, previous=prev[0] if prev else ''))
            self.db.execute('INSERT INTO audit(payload,hash) VALUES (?,?)', (body, digest(body)))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def verify_audit(self):
        prev = ''
        for payload, h in self.db.execute('SELECT payload,hash FROM audit ORDER BY seq'):
            if digest(payload) != h or json.loads(payload)['previous'] != prev:
                raise Denied('audit chain broken')
            prev = h
        return prev

    def add(self, q):
        with self.db:
            self.db.execute('INSERT OR IGNORE INTO cases VALUES (?,?,?)', (q['id'], 'observe', canonical(q)))

    def move(self, case, new):
        with self.db:
            row = self.db.execute('SELECT state FROM cases WHERE id=?', (case,)).fetchone()
            if not row:
                raise Denied('unknown proposal')
            transition(row[0], new)
            self.db.execute('UPDATE cases SET state=? WHERE id=?', (new, case))
        self.audit('transition', case=case, old=row[0], new=new)

    def reserve(self, amount, budget, cap):
        day = time.strftime('%Y-%m-%d', time.gmtime())
        self.db.execute('BEGIN IMMEDIATE')
        try:
            row = self.db.execute('SELECT reserved,calls FROM spend WHERE day=?', (day,)).fetchone() or (0, 0)
            if row[0]+amount > budget or row[1] >= cap:
                raise Denied('daily model budget/call cap exhausted')
            self.db.execute('INSERT OR REPLACE INTO spend VALUES (?,?,?)', (day, row[0]+amount, row[1]+1))
            self.db.commit()
        except BaseException:
            self.db.rollback()
            raise

    def get_cache(self, key):
        row = self.db.execute('SELECT body FROM cache WHERE key=? AND expires>?', (key, time.time())).fetchone()
        return json.loads(row[0]) if row else None

    def put_cache(self, key, value):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO cache VALUES (?,?,?)', (key, time.time()+300, canonical(value)))
