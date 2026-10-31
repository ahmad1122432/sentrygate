"""SQLite event store."""
import os, sqlite3, threading, time

_lock = threading.Lock()
_db = sqlite3.connect(os.getenv("SENTRY_DB", "sentry.db"), check_same_thread=False)
_db.row_factory = sqlite3.Row
_db.execute("""CREATE TABLE IF NOT EXISTS events(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, ip TEXT, method TEXT, path TEXT,
    action TEXT, rule_id TEXT, rule_name TEXT, owasp TEXT, severity TEXT, score REAL, detail TEXT)""")
_db.commit()


def log(ip, method, path, action, f, score):
    f = f or {}
    with _lock:
        cur = _db.execute(
            "INSERT INTO events(ts,ip,method,path,action,rule_id,rule_name,owasp,severity,score,detail) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), ip, method, path[:300], action, f.get("id"), f.get("name"),
             f.get("owasp"), f.get("severity"), score, f.get("detail")))
        _db.commit()
        return cur.lastrowid


def recent(n=50, only_threats=False):
    q = "SELECT * FROM events " + ("WHERE action!='allowed' " if only_threats else "") + "ORDER BY id DESC LIMIT ?"
    with _lock:
        return [dict(r) for r in _db.execute(q, (n,))]


def stats():
    with _lock:
        one = lambda q: [dict(r) for r in _db.execute(q)]
        total = _db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        by_action = {r["action"]: r["c"] for r in _db.execute("SELECT action, COUNT(*) c FROM events GROUP BY action")}
        return {
            "total": total, "by_action": by_action,
            "top_rules": one("SELECT rule_id, rule_name, COUNT(*) c FROM events WHERE rule_id IS NOT NULL GROUP BY rule_id ORDER BY c DESC LIMIT 5"),
            "top_paths": one("SELECT path, COUNT(*) c FROM events WHERE action!='allowed' GROUP BY path ORDER BY c DESC LIMIT 5"),
            "top_ips": one("SELECT ip, COUNT(*) c FROM events WHERE action!='allowed' GROUP BY ip ORDER BY c DESC LIMIT 5"),
        }
