"""Detection layer: request normalization, signature rules, anomaly score."""
import html, json, math, re
from collections import Counter
from urllib.parse import unquote_plus

# (id, name, OWASP category, severity, regex)
RULES = [
    ("SQLI-001", "SQL Injection (UNION SELECT)", "A03 Injection", "high", r"(?i)\bunion\b.{0,30}\bselect\b"),
    ("SQLI-002", "SQL Injection (tautology)", "A03 Injection", "high", r"(?i)\b(or|and)\b\s+(['\"]?)(\w+)\2\s*=\s*\2\3(?!\w)"),
    ("SQLI-003", "SQL Injection (stacked/comment)", "A03 Injection", "high", r"(?i)(;\s*(drop|delete|insert|update|alter)\b|'\s*(--|#)\s*$|'\s*\)?\s*(or|and)\b.{0,20}(--|#))"),
    ("SQLI-004", "SQL Injection (time based)", "A03 Injection", "high", r"(?i)\b(sleep|benchmark|pg_sleep)\s*\(|\bwaitfor\s+delay\b"),
    ("XSS-001", "Cross-Site Scripting (script tag)", "A03 Injection", "high", r"(?i)<\s*/?\s*script\b"),
    ("XSS-002", "Cross-Site Scripting (event handler)", "A03 Injection", "high", r"(?i)\bon(error|load|click|mouseover|focus|toggle)\s*="),
    ("XSS-003", "Cross-Site Scripting (javascript: URI)", "A03 Injection", "medium", r"(?i)javascript\s*:"),
    ("TRAV-001", "Path Traversal", "A01 Broken Access Control", "high", r"(\.\./|\.\.\\)"),
    ("TRAV-002", "Sensitive File Access", "A01 Broken Access Control", "high", r"(?i)/etc/(passwd|shadow)|boot\.ini|win\.ini"),
    ("CMDI-001", "Command Injection", "A03 Injection", "high", r"(?i)(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|curl|wget|nc|bash|sh|powershell)\b"),
]
COMPILED = [(a, b, c, d, re.compile(e)) for a, b, c, d, e in RULES]
SCANNER_UA = re.compile(r"(?i)sqlmap|nikto|nmap|masscan|acunetix|dirbuster|gobuster|nuclei")


def normalize(s: str, rounds: int = 3) -> str:
    """Decode repeatedly so double-encoded payloads can't hide."""
    for _ in range(rounds):
        d = html.unescape(unquote_plus(s))
        if d == s:
            break
        s = d
    return s.replace("\x00", "")


def _flatten(o):
    if isinstance(o, dict):
        return " ".join(f"{k} {_flatten(v)}" for k, v in o.items())
    if isinstance(o, list):
        return " ".join(_flatten(v) for v in o)
    return str(o)


def body_text(body: bytes) -> str:
    text = body[:100_000].decode("utf-8", "ignore")
    try:
        return _flatten(json.loads(text))
    except ValueError:
        return text


def finding(rid, name, owasp, sev, detail):
    return {"id": rid, "name": name, "owasp": owasp, "severity": sev, "detail": detail[:200]}


def inspect(path, query, body: bytes, headers):
    targets = {"path": path, "query": query, "body": body_text(body),
               "referer": headers.get("referer", "")}
    found, seen = [], set()
    for where, raw in targets.items():
        norm = normalize(raw)
        variants = (norm, re.sub(r"/\*.*?\*/", " ", norm))  # defeats UNION/**/SELECT
        for rid, name, owasp, sev, rx in COMPILED:
            if rid in seen:
                continue
            for v in variants:
                m = rx.search(v)
                if m:
                    seen.add(rid)
                    found.append(finding(rid, name, owasp, sev, f"{where}: {m.group(0)}"))
                    break
    if SCANNER_UA.search(headers.get("user-agent", "")):
        found.append(finding("SCAN-001", "Known scanner signature", "A05 Security Misconfiguration", "low", "user-agent"))
    return found


def anomaly_score(text: str) -> float:
    """Heuristic 0..1 risk score from length, special-character ratio and entropy.
    Baseline version; swap for a trained model (e.g. Isolation Forest) later."""
    t = normalize(text or "")
    n = len(t)
    if n == 0:
        return 0.0
    special = sum(c in "'\"<>;()|`\\{}$%" for c in t) / n
    cnt = Counter(t)
    ent = -sum(v / n * math.log2(v / n) for v in cnt.values())
    score = 0.45 * min(n / 600, 1) + 0.40 * min(special / 0.2, 1) + 0.15 * min(max(ent - 3.5, 0) / 2, 1)
    return round(min(score, 1.0), 2)
