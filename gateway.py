"""SentryGate - reverse-proxy security gateway.
Run:  uvicorn gateway:app --port 8080
Env:  BACKEND_URL (default http://127.0.0.1:9000), SENTRY_MODE=block|monitor,
      RATE_LIMIT, SENTRY_TOKEN (dashboard token; otherwise localhost only)
"""
import os, re, time
from collections import defaultdict, deque
from pathlib import Path

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse

import rules, store

BACKEND = os.getenv("BACKEND_URL", "http://127.0.0.1:9000").rstrip("/")
MODE = os.getenv("SENTRY_MODE", "block")            # block | monitor
RATE_LIMIT = int(os.getenv("RATE_LIMIT", "60"))     # requests per RATE_WINDOW
RATE_WINDOW = 10
MAX_BODY = 1_000_000
ANOMALY_BLOCK = 0.75
LOGIN_RE = re.compile(r"/(login|signin|auth)\b", re.I)
BRUTE_LIMIT, BRUTE_WINDOW = 5, 300                  # failed logins per 5 min
ID_RE = re.compile(r"^/api/[^/]+/(\d+)")
BOLA_LIMIT, BOLA_WINDOW = 10, 60                    # distinct object ids per minute

app = FastAPI(title="SentryGate", docs_url=None, redoc_url=None)
client = httpx.AsyncClient(timeout=15, follow_redirects=False)
hits, fails, ids = defaultdict(deque), defaultdict(deque), defaultdict(deque)
HOP = {"connection", "keep-alive", "transfer-encoding", "te", "upgrade", "proxy-authorization", "host", "content-length"}
SEC_HEADERS = {"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer"}


def _prune(dq, now, window, key=lambda x: x):
    while dq and key(dq[0]) < now - window:
        dq.popleft()


def behaviour_findings(ip, path):
    now, out = time.time(), []
    h = hits[ip]; _prune(h, now, RATE_WINDOW); h.append(now)
    if len(h) > RATE_LIMIT:
        out.append(rules.finding("RATE-001", "Rate limit exceeded", "API4 Unrestricted Resource Consumption", "medium", f"{len(h)} req/{RATE_WINDOW}s"))
    f = fails[ip]; _prune(f, now, BRUTE_WINDOW)
    if LOGIN_RE.search(path) and len(f) >= BRUTE_LIMIT:
        out.append(rules.finding("BRUTE-001", "Brute-force login attempts", "A07 Authentication Failures", "high", f"{len(f)} failures"))
    m = ID_RE.match(path)
    if m:
        d = ids[ip]; _prune(d, now, BOLA_WINDOW, key=lambda x: x[0]); d.append((now, m.group(1)))
        if len({i for _, i in d}) >= BOLA_LIMIT:
            out.append(rules.finding("BOLA-001", "Object ID enumeration", "API1 Broken Object Level Authorization", "high", f"{len({i for _, i in d})} ids/{BOLA_WINDOW}s"))
    return out


# ---------- admin dashboard ----------
def admin_ok(req: Request) -> bool:
    tok = os.getenv("SENTRY_TOKEN")
    if tok:
        return req.headers.get("x-sentry-token") == tok or req.query_params.get("token") == tok
    return req.client.host in ("127.0.0.1", "::1")


@app.get("/_sentry/")
async def dashboard(req: Request):
    if not admin_ok(req):
        return JSONResponse({"error": "forbidden"}, 403)
    return HTMLResponse((Path(__file__).parent / "dashboard.html").read_text(encoding="utf-8"))


@app.get("/_sentry/api/events")
async def api_events(req: Request, threats: bool = False):
    if not admin_ok(req):
        return JSONResponse({"error": "forbidden"}, 403)
    return store.recent(100, threats)


@app.get("/_sentry/api/stats")
async def api_stats(req: Request):
    if not admin_ok(req):
        return JSONResponse({"error": "forbidden"}, 403)
    return {**store.stats(), "mode": MODE}


# ---------- protection pipeline ----------
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"])
async def proxy(req: Request, path: str):
    ip, full_path = req.client.host, req.url.path
    body = await req.body()

    findings = rules.inspect(full_path, req.url.query, body, req.headers)
    if len(body) > MAX_BODY:
        findings.append(rules.finding("SIZE-001", "Oversized request body", "A04 Insecure Design", "medium", f"{len(body)} bytes"))
    findings += behaviour_findings(ip, full_path)

    score = rules.anomaly_score(rules.normalize(req.url.query) + " " + rules.body_text(body))
    if score >= ANOMALY_BLOCK and not any(f["severity"] != "low" for f in findings):
        findings.append(rules.finding("ANOM-001", "Anomalous request", "A06 Insecure Design", "medium", f"score {score}"))

    worst = next((f for sev in ("high", "medium", "low") for f in findings if f["severity"] == sev), None)
    threat = any(f["severity"] in ("high", "medium") for f in findings)
    action = ("blocked" if MODE == "block" else "monitored") if threat else ("flagged" if findings else "allowed")
    event_id = store.log(ip, req.method, full_path, action, worst, score)

    if action == "blocked":
        return JSONResponse({"error": "Request blocked by SentryGate", "reference": event_id}, 403)

    # forward to the protected application
    headers = {k: v for k, v in req.headers.items() if k.lower() not in HOP}
    try:
        r = await client.request(req.method, BACKEND + full_path, params=req.query_params, content=body, headers=headers)
    except httpx.HTTPError:
        return JSONResponse({"error": "Backend unavailable"}, 502)

    if LOGIN_RE.search(full_path) and r.status_code in (401, 403):
        fails[ip].append(time.time())

    out = {k: v for k, v in r.headers.items()
           if k.lower() not in HOP | {"content-encoding", "set-cookie"}}
    resp = Response(r.content, r.status_code, out)
    for c in r.headers.get_list("set-cookie"):
        resp.headers.append("set-cookie", c)
    for k, v in SEC_HEADERS.items():
        resp.headers.setdefault(k, v)
    return resp
