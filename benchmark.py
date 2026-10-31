"""Latency overhead: the same benign request sent straight to the backend vs through SentryGate.
Start the backend (9000) and a gateway with a high RATE_LIMIT on 8081 first:
  RATE_LIMIT=100000 uvicorn gateway:app --port 8081
Usage: python benchmark.py [N]"""
import json, statistics as st, sys, time
from pathlib import Path
import httpx

N = int(sys.argv[1]) if len(sys.argv) > 1 else 300
TARGETS = {"direct (no gateway)": "http://127.0.0.1:9000", "through SentryGate": "http://127.0.0.1:8081"}
PATH = "/search?q=leather+wallet"
out = {}
for name, base in TARGETS.items():
    with httpx.Client(base_url=base, timeout=10) as c:
        for _ in range(20):  # warm-up
            c.get(PATH)
        t = []
        for _ in range(N):
            s = time.perf_counter(); c.get(PATH); t.append((time.perf_counter() - s) * 1000)
    t.sort()
    out[name] = {"mean_ms": round(st.mean(t), 2), "median_ms": round(st.median(t), 2), "p95_ms": round(t[int(N * .95) - 1], 2)}
    print(f"{name:22s} mean {out[name]['mean_ms']:6.2f} ms | median {out[name]['median_ms']:6.2f} | p95 {out[name]['p95_ms']:6.2f}")
d = out["through SentryGate"]["mean_ms"] - out["direct (no gateway)"]["mean_ms"]
out["overhead_ms"] = round(d, 2)
print(f"Added latency: ~{d:.2f} ms per request (N={N}, sequential, localhost)")
Path("results").mkdir(exist_ok=True)
Path("results/benchmark.json").write_text(json.dumps(out, indent=2))
