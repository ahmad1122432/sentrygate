"""LAB ONLY: intentionally vulnerable demo app to test SentryGate against.
Never expose this to a network. Run: uvicorn demo_backend:app --port 9000"""
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE products(id INTEGER, name TEXT, price REAL);
INSERT INTO products VALUES (1,'Leather Wallet',19.5),(2,'Belt',14.0),(3,'Watch Strap',9.0);
CREATE TABLE users(id INTEGER, name TEXT, email TEXT);
""")
for i in range(1, 31):
    db.execute("INSERT INTO users VALUES (?,?,?)", (i, f"user{i}", f"user{i}@example.test"))


@app.get("/")
def home():
    return {"app": "demo backend", "note": "intentionally vulnerable"}


@app.get("/api/products")
def products(id: str = "1"):  # VULNERABLE: string-built SQL
    try:
        rows = db.execute(f"SELECT * FROM products WHERE id = {id}").fetchall()
        return {"result": rows}
    except Exception as e:
        return JSONResponse({"error": str(e)}, 500)


@app.get("/api/users/{uid}")
def user(uid: int):  # VULNERABLE: no ownership check (BOLA)
    row = db.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()
    return {"user": row}


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):  # VULNERABLE: reflected XSS
    return f"<h1>Results for {q}</h1>"


@app.post("/login")
async def login(req: Request):
    data = await req.json()
    if data.get("username") == "admin" and data.get("password") == "S3cret!demo":
        return {"token": "demo-token"}
    return JSONResponse({"error": "invalid credentials"}, 401)
