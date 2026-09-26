"""
Vulnerable Flask Web Application — Demo Target for Sentinel Bug Engine
Simulates a real-world web app with multiple OWASP Top 10 vulnerabilities.
DO NOT deploy this code. For demonstration purposes only.
"""

import os
import subprocess
import sqlite3
import pickle
import hashlib
from flask import Flask, request, jsonify

app = Flask(__name__)

# ─── CWE-798: Hardcoded Credentials ───────────────────────────────────────────
DATABASE_PASSWORD = "supersecret123"
AWS_ACCESS_KEY    = "AKIA1234567890ABCDEF"
STRIPE_SECRET_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dc"
GITHUB_TOKEN      = "ghp_1234567890abcdefghijklmnopqrstuv12"

app.secret_key = "hardcoded-flask-secret-do-not-use"

# ─── CWE-89: SQL Injection ────────────────────────────────────────────────────
@app.route("/user")
def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: f-string interpolation directly into SQL
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

@app.route("/search")
def search_products():
    name = request.args.get("name")
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    # VULNERABLE: string concatenation
    cursor.execute("SELECT * FROM products WHERE name = '" + name + "'")
    return jsonify(cursor.fetchall())

# ─── CWE-78: OS Command Injection ────────────────────────────────────────────
@app.route("/ping")
def ping_host():
    host = request.args.get("host")
    # VULNERABLE: shell=True with user input
    result = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True)
    return result.stdout.decode()

@app.route("/backup")
def backup():
    folder = request.args.get("folder", "/tmp")
    # VULNERABLE: os.system with user-controlled input
    os.system("tar -czf backup.tar.gz " + folder)
    return "Backup done"

# ─── CWE-502: Unsafe Deserialization ─────────────────────────────────────────
@app.route("/load_session", methods=["POST"])
def load_session():
    data = request.get_data()
    # VULNERABLE: pickle.loads on untrusted data allows RCE
    session_obj = pickle.loads(data)
    return jsonify({"user": str(session_obj)})

# ─── CWE-22: Path Traversal ───────────────────────────────────────────────────
@app.route("/file")
def read_file():
    filename = request.args.get("name")
    # VULNERABLE: no path sanitization
    with open(os.path.join("/var/app/uploads", filename), "r") as f:
        return f.read()

# ─── CWE-502 / eval: Remote Code Execution ───────────────────────────────────
@app.route("/calculate")
def calculate():
    expr = request.args.get("expr")
    # VULNERABLE: eval on user input
    result = eval(expr)
    return str(result)

# ─── CWE-400: Resource Leak (unclosed file) ──────────────────────────────────
def parse_log(log_path):
    # VULNERABLE: file opened without context manager — leaks on exception
    f = open(log_path, "r")
    lines = f.readlines()
    return lines  # f is never closed

# ─── Safe code (JVE should mark these as non-issues) ─────────────────────────
def get_user_safe(user_id: int):
    """Parameterized — NOT vulnerable."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = ?", (int(user_id),))
    return cursor.fetchone()

def run_ping_safe(host: str):
    """Allowlisted hosts only — NOT vulnerable."""
    allowed = {"8.8.8.8", "1.1.1.1"}
    if host not in allowed:
        raise ValueError("Host not allowed")
    subprocess.run(["ping", "-c", "1", host], shell=False, check=True)

if __name__ == "__main__":
    app.run(debug=True)
