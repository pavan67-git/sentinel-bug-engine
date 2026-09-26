# src/dashboard/server.py
"""Simple Flask dashboard for the Sentinel scanner.
Provides a web UI to run the scanner on a target directory and display findings.
"""

from flask import Flask, jsonify, render_template, request
from pathlib import Path

# Import the Scanner class
from src.scanner import Scanner

app = Flask(__name__, template_folder=Path(__file__).parent / "templates", static_folder=Path(__file__).parent / "static")

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan")
def api_scan():
    target = request.args.get("target", ".")
    # Instantiate Scanner with default parameters
    scanner = Scanner(target_path=target)
    findings = scanner.scan_path()
    # Serialize Finding objects to dicts
    def serialize(f):
        d = f.__dict__.copy()
        if hasattr(f, "jve") and f.jve:
            d["jve"] = f.jve.__dict__
        if hasattr(f, "tags"):
            d["tags"] = list(f.tags)
        return d
    data = [serialize(f) for f in findings]
    return jsonify(data)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
