import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from flask import Flask, request, jsonify, render_template
from flask_cors import CORS
from src.scanner import Scanner

app = Flask(__name__, template_folder='templates', static_folder='static')
CORS(app)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    target_path = data.get('target_path')
    patterns = data.get('patterns')
    scanner = Scanner(target_path=target_path, patterns=patterns)
    findings = list(scanner.scan())
    # Convert pydantic models to dicts for JSON response
    findings_dict = [f.dict() for f in findings]
    return jsonify(findings_dict)

if __name__ == '__main__':
    # Development server
    app.run(host='0.0.0.0', port=5000, debug=True)
