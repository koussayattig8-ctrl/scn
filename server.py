"""
Napse.ac - Game Forensic Scanner API Server
Bridges advanced forensic analysis with the web frontend
"""

from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
import json
import hashlib
import threading
import time
import os
import math
import secrets
from datetime import datetime, timedelta
import random

app = Flask(__name__)
CORS(app)

PROJECT_DIR = os.path.dirname(__file__)
SCANNER_EXE_PATHS = (
    os.path.join(PROJECT_DIR, "SentinelScanner.exe"),
    os.path.join(PROJECT_DIR, "dist", "SentinelScanner.exe"),
)


def scanner_exe_path():
    return next((path for path in SCANNER_EXE_PATHS if os.path.isfile(path)), None)

# Database of known cheats/mods
DEFAULT_DATABASE = {
    "weapons.meta": {"risk": "flagged", "mod": "No-Recoil & Magic Bullet Modification"},
    "visualsettings.dat": {"risk": "warning", "mod": "Custom Visuals / Clear Water"},
    "eulen.exe": {"risk": "flagged", "mod": "Eulen FiveM Cheat Menu Injector"},
    "redengine.exe": {"risk": "flagged", "mod": "RedEngine Resource Executor"},
    "desktop.dll": {"risk": "flagged", "mod": "Injected Overlay DLL Module"},
}

# Application state
app_state = {
    "is_scanning": False,
    "scan_progress": 0,
    "scanned_files": [],
    "telemetry_logs": [],
    "generated_pins": [],
    "access_keys": [],
    "admin_sessions": {},
    "user_sessions": {},
    "scan_owner": None,
    "scan_results_by_user": {},
    "scan_status_by_user": {},
    "scan_start_time": None,
    "saved_scans": []
}

STATE_LOCK = threading.Lock()
ADMIN_USERNAME = os.environ.get("SCN_ADMIN_USERNAME", "1")
ADMIN_PASSWORD = os.environ.get("SCN_ADMIN_PASSWORD", "1")

STATE_FILE = os.environ.get("SCN_STATE_FILE", os.path.join(PROJECT_DIR, "scn_state.json"))


def load_persistent_state():
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as state_file:
            saved_state = json.load(state_file)
        app_state["saved_scans"] = saved_state.get("saved_scans", [])
        app_state["generated_pins"] = saved_state.get("generated_pins", [])
        app_state["access_keys"] = saved_state.get("access_keys", [])
        app_state["scan_results_by_user"] = saved_state.get("scan_results_by_user", {})
        app_state["scan_status_by_user"] = saved_state.get("scan_status_by_user", {})
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        pass


def persist_state():
    temporary_file = f"{STATE_FILE}.tmp"
    state = {
        "saved_scans": app_state["saved_scans"],
        "generated_pins": app_state["generated_pins"],
        "access_keys": app_state["access_keys"],
        "scan_results_by_user": app_state["scan_results_by_user"],
        "scan_status_by_user": app_state["scan_status_by_user"]
    }
    try:
        with open(temporary_file, "w", encoding="utf-8") as state_file:
            json.dump(state, state_file, ensure_ascii=False, indent=2)
        os.replace(temporary_file, STATE_FILE)
    except OSError as error:
        print(f"Failed to persist scanner state: {error}")


load_persistent_state()


def sha256_of_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()[:32]
    except Exception:
        return "unavailable"


def entropy_of_file(path):
    try:
        with open(path, "rb") as f:
            data = f.read()
    except Exception:
        return 0.0

    if not data:
        return 0.0

    frequency = {}
    for byte in data:
        frequency[byte] = frequency.get(byte, 0) + 1

    entropy = 0.0
    length = len(data)
    for count in frequency.values():
        probability = count / length
        entropy -= probability * (math.log(probability, 2))
    return round(entropy, 2)


def build_real_scan_results(target_path):
    candidate_paths = []
    for root, _, files in os.walk(target_path):
        if root.lower().endswith(("system32", "windows")):
            continue
        for name in files:
            lower_name = name.lower()
            if lower_name.endswith((".exe", ".dll", ".meta", ".dat", ".rpf", ".zip", ".rar", ".7z")):
                candidate_paths.append(os.path.join(root, name))

    if not candidate_paths:
        return []

    findings = []
    for path in candidate_paths[:20]:
        name = os.path.basename(path).lower()
        match = None
        for key, meta in DEFAULT_DATABASE.items():
            if key.lower() in name or name in key.lower():
                match = meta
                break

        if match is None:
            status = "clean"
            mod = "Vanilla File"
        else:
            status = match["risk"]
            mod = match["mod"]

        findings.append({
            "status": status,
            "path": path,
            "mod": mod,
            "hash": sha256_of_file(path),
            "entropy": str(entropy_of_file(path)),
            "category": path.lower().split(".")[-1] if "." in path else "file",
        })

    return findings


def add_telemetry_log(message):
    timestamp = datetime.now().strftime("%H:%M:%S")
    log_entry = f"[{timestamp}] {message}"
    app_state["telemetry_logs"].append(log_entry)
    if len(app_state["telemetry_logs"]) > 100:
        app_state["telemetry_logs"].pop(0)


def admin_credentials_valid(data):
    return data.get("username") == ADMIN_USERNAME and data.get("password") == ADMIN_PASSWORD


def password_hash(password):
    return hashlib.sha256(str(password).encode("utf-8")).hexdigest()


def admin_token_valid(token):
    if not token:
        return False
    expires_at = app_state["admin_sessions"].get(token)
    if not expires_at:
        return False
    if datetime.now() >= expires_at:
        app_state["admin_sessions"].pop(token, None)
        return False
    return True


def require_admin_token():
    return admin_token_valid(request.headers.get("X-Admin-Token"))


def create_user_session(username):
    session_id = secrets.token_urlsafe(32)
    app_state["user_sessions"][session_id] = {
        "username": username,
        "created_at": datetime.now()
    }
    return session_id


def current_user():
    session = app_state["user_sessions"].get(request.headers.get("X-User-Session"))
    return session.get("username") if session else None


def require_user():
    username = current_user()
    if not username:
        return None, (jsonify({"status": "error", "message": "User login is required."}), 401)
    return username, None


def record_owner(record):
    return record.get("owner") or record.get("user") or "Legacy"


def owned_scan_results(username):
    return app_state["scan_results_by_user"].get(username, [])


def access_key_expired(key_record):
    expires_at = key_record.get("expires_at")
    return bool(expires_at and datetime.now() >= datetime.fromisoformat(expires_at))

@app.route('/')
def index():
    with open('index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/download/scanner', methods=['GET'])
def download_scanner():
    pin_code = request.args.get('pin', '').strip()
    exe_path = scanner_exe_path()
    if not exe_path:
        return jsonify({"status": "error", "message": "Scanner download is not available yet."}), 404
    if not pin_code.isdigit() or len(pin_code) != 6:
        return jsonify({"status": "error", "message": "A valid 6-digit PIN is required."}), 400
    return f"""<!doctype html>
<html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>Scn.ac Scanner</title>
<style>body{{margin:0;min-height:100vh;display:grid;place-items:center;background:#080406;color:#fff;font-family:Arial,sans-serif}}main{{width:min(420px,calc(100% - 40px));padding:32px;text-align:center;border:1px solid #581329;border-radius:18px;background:#12080d;box-shadow:0 0 40px #3b0b1d}}h1{{color:#fb7185}}.pin{{margin:24px 0;font:700 36px monospace;letter-spacing:8px;color:#34d399}}a{{display:inline-block;padding:13px 24px;border-radius:9px;background:#e11d48;color:#fff;text-decoration:none;font-weight:700}}p{{color:#d4a7b0;line-height:1.6}}</style></head>
<body><main><h1>Scn.ac Scanner</h1><p>Your scan PIN is:</p><div class=\"pin\">{pin_code}</div><p>Download and run the scanner. It will ask for this PIN before starting.</p><a href=\"/download/scanner/file\">Download SentinelScanner.exe</a></main></body></html>"""

@app.route('/download/scanner/file', methods=['GET'])
def download_scanner_file():
    exe_path = scanner_exe_path()
    if not exe_path:
        return jsonify({"status": "error", "message": "Scanner download is not available yet."}), 404
    return send_file(exe_path, as_attachment=True, download_name='SentinelScanner.exe')

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "online",
        "engine": "Napse.ac v3.0.0",
        "timestamp": datetime.now().isoformat(),
        "is_scanning": app_state["is_scanning"]
    })


@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json() or {}
    if not admin_credentials_valid(data):
        return jsonify({"status": "error", "message": "Admin credentials are invalid."}), 403

    token = secrets.token_urlsafe(32)
    app_state["admin_sessions"][token] = datetime.now() + timedelta(hours=8)
    add_telemetry_log("Administrator signed in")
    return jsonify({"status": "success", "token": token, "username": ADMIN_USERNAME}), 200

@app.route('/api/admin/access-key', methods=['POST'])
def create_access_key():
    data = request.get_json() or {}
    if not require_admin_token():
        return jsonify({"status": "error", "message": "Administrator login is required."}), 401

    try:
        duration_minutes = int(data.get("duration_minutes", 60))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Duration must be a positive number of minutes."}), 400
    if duration_minutes < 1 or duration_minutes > 525600:
        return jsonify({"status": "error", "message": "Duration must be between 1 minute and 365 days."}), 400

    access_key = secrets.token_urlsafe(24)
    account_password = str(data.get("account_password", "")).strip()
    if len(account_password) < 4:
        return jsonify({"status": "error", "message": "Account password must contain at least 4 characters."}), 400
    expires_at = datetime.now() + timedelta(minutes=duration_minutes)
    key_record = {
        "key": access_key,
        "created": datetime.now().isoformat(),
        "expires_at": expires_at.isoformat(),
        "duration_minutes": duration_minutes,
        "used": False,
        "used_at": None,
        "target_user": str(data.get("target_user", "User")).strip() or "User",
        "password_hash": password_hash(account_password)
    }
    with STATE_LOCK:
        app_state["access_keys"].append(key_record)
        persist_state()

    add_telemetry_log("One-time dashboard access key generated")
    return jsonify({"status": "success", "key": access_key, "target_user": key_record["target_user"], "expires_at": key_record["expires_at"]}), 201


@app.route('/api/admin/access-keys', methods=['GET'])
def list_access_keys():
    if not require_admin_token():
        return jsonify({"status": "error", "message": "Administrator login is required."}), 401
    return jsonify({
        "status": "success",
        "keys": [{
            "key": entry.get("key"),
            "created": entry.get("created"),
            "expires_at": entry.get("expires_at"),
            "duration_minutes": entry.get("duration_minutes"),
            "target_user": entry.get("target_user", "User"),
            "used": bool(entry.get("used")),
            "used_at": entry.get("used_at")
        } for entry in app_state["access_keys"]]
    })


@app.route('/api/admin/access-key/update', methods=['POST'])
def update_access_key():
    data = request.get_json() or {}
    if not require_admin_token():
        return jsonify({"status": "error", "message": "Administrator login is required."}), 401
    key_value = str(data.get("key", "")).strip()
    try:
        duration_minutes = int(data.get("duration_minutes"))
    except (TypeError, ValueError):
        return jsonify({"status": "error", "message": "Duration must be a positive number of minutes."}), 400
    if duration_minutes < 1 or duration_minutes > 525600:
        return jsonify({"status": "error", "message": "Duration must be between 1 minute and 365 days."}), 400

    with STATE_LOCK:
        key_record = next((entry for entry in app_state["access_keys"] if entry.get("key") == key_value), None)
        if key_record is None:
            return jsonify({"status": "error", "message": "Access key not found."}), 404
        key_record["target_user"] = str(data.get("target_user", key_record.get("target_user", "User"))).strip() or "User"
        key_record["duration_minutes"] = duration_minutes
        key_record["expires_at"] = (datetime.now() + timedelta(minutes=duration_minutes)).isoformat()
        persist_state()
    return jsonify({"status": "success", "message": "Access key updated."})


@app.route('/api/admin/access-key/delete', methods=['POST'])
def delete_access_key():
    data = request.get_json() or {}
    if not require_admin_token():
        return jsonify({"status": "error", "message": "Administrator login is required."}), 401
    key_value = str(data.get("key", "")).strip()
    with STATE_LOCK:
        original_count = len(app_state["access_keys"])
        key_record = next((entry for entry in app_state["access_keys"] if entry.get("key") == key_value), None)
        app_state["access_keys"] = [entry for entry in app_state["access_keys"] if entry.get("key") != key_value]
        if len(app_state["access_keys"]) == original_count:
            return jsonify({"status": "error", "message": "Access key not found."}), 404
        account_name = key_record.get("target_user") if key_record else None
        if account_name:
            app_state["generated_pins"] = [
                entry for entry in app_state["generated_pins"] if record_owner(entry) != account_name
            ]
            app_state["saved_scans"] = [
                scan for scan in app_state["saved_scans"] if record_owner(scan) != account_name
            ]
        persist_state()
    add_telemetry_log("Dashboard access key deleted")
    return jsonify({"status": "success", "message": "Access key deleted."})

@app.route('/api/auth/login', methods=['POST'])
def login_with_access_key():
    data = request.get_json() or {}
    access_key = str(data.get("key", "")).strip()
    username = str(data.get("username", "User")).strip() or "User"
    password = str(data.get("password", ""))
    if not access_key:
        return jsonify({"status": "error", "message": "A dashboard access key is required."}), 400

    with STATE_LOCK:
        key_record = next((entry for entry in app_state["access_keys"] if secrets.compare_digest(entry.get("key", ""), access_key)), None)
        if key_record is None:
            return jsonify({"status": "invalid", "message": "Invalid dashboard access key."}), 401
        assigned_user = str(key_record.get("target_user", "")).strip()
        if assigned_user and not secrets.compare_digest(assigned_user.casefold(), username.casefold()):
            return jsonify({"status": "invalid", "message": "This access key belongs to another account."}), 401
        stored_password = key_record.get("password_hash")
        if not stored_password or not secrets.compare_digest(stored_password, password_hash(password)):
            return jsonify({"status": "invalid", "message": "Invalid account password."}), 401
        if access_key_expired(key_record):
            return jsonify({"status": "expired", "message": "This access key has expired."}), 410
        if not key_record.get("used"):
            key_record["used"] = True
            key_record["used_at"] = datetime.now().isoformat()
            persist_state()

    add_telemetry_log(f"Dashboard access key used by {username}")
    session_id = create_user_session(username)
    return jsonify({
        "status": "success",
        "message": "Login accepted. This account key remains active until the administrator deletes it.",
        "username": username,
        "expires_at": key_record.get("expires_at"),
        "session_id": session_id
    }), 200

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    owner = current_user()
    pin_code = str(data.get("pin", "")).strip()
    if not owner and pin_code:
        pin_record = next((entry for entry in app_state["generated_pins"] if entry.get("pin") == pin_code), None)
        owner = record_owner(pin_record) if pin_record else None
    if not owner and not ("records" in data and "summary" in data):
        return jsonify({"status": "error", "message": "User login is required."}), 401
    owner = owner or str(data.get("user", "Unknown User")).strip() or "Unknown User"
    
    # Check if this is a result upload from vs.py GUI
    if "records" in data and "summary" in data:
        # This is scan results from vs.py - store them
        results = []
        for record in data.get("records", []):
            results.append({
                "status": record.get("verdict", "clean"),
                "path": record.get("file_path", ""),
                "mod": record.get("anomaly", ""),
                "hash": record.get("sha256", ""),
                "entropy": "0",
                "category": record.get("file_path", "").split(".")[-1] if "." in record.get("file_path", "") else "file",
            })
        
        app_state["scanned_files"] = results
        app_state["scan_results_by_user"][owner] = results
        app_state["scan_status_by_user"][owner] = {"status": "completed", "files_processed": len(results), "updated_at": datetime.now().isoformat()}
        persist_state()
        app_state["scan_owner"] = owner
        app_state["is_scanning"] = False
        
        user = data.get("user", "Unknown")
        pc_name = data.get("pc_name", "Unknown")
        add_telemetry_log(f"Scan from {user}@{pc_name} - {len(results)} file(s) analyzed")
        
        return jsonify({"status": "success", "message": "Scan results received", "files_stored": len(results)}), 200
    
    # Otherwise, start a new scan from the API
    if app_state["is_scanning"]:
        return jsonify({"error": "Scan already in progress"}), 409
    
    app_state["is_scanning"] = True
    app_state["scan_progress"] = 0
    app_state["scanned_files"] = []
    app_state["scan_owner"] = owner
    app_state["scan_results_by_user"][owner] = []
    app_state["scan_status_by_user"][owner] = {"status": "running", "files_processed": 0, "updated_at": datetime.now().isoformat()}
    persist_state()
    
    add_telemetry_log("Forensic scan initiated")
    
    def run_scan():
        for i in range(101):
            app_state["scan_progress"] = i
            time.sleep(0.03)

        target = data.get("target_path", "C:/")
        results = build_real_scan_results(target)
        app_state["scanned_files"] = results
        app_state["scan_owner"] = owner
        app_state["scan_results_by_user"][owner] = results
        app_state["scan_status_by_user"][owner] = {"status": "completed", "files_processed": len(results), "updated_at": datetime.now().isoformat()}
        persist_state()
        app_state["is_scanning"] = False

        if results:
            add_telemetry_log(f"Scan complete - {len(results)} file(s) analyzed")
        else:
            add_telemetry_log("Scan complete - no matching files found in the selected location")
    
    thread = threading.Thread(target=run_scan, daemon=True)
    thread.start()
    
    return jsonify({"status": "scanning", "message": "Scan started"}), 202

@app.route('/api/scan/progress', methods=['GET'])
def scan_progress():
    owner, error_response = require_user()
    if error_response:
        return error_response
    visible_files = owned_scan_results(owner)
    return jsonify({
        "is_scanning": app_state["is_scanning"],
        "progress": app_state["scan_progress"],
        "files_processed": len(visible_files),
        "stats": {
            "total": len(visible_files),
            "flagged": len([f for f in visible_files if f['status'] == 'flagged']),
            "warning": len([f for f in visible_files if f['status'] == 'warning']),
            "clean": len([f for f in visible_files if f['status'] == 'clean'])
        }
    })

@app.route('/api/results', methods=['GET'])
def get_results():
    owner, error_response = require_user()
    if error_response:
        return error_response
    visible_files = owned_scan_results(owner)
    return jsonify({
        "total": len(visible_files),
        "results": visible_files,
        "is_scanning": app_state["is_scanning"]
    })

@app.route('/api/scan/result', methods=['POST'])
def add_scan_result():
    """Accept incremental scan results from vs.py as files are scanned"""
    data = request.get_json() or {}
    owner = current_user()
    pin_code = str(data.get("pin", "")).strip()
    if not owner and pin_code:
        pin_record = next((entry for entry in app_state["generated_pins"] if entry.get("pin") == pin_code), None)
        owner = record_owner(pin_record) if pin_record else None
    owner = owner or str(data.get("user", "Unknown User")).strip() or "Unknown User"
    app_state["scan_owner"] = owner
    app_state["scan_status_by_user"][owner] = {"status": "running", "files_processed": len(app_state["scan_results_by_user"].get(owner, [])), "updated_at": datetime.now().isoformat()}
    
    result = {
        "status": data.get("verdict", "clean"),
        "path": data.get("file_path", ""),
        "mod": data.get("anomaly", ""),
        "hash": data.get("sha256", ""),
        "entropy": data.get("entropy", "0"),
        "category": data.get("file_path", "").split(".")[-1] if "." in data.get("file_path", "") else "file",
    }
    
    # Add to results if not already present
    results = app_state["scan_results_by_user"].setdefault(owner, [])
    if not any(r["path"] == result["path"] for r in results):
        results.append(result)
        app_state["scanned_files"] = results
        persist_state()
    
    return jsonify({"status": "received", "total_files": len(results)}), 200


@app.route('/api/scan/status', methods=['GET'])
def scan_status():
    owner, error_response = require_user()
    if error_response:
        return error_response
    status = app_state["scan_status_by_user"].get(owner, {"status": "idle", "files_processed": len(owned_scan_results(owner))})
    return jsonify(status)

@app.route('/api/pin/generate', methods=['POST'])
def generate_pin():
    data = request.get_json() or {}
    owner, error_response = require_user()
    if error_response:
        return error_response
    duration = int(data.get('duration', 15))
    target_user = data.get('target_user', 'Unassigned')

    existing_pins = {entry.get('pin') for entry in app_state["generated_pins"]}
    existing_pins.update(scan.get('pin') for scan in app_state["saved_scans"])
    pin_code = f"{random.randint(100000, 999999)}"
    while pin_code in existing_pins:
        pin_code = f"{random.randint(100000, 999999)}"
    expiry_time = datetime.now() + timedelta(minutes=duration)

    app_state["generated_pins"].append({
        "pin": pin_code,
        "target": target_user,
        "owner": owner,
        "created": datetime.now().isoformat(),
        "expires_at": expiry_time.isoformat()
    })
    persist_state()

    add_telemetry_log(f"PIN generated: {pin_code}")

    return jsonify({
        "status": "success",
        "pin": pin_code,
        "expires_at": expiry_time.isoformat(),
        "scan_url": f"{request.host_url.rstrip('/')}/?pin={pin_code}",
        "scanner_url": f"{request.host_url.rstrip('/')}/download/scanner?pin={pin_code}"
    })

@app.route('/api/pin/verify', methods=['POST'])
def verify_pin():
    data = request.get_json() or {}
    pin_code = str(data.get('pin', '')).strip()
    target_user = data.get('target_user')

    if not pin_code or not pin_code.isdigit() or len(pin_code) != 6:
        return jsonify({"status": "error", "message": "PIN must be a 6-digit number."}), 400

    now = datetime.now()
    for entry in reversed(app_state["generated_pins"]):
        if entry.get("pin") != pin_code:
            continue

        expires_at = entry.get("expires_at")
        if expires_at:
            expiry_dt = datetime.fromisoformat(expires_at)
            if now > expiry_dt:
                return jsonify({"status": "expired", "message": "PIN has expired."}), 410

        if target_user and str(entry.get("target", "")).strip() and str(entry.get("target", "")).lower() != str(target_user).lower():
            return jsonify({"status": "invalid", "message": "PIN does not match the provided target user."}), 403

        add_telemetry_log(f"PIN verified: {pin_code}")
        return jsonify({
            "status": "valid",
            "message": "PIN accepted.",
            "pin": pin_code,
            "target": entry.get("target"),
            "expires_at": expires_at
        })

    return jsonify({"status": "invalid", "message": "PIN not found or invalid."}), 404

@app.route('/api/telemetry', methods=['GET'])
def telemetry():
    return jsonify({
        "logs": app_state["telemetry_logs"][-50:],
        "total": len(app_state["telemetry_logs"])
    })

@app.route('/api/dashboard/stats', methods=['GET'])
def dashboard_stats():
    owner, error_response = require_user()
    if error_response:
        return error_response
    files = owned_scan_results(owner)
    return jsonify({
        "total_checks": len(files),
        "clean_files": len([f for f in files if f['status'] == 'clean']),
        "suspicious": len([f for f in files if f['status'] == 'warning']),
        "flagged": len([f for f in files if f['status'] == 'flagged']),
        "is_scanning": app_state["is_scanning"],
        "scan_progress": app_state["scan_progress"]
    })

@app.route('/api/scans/save', methods=['POST'])
def save_scan():
    """Save current scan results with a PIN"""
    data = request.get_json() or {}
    pin_code = str(data.get('pin', '')).strip()
    owner = current_user()
    if not owner and pin_code:
        pin_entry = next((entry for entry in app_state["generated_pins"] if entry.get("pin") == pin_code), None)
        owner = record_owner(pin_entry) if pin_entry else None
    if not owner:
        return jsonify({"status": "error", "message": "User login or a valid scan PIN is required."}), 401
    if pin_code and (not pin_code.isdigit() or len(pin_code) != 6):
        return jsonify({"status": "error", "message": "PIN must be a 6-digit number."}), 400

    if not pin_code:
        used_pins = {scan["pin"] for scan in app_state["saved_scans"]}
        pin_code = f"{random.randint(100000, 999999)}"
        while pin_code in used_pins:
            pin_code = f"{random.randint(100000, 999999)}"
    if any(scan["pin"] == pin_code for scan in app_state["saved_scans"]):
        return jsonify({"status": "error", "message": "This PIN already has a saved scan."}), 409

    if data.get('pin'):
        pin_entry = next((entry for entry in app_state["generated_pins"] if entry.get("pin") == pin_code and record_owner(entry) == owner), None)
        if pin_entry is None:
            return jsonify({"status": "error", "message": "PIN was not generated by this server."}), 404
        if datetime.now() > datetime.fromisoformat(pin_entry["expires_at"]):
            return jsonify({"status": "expired", "message": "PIN has expired."}), 410

    notes = data.get('notes', 'Forensic Scan Report')
    user = data.get('user', 'Unknown User')
    
    scan_record = {
        "pin": pin_code,
        "timestamp": datetime.now().isoformat(),
        "user": user,
        "owner": owner,
        "notes": notes,
        "file_count": len(owned_scan_results(owner)),
        "flagged_count": len([f for f in owned_scan_results(owner) if f['status'] == 'flagged']),
        "warning_count": len([f for f in owned_scan_results(owner) if f['status'] == 'warning']),
        "clean_count": len([f for f in owned_scan_results(owner) if f['status'] == 'clean']),
        "results": owned_scan_results(owner),
        "public": False
    }
    
    app_state["saved_scans"].insert(0, scan_record)
    persist_state()
    add_telemetry_log(f"Scan saved with PIN: {pin_code}")
    
    return jsonify({
        "status": "success",
        "pin": pin_code,
        "message": f"Scan saved successfully with PIN {pin_code}",
        "scan_url": f"{request.host_url.rstrip('/')}/?pin={pin_code}"
    }), 200

@app.route('/api/scans/list', methods=['GET'])
def list_scans():
    """Get all saved scans"""
    owner, error_response = require_user()
    if error_response:
        return error_response
    scans_summary = []
    for scan in app_state["saved_scans"]:
        if record_owner(scan) != owner:
            continue
        scans_summary.append({
            "pin": scan["pin"],
            "timestamp": scan["timestamp"],
            "user": scan["user"],
            "notes": scan["notes"],
            "file_count": scan["file_count"],
            "flagged_count": scan["flagged_count"],
            "warning_count": scan["warning_count"],
            "clean_count": scan["clean_count"],
            "public": scan["public"]
        })
    
    return jsonify({
        "total": len(scans_summary),
        "scans": scans_summary
    }), 200

@app.route('/api/scans/<pin>', methods=['GET'])
def get_scan(pin):
    """Get specific scan by PIN"""
    for scan in app_state["saved_scans"]:
        if scan["pin"] == pin:
            return jsonify({
                "status": "found",
                "scan": scan
            }), 200
    
    return jsonify({"status": "not_found", "message": "Scan not found"}), 404

@app.route('/api/scans/<pin>/delete', methods=['POST'])
def delete_scan(pin):
    """Delete a saved scan"""
    for i, scan in enumerate(app_state["saved_scans"]):
        if scan["pin"] == pin:
            app_state["saved_scans"].pop(i)
            persist_state()
            add_telemetry_log(f"Scan deleted: {pin}")
            return jsonify({"status": "success", "message": "Scan deleted"}), 200
    
    return jsonify({"status": "not_found", "message": "Scan not found"}), 404

@app.route('/api/scans/<pin>/public', methods=['POST'])
def make_scan_public(pin):
    """Make a scan public"""
    data = request.get_json() or {}
    public = data.get('public', True)
    
    for scan in app_state["saved_scans"]:
        if scan["pin"] == pin:
            scan["public"] = public
            add_telemetry_log(f"Scan {pin} visibility changed to {'public' if public else 'private'}")
            return jsonify({"status": "success", "public": public}), 200
    
    return jsonify({"status": "not_found", "message": "Scan not found"}), 404

if __name__ == '__main__':
    print("=" * 60)
    print(" Napse.ac - Game Forensic Scanner API")
    print(" Version: 3.0.0")
    print("=" * 60)
    print("")
    print(" Dashboard: http://localhost:8000")
    print(" API Docs: http://localhost:8000/api/health")
    print("")
    add_telemetry_log("Napse.ac Engine initialized and ready")
    app.run(
        host=os.environ.get('HOST', '0.0.0.0'),
        port=int(os.environ.get('PORT', '8000')),
        debug=False,
        threaded=True
    )
    