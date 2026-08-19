"""
Napse.ac - Game Forensic Scanner API Server
Bridges advanced forensic analysis with the web frontend
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import hashlib
import threading
import time
import os
import math
from datetime import datetime, timedelta
import random

app = Flask(__name__)
CORS(app)

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
    "scan_start_time": None,
    "saved_scans": []
}


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

@app.route('/')
def index():
    with open('index.html', 'r', encoding='utf-8') as f:
        return f.read()

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({
        "status": "online",
        "engine": "Napse.ac v3.0.0",
        "timestamp": datetime.now().isoformat(),
        "is_scanning": app_state["is_scanning"]
    })

@app.route('/api/scan', methods=['POST'])
def start_scan():
    data = request.get_json() or {}
    
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
    
    add_telemetry_log("Forensic scan initiated")
    
    def run_scan():
        for i in range(101):
            app_state["scan_progress"] = i
            time.sleep(0.03)

        target = data.get("target_path", "C:/")
        results = build_real_scan_results(target)
        app_state["scanned_files"] = results
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
    return jsonify({
        "is_scanning": app_state["is_scanning"],
        "progress": app_state["scan_progress"],
        "files_processed": len(app_state["scanned_files"]),
        "stats": {
            "total": len(app_state["scanned_files"]),
            "flagged": len([f for f in app_state["scanned_files"] if f['status'] == 'flagged']),
            "warning": len([f for f in app_state["scanned_files"] if f['status'] == 'warning']),
            "clean": len([f for f in app_state["scanned_files"] if f['status'] == 'clean'])
        }
    })

@app.route('/api/results', methods=['GET'])
def get_results():
    return jsonify({
        "total": len(app_state["scanned_files"]),
        "results": app_state["scanned_files"],
        "is_scanning": app_state["is_scanning"]
    })

@app.route('/api/scan/result', methods=['POST'])
def add_scan_result():
    """Accept incremental scan results from vs.py as files are scanned"""
    data = request.get_json() or {}
    
    result = {
        "status": data.get("verdict", "clean"),
        "path": data.get("file_path", ""),
        "mod": data.get("anomaly", ""),
        "hash": data.get("sha256", ""),
        "entropy": data.get("entropy", "0"),
        "category": data.get("file_path", "").split(".")[-1] if "." in data.get("file_path", "") else "file",
    }
    
    # Add to results if not already present
    if not any(r["path"] == result["path"] for r in app_state["scanned_files"]):
        app_state["scanned_files"].append(result)
    
    return jsonify({"status": "received", "total_files": len(app_state["scanned_files"])}), 200

@app.route('/api/pin/generate', methods=['POST'])
def generate_pin():
    data = request.get_json() or {}
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
        "created": datetime.now().isoformat(),
        "expires_at": expiry_time.isoformat()
    })

    add_telemetry_log(f"PIN generated: {pin_code}")

    return jsonify({
        "status": "success",
        "pin": pin_code,
        "expires_at": expiry_time.isoformat(),
        "scan_url": f"{request.host_url.rstrip('/')}/?pin={pin_code}"
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
    files = app_state["scanned_files"]
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
        pin_entry = next((entry for entry in app_state["generated_pins"] if entry.get("pin") == pin_code), None)
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
        "notes": notes,
        "file_count": len(app_state["scanned_files"]),
        "flagged_count": len([f for f in app_state["scanned_files"] if f['status'] == 'flagged']),
        "warning_count": len([f for f in app_state["scanned_files"] if f['status'] == 'warning']),
        "clean_count": len([f for f in app_state["scanned_files"] if f['status'] == 'clean']),
        "results": app_state["scanned_files"],
        "public": False
    }
    
    app_state["saved_scans"].insert(0, scan_record)
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
    scans_summary = []
    for scan in app_state["saved_scans"]:
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
