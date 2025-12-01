from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import os
import stat
import hashlib
import json
import getpass
import win32security
import threading
from collections import deque
from datetime import datetime
import time

app = Flask(__name__)
CORS(app)

# Store recent events in memory
events_buffer = deque(maxlen=1000)
monitoring_active = False
monitor_thread = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
    WATCHDOG_AVAILABLE = True
except ImportError:
    WATCHDOG_AVAILABLE = False

# Track modifications for ransomware alert
modification_times = deque(maxlen=1000)
ALERT_THRESHOLD = 10
ALERT_WINDOW = 20

def get_file_hash(path):
    try:
        md5_hash = hashlib.md5()
        sha256_hash = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
                sha256_hash.update(chunk)
        return md5_hash.hexdigest(), sha256_hash.hexdigest()
    except Exception:
        return None, None

def get_permissions(path):
    try:
        mode = os.stat(path).st_mode
        return stat.filemode(mode)
    except Exception:
        return "unknown"

def get_file_size(path):
    try:
        return os.path.getsize(path)
    except Exception:
        return 0

def get_user_info():
    try:
        user_name = getpass.getuser()
        user_sid = win32security.LookupAccountName(None, user_name)[0]
        sid_str = win32security.ConvertSidToStringSid(user_sid)
        return {"id": sid_str, "name": user_name, "privilege_level": "admin"}
    except Exception:
        return {"id": "unknown", "name": "unknown", "privilege_level": "unknown"}

def check_bulk_encryption_alert():
    now = time.time()
    recent_mods = [t for t in modification_times if now - t <= ALERT_WINDOW]
    return len(recent_mods) >= ALERT_THRESHOLD

class FileEventHandler(FileSystemEventHandler):
    def log_event(self, action, path):
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1][1:] if "." in name else ""
        md5, sha256 = get_file_hash(path) if os.path.isfile(path) else (None, None)
        perms = get_permissions(path)
        size = get_file_size(path)

        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "file_path": path,
            "file_name": name,
            "extension": ext,
            "action": action,
            "permissions": perms,
            "size_bytes": size,
            "md5_hash": md5,
            "sha256_hash": sha256,
            "user_info": get_user_info(),
            "alert": False
        }

        # Check for ransomware-like behavior
        if action == "modified" and md5:
            modification_times.append(time.time())
            if check_bulk_encryption_alert():
                log_entry["alert"] = True
                log_entry["alert_message"] = "ALERT: Bulk file encryption/modification detected!"

        events_buffer.append(log_entry)

    def on_created(self, event):
        if event.is_directory:
            self.log_event("dir_created", event.src_path)
        else:
            self.log_event("created", event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.log_event("modified", event.src_path)

    def on_deleted(self, event):
        if event.is_directory:
            self.log_event("dir_deleted", event.src_path)
        else:
            self.log_event("deleted", event.src_path)

observer = None

def start_file_monitoring():
    global observer, monitoring_active
    
    if not WATCHDOG_AVAILABLE:
        events_buffer.append({
            "error": "Watchdog not available. Install with: pip install watchdog",
            "timestamp": datetime.now().isoformat()
        })
        return
    
    try:
        observer = Observer()
        event_handler = FileEventHandler()
        
        # Monitor common user directories
        user_profile = os.environ.get("USERPROFILE", "")
        watch_paths = []
        
        if user_profile:
            watch_paths.extend([
                os.path.join(user_profile, "Downloads"),
                os.path.join(user_profile, "Documents"),
                os.path.join(user_profile, "Desktop")
            ])
        
        # Add current directory
        watch_paths.append(os.getcwd())
        
        for path in watch_paths:
            if os.path.exists(path):
                observer.schedule(event_handler, path, recursive=True)
        
        observer.start()
        
        while monitoring_active:
            time.sleep(1)
            
    except Exception as e:
        events_buffer.append({"error": f"Monitor error: {str(e)}", "timestamp": datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('file_monitor.html')

@app.route('/api/events')
def get_events():
    return jsonify(list(events_buffer))

@app.route('/api/start')
def start_monitoring():
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=start_file_monitoring, daemon=True)
        monitor_thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route('/api/stop')
def stop_monitoring():
    global monitoring_active, observer
    monitoring_active = False
    if observer:
        observer.stop()
        observer.join()
    return jsonify({"status": "stopped"})

@app.route('/api/clear')
def clear_events():
    events_buffer.clear()
    return jsonify({"status": "cleared"})

@app.route('/api/status')
def get_status():
    return jsonify({
        "watchdog_available": WATCHDOG_AVAILABLE,
        "monitoring_active": monitoring_active,
        "event_count": len(events_buffer)
    })

if __name__ == '__main__':
    app.run(debug=True, port=5004, host='0.0.0.0')
