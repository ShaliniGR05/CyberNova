import os
import stat
import hashlib
import json
import getpass
import win32security
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import tkinter as tk
from tkinter import scrolledtext, messagebox
import time
from collections import deque


# ===== Utility Functions =====
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


# ===== Global: track modifications for ransomware alert =====
modification_times = deque(maxlen=1000)  # store timestamps of modifications
ALERT_THRESHOLD = 10       # number of modified files
ALERT_WINDOW = 20          # seconds window


def check_bulk_encryption_alert():
    now = time.time()
    recent_mods = [t for t in modification_times if now - t <= ALERT_WINDOW]
    if len(recent_mods) >= ALERT_THRESHOLD:
        return True
    return False


# ===== Watchdog Event Handler =====
class FileEventHandler(FileSystemEventHandler):
    def __init__(self, path, log_store, gui_update_func, observer, alert_func):
        super().__init__()
        self.path = path
        self.log_store = log_store
        self.gui_update_func = gui_update_func
        self.observer = observer
        self.alert_func = alert_func

    def log_event(self, action, path):
        name = os.path.basename(path)
        ext = os.path.splitext(name)[1][1:] if "." in name else ""
        md5, sha256 = get_file_hash(path) if os.path.isfile(path) else (None, None)
        perms = get_permissions(path)
        size = get_file_size(path)

        log_entry = {
            "file": {
                "path": path,
                "name": name,
                "extension": ext,
                "hash": {"md5": md5, "sha256": sha256},
                "action": action,
                "old_permissions": perms,
                "new_permissions": perms,
                "size_bytes": size,
            },
            "user": get_user_info(),
        }

        log_json = json.dumps(log_entry, indent=2)
        self.log_store[self.path].append(log_json)

        # Check for ransomware-like behavior
        if action == "modified" and md5:
            modification_times.append(time.time())
            if check_bulk_encryption_alert():
                self.alert_func("ALERT: Bulk file encryption/modification detected!")

        # Update GUI if this is the active path
        self.gui_update_func()

    def on_created(self, event):
        if event.is_directory:
            try:
                self.observer.schedule(self, event.src_path, recursive=True)
            except Exception:
                pass
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


# ===== Tkinter GUI + Watchdog Observer =====
def start_monitoring():
    root = tk.Tk()
    root.title("Real-Time File Monitor with Alerts")
    root.geometry("1000x700")

    # Container for logs per path
    log_store = {}
    active_path = {"value": None}

    # Text area for logs
    text_area = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10))
    text_area.pack(fill=tk.BOTH, expand=True)

    # Function to update GUI with logs of the active path
    def update_gui():
        if active_path["value"]:
            text_area.delete(1.0, tk.END)
            for log in log_store[active_path["value"]]:
                text_area.insert(tk.END, log + "\n\n")
            text_area.see(tk.END)

    # Function for button clicks
    def show_logs_for(path):
        active_path["value"] = path
        update_gui()

    # Alert function
    def raise_alert(msg):
        messagebox.showerror("SECURITY ALERT", msg)

    # Frame for buttons
    button_frame = tk.Frame(root)
    button_frame.pack(pady=5)

    observer = Observer()

    # Detect drives + specific folders
    user_profile = os.environ["USERPROFILE"]
    watch_paths = [
        os.path.join(user_profile, "Downloads"),
        os.path.join(user_profile, "Documents"),
    ]
    for drive in "DEFGHIJKLMNOPQRSTUVWXYZ":
        drive_path = f"{drive}:\\"
        if os.path.exists(drive_path):
            watch_paths.append(drive_path)

    # Initialize log store & buttons
    for path in watch_paths:
        if os.path.exists(path):
            log_store[path] = []

            # Create button for this path
            btn = tk.Button(button_frame, text=path, command=lambda p=path: show_logs_for(p))
            btn.pack(side=tk.LEFT, padx=5)

            # Watchdog event handler for this path
            event_handler = FileEventHandler(path, log_store, update_gui, observer, raise_alert)
            observer.schedule(event_handler, path, recursive=True)

    observer.start()

    try:
        root.mainloop()
    except KeyboardInterrupt:
        observer.stop()
    observer.join()


if __name__ == "__main__":
    start_monitoring()
