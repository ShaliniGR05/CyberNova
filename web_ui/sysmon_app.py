from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import json
import time
import xml.etree.ElementTree as ET
import win32evtlog
import os
import winreg
import threading
from collections import deque
from datetime import datetime

app = Flask(__name__)
CORS(app)

# Store recent events in memory
events_buffer = deque(maxlen=1000)
monitoring_active = False
monitor_thread = None
last_error = None

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
# Prefer local config shipped with the web_ui; allow override via ENV SYSMON_CONFIG_PATH
SYSMON_CONFIG_PATH = os.environ.get(
    "SYSMON_CONFIG_PATH",
    os.path.join(os.path.dirname(__file__), "sysmon_config.xml"),
)

# Map Sysmon configuration tags to Event IDs
EVENT_NAME_TO_ID = {
    "ProcessCreate": 1,
    "NetworkConnect": 3,
    "ProcessTerminate": 5,
    "DriverLoad": 6,
    "ImageLoad": 7,
    "CreateRemoteThread": 8,
    "ProcessAccess": 10,
    "FileCreate": 11,
    "PipeEvent": 17,
    "PipeConnected": 18,
    "WmiEventFilter": 19,
    "WmiEventConsumer": 20,
    "WmiEventConsumerToFilter": 21,
    "DnsQuery": 22,
    "FileDelete": 23,
    "ClipboardChange": 24,
    "ProcessTampering": 25,
    "FileDeleteDetected": 26,
    "FileBlockExecutable": 27,
    "FileBlockShredding": 28,
    "FileBlockUnsigned": 29,
}

# RegistryEvent -> EventType mapping
REG_EVENTTYPE_TO_ID = {
    "CreateKey": 12,
    "SetValue": 13,
    "DeleteKey": 14,
    "DeleteValue": 15,
    "RenameKey": 16,
}

# Fields in Sysmon EventData that can contain image paths we can match against
IMAGE_FIELDS = ("Image", "ImageLoaded", "SourceImage", "TargetImage")

def _strip_ns(elem):
    for el in elem.iter():
        if isinstance(el.tag, str) and "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
    return elem

def parse_sysmon_config_event_ids(path: str) -> set[int]:
    # If the config file is missing/unreadable, return empty set so we fall back to provider-only
    if not path or not os.path.isfile(path):
        return set()
    tree = ET.parse(path)
    root = tree.getroot()
    event_ids: set[int] = set()
    ef = root.find("EventFiltering")
    if ef is None:
        return event_ids

    for child in list(ef):
        tag = child.tag
        onmatch = child.attrib.get("onmatch", "")
        if tag == "RegistryEvent":
            if onmatch != "include":
                continue
            for et in child.findall(".//EventType"):
                if (et.attrib.get("condition") == "is") and et.text:
                    evt_id = REG_EVENTTYPE_TO_ID.get(et.text.strip())
                    if evt_id:
                        event_ids.add(evt_id)
        else:
            if onmatch == "include":
                evt_id = EVENT_NAME_TO_ID.get(tag)
                if evt_id:
                    event_ids.add(evt_id)
    return event_ids

def build_sysmon_query(event_ids: set[int]) -> str:
    # Filter only by EventID under System; channel is already set by EvtQuery call
    if event_ids:
        id_clause = " or ".join(f"EventID={i}" for i in sorted(event_ids))
        return f"*[System[({id_clause})]]"
    # Fallback: provider-only filter (rarely used because we parse ids from config)
    return f"*[System[Provider[@Name=\"{SYSMON_PROVIDER}\"]]]"

def render_event_to_record(xml_str: str) -> dict:
    root = _strip_ns(ET.fromstring(xml_str))
    sys = root.find("System")
    ed = root.find("EventData")
    record = {
        "EventID": int(sys.findtext("EventID") or 0),
        "Provider": (sys.find("Provider").attrib.get("Name") if sys.find("Provider") is not None else SYSMON_PROVIDER),
        "Computer": sys.findtext("Computer"),
        "Channel": sys.findtext("Channel"),
        "TimeCreated": (sys.find("TimeCreated").attrib.get("SystemTime") if sys.find("TimeCreated") is not None else None),
        "RecordID": int(sys.findtext("EventRecordID") or 0),
        "EventData": {},
    }
    if ed is not None:
        for d in ed.findall("Data"):
            key = d.attrib.get("Name") or "Data"
            val = (d.text or "").strip()
            record["EventData"][key] = val
    return record

def enumerate_installed_apps() -> list[dict]:
    """Enumerate installed applications from Uninstall registry keys."""
    roots = [
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_LOCAL_MACHINE, winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
        (winreg.HKEY_CURRENT_USER,  winreg.KEY_READ | winreg.KEY_WOW64_64KEY),
        (winreg.HKEY_CURRENT_USER,  winreg.KEY_READ | winreg.KEY_WOW64_32KEY),
    ]
    subkey = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
    apps: list[dict] = []
    for root, access in roots:
        try:
            k = winreg.OpenKey(root, subkey, 0, access)
        except OSError:
            continue
        idx = 0
        while True:
            try:
                skn = winreg.EnumKey(k, idx)
                idx += 1
                try:
                    sk = winreg.OpenKey(k, skn)
                except OSError:
                    continue
                try:
                    name = winreg.QueryValueEx(sk, "DisplayName")[0]
                except OSError:
                    winreg.CloseKey(sk)
                    continue
                install_location = None
                display_icon = None
                try:
                    install_location = winreg.QueryValueEx(sk, "InstallLocation")[0]
                except OSError:
                    pass
                try:
                    display_icon = winreg.QueryValueEx(sk, "DisplayIcon")[0]
                except OSError:
                    pass
                apps.append({
                    "name": name,
                    "install_location": install_location,
                    "display_icon": display_icon,
                })
                winreg.CloseKey(sk)
            except OSError:
                break
        winreg.CloseKey(k)
    # De-duplicate by (name, install_location)
    seen = set()
    uniq: list[dict] = []
    for a in apps:
        key = ((a.get("name") or "").strip().lower(), (a.get("install_location") or "").strip().lower())
        if key not in seen:
            seen.add(key)
            uniq.append(a)
    uniq.sort(key=lambda x: (x.get("name") or "").lower())
    return uniq

def _parse_display_icon_path(value: str | None) -> str | None:
    if not value:
        return None
    s = os.path.expandvars(value).strip().strip('"')
    if "," in s:
        s = s.split(",", 1)[0]
    s = s.strip().strip('"')
    return s if s and os.path.isfile(s) else None

def _normalize_path(p: str) -> str:
    return os.path.normcase(os.path.normpath(p))

def build_app_candidates(app: dict | None) -> tuple[set[str], set[str]]:
    """Return (candidate_dirs, candidate_exes) from InstallLocation and DisplayIcon."""
    dirs: set[str] = set()
    exes: set[str] = set()
    if not app:
        return dirs, exes
    install = (app.get("install_location") or "").strip().strip('"')
    install = os.path.expandvars(install)
    if install and os.path.isdir(install):
        dirs.add(_normalize_path(install))
    di = _parse_display_icon_path(app.get("display_icon"))
    if di:
        exes.add(_normalize_path(di))
        parent = os.path.dirname(di)
        if parent and os.path.isdir(parent):
            dirs.add(_normalize_path(parent))
    return dirs, exes

def get_event_image_paths(rec: dict) -> list[str]:
    ed = rec.get("EventData") or {}
    paths: list[str] = []
    for k in IMAGE_FIELDS:
        v = ed.get(k)
        if v:
            paths.append(v)
    return paths

def make_app_matcher(app: dict | None):
    """Return a predicate(rec)->bool that matches events for the selected app."""
    cand_dirs, cand_exes = build_app_candidates(app)
    if not cand_dirs and not cand_exes:
        return None
    def _match(rec: dict) -> bool:
        for p in get_event_image_paths(rec):
            np = _normalize_path(p)
            if np in cand_exes:
                return True
            for d in cand_dirs:
                if np == d or np.startswith(d + os.sep):
                    return True
        return False
    return _match

# Selected application state
selected_app: dict | None = None
app_matcher = None
installed_apps_cache: list[dict] | None = None

def monitor_sysmon_events():
    global monitoring_active, events_buffer, last_error
    last_error = None
    try:
        ids = parse_sysmon_config_event_ids(SYSMON_CONFIG_PATH)
        query = build_sysmon_query(ids)

        hquery = None
        filter_ids_runtime = None
        try:
            flags = win32evtlog.EvtQueryChannelPath
            try:
                flags |= win32evtlog.EvtQueryTolerateQueryErrors
            except AttributeError:
                pass
            hquery = win32evtlog.EvtQuery(SYSMON_CHANNEL, flags, query)
        except win32evtlog.error as e:
            # 15001 = The specified query is invalid. Fallback to no filter and filter in Python.
            if getattr(e, "winerror", None) == 15001:
                # Try provider-only query first to keep events constrained to Sysmon
                try:
                    provider_only = build_sysmon_query(set())
                    hquery = win32evtlog.EvtQuery(SYSMON_CHANNEL, flags, provider_only)
                    last_error = "Query rejected (15001). Using provider-only query with Python-side EventID filtering."
                    filter_ids_runtime = set(ids)
                except win32evtlog.error:
                    last_error = "Query rejected (15001). Falling back to no-query with Python-side filtering."
                    hquery = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, None)
                    filter_ids_runtime = set(ids)
            elif getattr(e, "winerror", None) == 5:
                # Access denied
                last_error = (
                    "Access denied (5): run Python as Administrator, or grant read access to 'Microsoft-Windows-Sysmon/Operational'"
                )
                raise
            else:
                last_error = f"EvtQuery error: {getattr(e, 'winerror', None)}"
                raise
        except Exception as e:
            last_error = str(e)
            raise

        while monitoring_active:
            try:
                handles = win32evtlog.EvtNext(hquery, 16, 1000)  # up to 16 events, 1s timeout
            except win32evtlog.error:
                time.sleep(0.5)
                continue

            if not handles:
                time.sleep(0.2)
                continue

            for h in handles:
                try:
                    xml = win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml)
                    rec = render_event_to_record(xml)
                    if filter_ids_runtime and rec.get("EventID") not in filter_ids_runtime:
                        continue
                    # App filter, if any
                    matcher = app_matcher  # read snapshot
                    if matcher and not matcher(rec):
                        continue
                    events_buffer.append(rec)
                except Exception as e:
                    last_error = str(e)
                finally:
                    try:
                        win32evtlog.EvtClose(h)
                    except Exception:
                        pass
    except Exception as e:
        events_buffer.append({"error": f"Monitor error: {str(e)}", "timestamp": datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('sysmon_app.html')

@app.route('/api/events')
def get_events():
    return jsonify(list(events_buffer))

@app.route('/api/status')
def status():
    return jsonify({
        "monitoring": monitoring_active,
        "count": len(events_buffer),
        "selected_app": (selected_app.get("name") if selected_app else None),
        "last_error": last_error,
    "config_path": SYSMON_CONFIG_PATH,
    })

@app.route('/api/start')
def start_monitoring():
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_sysmon_events, daemon=True)
        monitor_thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route('/api/stop')
def stop_monitoring():
    global monitoring_active
    monitoring_active = False
    return jsonify({"status": "stopped"})

@app.route('/api/clear')
def clear_events():
    events_buffer.clear()
    return jsonify({"status": "cleared"})

@app.route('/api/apps')
def list_apps():
    global installed_apps_cache
    if installed_apps_cache is None:
        try:
            installed_apps_cache = enumerate_installed_apps()
        except Exception:
            installed_apps_cache = []
    # return only name to keep payload light, include hint fields too
    return jsonify([
        {
            "name": a.get("name"),
            "install_location": a.get("install_location"),
            "display_icon": a.get("display_icon"),
        } for a in installed_apps_cache
    ])

@app.route('/api/select_app', methods=['POST'])
def select_app():
    global selected_app, app_matcher, installed_apps_cache
    data = request.get_json(silent=True) or {}
    name = (data.get('name') or '').strip()
    if not installed_apps_cache:
        try:
            installed_apps_cache = enumerate_installed_apps()
        except Exception:
            installed_apps_cache = []
    if not name:
        selected_app = None
        app_matcher = None
        return jsonify({"status": "cleared", "selected_app": None})
    # exact match by name (case-insensitive)
    cand = None
    for a in installed_apps_cache:
        if (a.get('name') or '').strip().lower() == name.lower():
            cand = a
            break
    selected_app = cand
    app_matcher = make_app_matcher(selected_app)
    return jsonify({
        "status": "ok",
        "selected_app": (selected_app.get('name') if selected_app else None),
        "has_matcher": app_matcher is not None,
    })

if __name__ == '__main__':
    app.run(debug=True, port=5001, host='0.0.0.0')
