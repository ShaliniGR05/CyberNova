import json
import time
import xml.etree.ElementTree as ET
import win32evtlog
import os
import winreg

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
SYSMON_PROVIDER = "Microsoft-Windows-Sysmon"
SYSMON_CONFIG_PATH = r"d:\Techno\demo\sysmon_config.xml"

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
    subkey = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
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
        key = (a["name"].strip().lower(), (a.get("install_location") or "").strip().lower())
        if key not in seen:
            seen.add(key)
            uniq.append(a)
    uniq.sort(key=lambda x: x["name"].lower())
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

def choose_application(apps: list[dict]) -> dict | None:
    """Print apps and let user choose by number or name substring."""
    if not apps:
        print("No installed applications found; showing all events.")
        return None
    print("Installed applications:")
    for i, a in enumerate(apps, 1):
        print(f"{i:3d}. {a['name']}")
    sel = input("Select app number or name (Enter for all): ").strip()
    if not sel:
        return None
    try:
        idx = int(sel)
        if 1 <= idx <= len(apps):
            return apps[idx - 1]
    except ValueError:
        q = sel.lower()
        for a in apps:
            if q in a["name"].lower():
                return a
    print("Invalid selection; showing all events.")
    return None

def main():
    ids = parse_sysmon_config_event_ids(SYSMON_CONFIG_PATH)
    query = build_sysmon_query(ids)
    print(f"Listening for Sysmon events on '{SYSMON_CHANNEL}' with EventIDs: {sorted(ids)}. Press Ctrl+C to stop.")
    print(f"Using query: {query}")

    # New: scan installed apps and optionally filter by app
    try:
        apps = enumerate_installed_apps()
    except Exception as _e:
        apps = []
    selected_app = choose_application(apps)
    app_matcher = make_app_matcher(selected_app)
    if selected_app:
        print(f"Filtering events for application: {selected_app['name']}")

    hquery = None
    filter_ids_runtime = None
    try:
        try:
            hquery = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, query)
        except win32evtlog.error as e:
            # 15001 = The specified query is invalid. Fallback to no filter and filter in Python.
            if getattr(e, "winerror", None) == 15001:
                print("Query rejected (15001). Falling back to no-query and filtering by EventID in Python.")
                hquery = win32evtlog.EvtQuery(SYSMON_CHANNEL, win32evtlog.EvtQueryChannelPath, None)
                filter_ids_runtime = set(ids)
            else:
                raise

        while True:
            try:
                handles = win32evtlog.EvtNext(hquery, 16, 1000)  # up to 16 events, 1s timeout
            except win32evtlog.error:
                time.sleep(0.5)
                continue

            if not handles:
                time.sleep(0.5)
                continue

            for h in handles:
                try:
                    xml = win32evtlog.EvtRender(h, win32evtlog.EvtRenderEventXml)
                    rec = render_event_to_record(xml)
                    if filter_ids_runtime and rec.get("EventID") not in filter_ids_runtime:
                        continue
                    if app_matcher and not app_matcher(rec):
                        continue
                    print(json.dumps(rec, indent=2))
                finally:
                    try:
                        win32evtlog.EvtClose(h)
                    except Exception:
                        pass
    except KeyboardInterrupt:
        print("\nStopped listening for Sysmon events.")
    finally:
        if hquery:
            try:
                win32evtlog.EvtClose(hquery)
            except Exception:
                pass

if __name__ == "__main__":
    main()
