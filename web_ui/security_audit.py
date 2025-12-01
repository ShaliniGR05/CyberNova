from flask import Flask, render_template, jsonify
from flask_cors import CORS
import json
import win32evtlog
import threading
from collections import deque
from datetime import datetime
import time
try:
    import win32event
    import win32con
    _HAS_NOTIFY = True
except Exception:
    _HAS_NOTIFY = False

app = Flask(__name__)
CORS(app)

# Store recent events in memory
events_buffer = deque(maxlen=1000)
monitoring_active = False
monitor_thread = None
last_error = None

# Security log channel
LOG_TYPE = "Security"
# Actual Event IDs for logon success/failure. The low 16-bits of EventID contain the ID.
EVENT_IDS = {4624, 4625}

def _to_iso(dt_val):
    """Best-effort convert a Windows PyTime or datetime to ISO 8601 string."""
    try:
        # pywintypes.Time typically behaves like datetime
        return dt_val.isoformat()
    except Exception:
        try:
            from datetime import datetime as _dt
            # Some PyTime objects can be cast to float seconds
            return _dt.fromtimestamp(float(dt_val)).isoformat()
        except Exception:
            return str(dt_val)

def monitor_security_events():
    global monitoring_active, events_buffer, last_error
    try:
        server = 'localhost'
        hand = win32evtlog.OpenEventLog(server, LOG_TYPE)
        seq_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

        # Initial tail: jump near the end so we don't replay the whole log.
        try:
            oldest = win32evtlog.GetOldestEventLogRecord(hand)
            total = win32evtlog.GetNumberOfEventLogRecords(hand)
            last_rec = oldest + max(total - 1, 0)
            tail = 50  # show last 50 relevant events on start
            start_at = max(oldest, last_rec - tail + 1)
            seek_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
            events = win32evtlog.ReadEventLog(hand, seek_flags, start_at)
            if events:
                for event in events:
                    actual_id = int(event.EventID) & 0xFFFF
                    if actual_id in EVENT_IDS:
                        inserts = event.StringInserts or []
                        def _get(idx, default="Unknown"):
                            return inserts[idx] if len(inserts) > idx and inserts[idx] else default
                        record = {
                            "EventID": actual_id,
                            "EventType": "Logon Success" if actual_id == 4624 else "Logon Failed",
                            "TimeGenerated": str(event.TimeGenerated),
                            "TimeGeneratedISO": _to_iso(event.TimeGenerated),
                            "SourceName": event.SourceName,
                            "ComputerName": event.ComputerName or "Unknown",
                            "EventCategory": event.EventCategory,
                            "RecordNumber": event.RecordNumber or 0,
                            "EventData": inserts,
                            "UserName": _get(5),
                            "Domain": _get(6),
                            "LogonType": _get(8),
                            "SourceIP": _get(18, "Local"),
                            "timestamp": datetime.now().isoformat()
                        }
                        events_buffer.append(record)
        except Exception:
            # Non-fatal: fall back to sequential reads
            pass

        # Setup event notification for real-time updates if available
        hevt = None
        if _HAS_NOTIFY:
            try:
                hevt = win32event.CreateEvent(None, 0, 0, None)
                win32evtlog.NotifyChangeEventLog(hand, hevt)
            except Exception as e:
                hevt = None
                last_error = f"Notify setup failed: {e}"

        while monitoring_active:
            try:
                # If we have an event notification handle, wait to be signalled
                if hevt is not None:
                    rc = win32event.WaitForSingleObject(hevt, 1000)
                    wait_ok = getattr(win32event, "WAIT_OBJECT_0", 0)
                    if rc == wait_ok:
                        # re-arm notifications
                        try:
                            win32evtlog.NotifyChangeEventLog(hand, hevt)
                        except Exception:
                            pass
                # Read any available new events
                events = win32evtlog.ReadEventLog(hand, seq_flags, 0)
                if events:
                    for event in events:
                        # In pywin32, the real Event ID is stored in the low 16 bits
                        actual_id = int(event.EventID) & 0xFFFF
                        if actual_id in EVENT_IDS:
                            inserts = event.StringInserts or []
                            # Safe access helpers
                            def _get(idx, default="Unknown"):
                                return inserts[idx] if len(inserts) > idx and inserts[idx] else default
                            record = {
                                "EventID": actual_id,
                                "EventType": "Logon Success" if actual_id == 4624 else "Logon Failed",
                                # Keep original string and an ISO variant for UI parsing
                                "TimeGenerated": str(event.TimeGenerated),
                                "TimeGeneratedISO": _to_iso(event.TimeGenerated),
                                "SourceName": event.SourceName,
                                "ComputerName": event.ComputerName or "Unknown",
                                "EventCategory": event.EventCategory,
                                "RecordNumber": event.RecordNumber or 0,
                                "EventData": inserts,
                                # Indices vary by provider version; guard them
                                "UserName": _get(5),
                                "Domain": _get(6),
                                "LogonType": _get(8),
                                "SourceIP": _get(18, "Local"),
                                "timestamp": datetime.now().isoformat()
                            }
                            events_buffer.append(record)
                else:
                    # Nothing new yet; short sleep before polling again
                    time.sleep(0.3)
            except Exception as e:
                last_error = str(e)
                time.sleep(1)
    except Exception as e:
        last_error = str(e)
        events_buffer.append({"error": f"Monitor error: {str(e)}", "timestamp": datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('security_audit.html')

@app.route('/api/events')
def get_events():
    # Only return valid audit records containing an EventID
    data = [e for e in list(events_buffer) if isinstance(e, dict) and e.get("EventID")]
    return jsonify(data)

@app.route('/api/status')
def get_status():
    return jsonify({
        "monitoring": monitoring_active,
    "count": len(events_buffer),
    "last_error": last_error
    })

# Auto-start removed for Flask 3 compatibility; use /api/start to begin monitoring.

@app.route('/api/start')
def start_monitoring():
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_security_events, daemon=True)
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

if __name__ == '__main__':
    app.run(debug=True, port=5002, host='0.0.0.0')
