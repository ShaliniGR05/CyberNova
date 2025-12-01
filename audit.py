import json
import win32evtlog
from datetime import datetime

log_type = "Security"
event_ids = {4624, 4625}

def to_iso(dt):
    try:
        return dt.isoformat()
    except Exception:
        try:
            return datetime.fromtimestamp(float(dt)).isoformat()
        except Exception:
            return str(dt)

server = 'localhost'
hand = win32evtlog.OpenEventLog(server, log_type)

seq_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("Listening for Security logon events (4624=Success, 4625=Fail)... Press Ctrl+C to stop.")

try:
    # Initial tail read to start near the end
    try:
        oldest = win32evtlog.GetOldestEventLogRecord(hand)
        total = win32evtlog.GetNumberOfEventLogRecords(hand)
        last = oldest + max(total - 1, 0)
        tail = 50
        start_at = max(oldest, last - tail + 1)
        seek_flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEEK_READ
        events = win32evtlog.ReadEventLog(hand, seek_flags, start_at)
        if events:
            for event in events:
                actual_id = int(event.EventID) & 0xFFFF
                if actual_id in event_ids:
                    record = {
                        "EventID": actual_id,
                        "TimeGenerated": str(event.TimeGenerated),
                        "TimeGeneratedISO": to_iso(event.TimeGenerated),
                        "SourceName": event.SourceName,
                        "ComputerName": event.ComputerName,
                        "EventCategory": event.EventCategory,
                        "EventType": event.EventType,
                        "RecordNumber": event.RecordNumber,
                        "EventData": event.StringInserts or []
                    }
                    print(json.dumps(record))
    except Exception:
        pass

    while True:
        events = win32evtlog.ReadEventLog(hand, seq_flags, 0)
        if events:
            for event in events:
                actual_id = int(event.EventID) & 0xFFFF
                if actual_id in event_ids:
                    record = {
                        "EventID": actual_id,
                        "TimeGenerated": str(event.TimeGenerated),
                        "TimeGeneratedISO": to_iso(event.TimeGenerated),
                        "SourceName": event.SourceName,
                        "ComputerName": event.ComputerName,
                        "EventCategory": event.EventCategory,
                        "EventType": event.EventType,
                        "RecordNumber": event.RecordNumber,
                        "EventData": event.StringInserts or []
                    }
                    print(json.dumps(record))
except KeyboardInterrupt:
    print("\nStopped listening for Security logon events.")
