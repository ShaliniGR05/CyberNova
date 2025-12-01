import json
import win32evtlog

# Sysmon channel
log_type = "Microsoft-Windows-Sysmon/Operational"

# Event IDs to capture
event_ids = {1, 3, 7, 10, 11, 22}

server = 'localhost'
hand = win32evtlog.OpenEventLog(server, log_type)

# Flags: read forward in real-time
flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ

print("Listening for Sysmon events in real-time... (Press Ctrl+C to stop)")

try:
    while True:
        events = win32evtlog.ReadEventLog(hand, flags, 0)
        if events:
            for event in events:
                if event.EventID in event_ids:
                    record = {
                        "EventID": event.EventID,
                        "TimeGenerated": str(event.TimeGenerated),
                        "SourceName": event.SourceName,
                        "ComputerName": event.ComputerName,
                        "EventCategory": event.EventCategory,
                        "EventType": event.EventType,
                        "RecordNumber": event.RecordNumber,
                        "EventData": event.StringInserts
                    }
                    print(json.dumps(record, indent=2))
except KeyboardInterrupt:
    print("\nStopped listening for Sysmon events.")
