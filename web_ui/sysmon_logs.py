from flask import Flask, render_template, jsonify
from flask_cors import CORS
import json
import win32evtlog
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

# Sysmon channel
LOG_TYPE = "Microsoft-Windows-Sysmon/Operational"
EVENT_IDS = {1, 3, 7, 10, 11, 22}  # Process Create, Network Connect, Image Load, Process Access, File Create, DNS Query

EVENT_DESCRIPTIONS = {
    1: "Process Create",
    3: "Network Connect", 
    7: "Image Load",
    10: "Process Access",
    11: "File Create",
    22: "DNS Query"
}

def monitor_sysmon_events():
    global monitoring_active, events_buffer
    
    try:
        server = 'localhost'
        hand = win32evtlog.OpenEventLog(server, LOG_TYPE)
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        
        while monitoring_active:
            try:
                events = win32evtlog.ReadEventLog(hand, flags, 0)
                if events:
                    for event in events:
                        if event.EventID in EVENT_IDS:
                            # Parse event data
                            event_data = {}
                            if event.StringInserts:
                                for i, insert in enumerate(event.StringInserts):
                                    event_data[f"Data_{i}"] = insert
                            
                            record = {
                                "EventID": event.EventID,
                                "EventDescription": EVENT_DESCRIPTIONS.get(event.EventID, f"Event {event.EventID}"),
                                "TimeGenerated": str(event.TimeGenerated),
                                "SourceName": event.SourceName,
                                "ComputerName": event.ComputerName,
                                "EventCategory": event.EventCategory,
                                "RecordNumber": event.RecordNumber,
                                "ProcessID": event_data.get("Data_3", "Unknown") if event.EventID == 1 else None,
                                "ProcessName": event_data.get("Data_4", "Unknown") if event.EventID == 1 else None,
                                "CommandLine": event_data.get("Data_10", "Unknown") if event.EventID == 1 else None,
                                "SourceIP": event_data.get("Data_2", "Unknown") if event.EventID == 3 else None,
                                "DestIP": event_data.get("Data_3", "Unknown") if event.EventID == 3 else None,
                                "DestPort": event_data.get("Data_4", "Unknown") if event.EventID == 3 else None,
                                "QueryName": event_data.get("Data_5", "Unknown") if event.EventID == 22 else None,
                                "FileName": event_data.get("Data_2", "Unknown") if event.EventID == 11 else None,
                                "EventData": event_data,
                                "timestamp": datetime.now().isoformat()
                            }
                            events_buffer.append(record)
                time.sleep(0.5)
            except Exception as e:
                time.sleep(1)
    except Exception as e:
        events_buffer.append({"error": f"Monitor error: {str(e)}", "timestamp": datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('sysmon_logs.html')

@app.route('/api/events')
def get_events():
    return jsonify(list(events_buffer))

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

@app.route('/api/stats')
def get_stats():
    event_counts = {}
    for event in events_buffer:
        if 'EventID' in event:
            event_id = event['EventID']
            event_counts[event_id] = event_counts.get(event_id, 0) + 1
    
    return jsonify({
        "total_events": len(events_buffer),
        "event_counts": event_counts,
        "monitoring_active": monitoring_active
    })

if __name__ == '__main__':
    app.run(debug=True, port=5006, host='0.0.0.0')
