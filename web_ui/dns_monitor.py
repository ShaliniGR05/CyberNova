from flask import Flask, render_template, jsonify
from flask_cors import CORS
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
    from scapy.all import sniff, DNS, DNSQR, DNSRR, IP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

def process_dns_packet(pkt):
    global events_buffer
    try:
        if pkt.haslayer(DNS):
            dns = pkt[DNS]
            direction = "Response" if dns.qr == 1 else "Query"
            qname = dns[DNSQR].qname.decode(errors="ignore") if dns.qd else "<none>"
            
            record = {
                "timestamp": datetime.now().isoformat(),
                "direction": direction,
                "query_name": qname,
                "source_ip": pkt[IP].src if pkt.haslayer(IP) else "Unknown",
                "dest_ip": pkt[IP].dst if pkt.haslayer(IP) else "Unknown",
                "query_type": dns.qd.qtype if dns.qd else 0,
                "response_code": dns.rcode if hasattr(dns, 'rcode') else 0,
                "answers": [],
                "answer_count": dns.ancount if hasattr(dns, 'ancount') else 0
            }
            
            if dns.qr == 1 and dns.ancount > 0:  # Response with answers
                for i in range(min(dns.ancount, 5)):  # Limit to 5 answers
                    try:
                        rr = dns.an[i]
                        answer = {
                            "name": rr.rrname.decode() if hasattr(rr, 'rrname') else "",
                            "type": rr.type if hasattr(rr, 'type') else 0,
                            "data": str(getattr(rr, 'rdata', ''))
                        }
                        record["answers"].append(answer)
                    except Exception:
                        pass
            
            events_buffer.append(record)
    except Exception as e:
        events_buffer.append({"error": f"Packet processing error: {str(e)}", "timestamp": datetime.now().isoformat()})

def monitor_dns_traffic():
    global monitoring_active
    try:
        if SCAPY_AVAILABLE:
            sniff(filter="udp port 53 or tcp port 53", prn=process_dns_packet, store=0, stop_filter=lambda x: not monitoring_active)
        else:
            while monitoring_active:
                events_buffer.append({
                    "error": "Scapy not available. Install with: pip install scapy",
                    "timestamp": datetime.now().isoformat()
                })
                time.sleep(5)
    except Exception as e:
        events_buffer.append({"error": f"Monitor error: {str(e)}", "timestamp": datetime.now().isoformat()})

@app.route('/')
def index():
    return render_template('dns_monitor.html')

@app.route('/api/events')
def get_events():
    return jsonify(list(events_buffer))

@app.route('/api/start')
def start_monitoring():
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_dns_traffic, daemon=True)
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

@app.route('/api/status')
def get_status():
    return jsonify({
        "scapy_available": SCAPY_AVAILABLE,
        "monitoring_active": monitoring_active,
        "event_count": len(events_buffer)
    })

if __name__ == '__main__':
    app.run(debug=True, port=5003, host='0.0.0.0')
