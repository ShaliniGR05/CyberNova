from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
import threading
from collections import deque
from datetime import datetime
import time
import queue

app = Flask(__name__)
CORS(app)

# Store recent events in memory
events_buffer = deque(maxlen=1000)
monitoring_active = False
monitor_thread = None

try:
    from scapy.all import AsyncSniffer, Ether, IP, IPv6, TCP, UDP, ICMP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

# Port security mapping
PORT_MAP = {
    80: ("HTTP", False), 8080: ("HTTP", False), 8000: ("HTTP", False),
    443: ("HTTPS", True), 8443: ("HTTPS", True), 9443: ("HTTPS", True),
    21: ("FTP", False), 20: ("FTP-DATA", False), 22: ("SSH/SFTP", True),
    25: ("SMTP", False), 587: ("SMTP-STARTTLS", True), 465: ("SMTPS", True),
    110: ("POP3", False), 995: ("POP3S", True), 143: ("IMAP", False), 993: ("IMAPS", True),
    23: ("Telnet", False), 3389: ("RDP", True), 53: ("DNS", False), 853: ("DNS-over-TLS", True),
    389: ("LDAP", False), 636: ("LDAPS", True)
}

TLS_LIKE_PORTS = {443, 8443, 9443, 853, 993, 995, 465, 587, 990, 989}

def detect_app_and_security(transport, sport, dport, raw_first_bytes):
    candidates = []
    for p in (sport, dport):
        if p in PORT_MAP:
            candidates.append(PORT_MAP[p])

    if candidates:
        app, is_sec = sorted(candidates, key=lambda x: x[1], reverse=True)[0]
        return app, is_sec

    # Light TLS heuristic
    if transport == "TCP" and raw_first_bytes:
        if len(raw_first_bytes) >= 2 and raw_first_bytes[0] == 0x16 and raw_first_bytes[1] == 0x03:
            return "TLS", True

    if (sport in TLS_LIKE_PORTS) or (dport in TLS_LIKE_PORTS):
        return "TLS-like", True

    return "Unknown", None

def tcp_flags_to_str(tcp_layer):
    flags = tcp_layer.flags
    mapping = [('C', 0x80), ('E', 0x40), ('U', 0x20), ('A', 0x10),
               ('P', 0x08), ('R', 0x04), ('S', 0x02), ('F', 0x01)]
    return ''.join(ch for ch, bit in mapping if flags & bit)

def extract_record(pkt):
    try:
        ip = None
        if IP in pkt:
            ip = pkt[IP]
        elif IPv6 in pkt:
            ip = pkt[IPv6]
        else:
            return None

        transport = None
        sport = dport = None
        tcp_flags = ""
        raw_bytes = None

        if TCP in pkt:
            transport = "TCP"
            sport = int(pkt[TCP].sport)
            dport = int(pkt[TCP].dport)
            tcp_flags = tcp_flags_to_str(pkt[TCP])
            try:
                raw_bytes = bytes(pkt[TCP].payload)[:5]
            except Exception:
                raw_bytes = None
        elif UDP in pkt:
            transport = "UDP"
            sport = int(pkt[UDP].sport)
            dport = int(pkt[UDP].dport)
            try:
                raw_bytes = bytes(pkt[UDP].payload)[:5]
            except Exception:
                raw_bytes = None
        elif ICMP in pkt:
            transport = "ICMP"
        else:
            transport = str(ip.proto) if hasattr(ip, "proto") else "Unknown"

        app_proto, is_secure = detect_app_and_security(transport, sport, dport, raw_bytes)

        record = {
            "timestamp": datetime.fromtimestamp(pkt.time).isoformat(timespec="milliseconds"),
            "src_ip": ip.src if hasattr(ip, "src") else "",
            "dst_ip": ip.dst if hasattr(ip, "dst") else "",
            "src_port": sport,
            "dst_port": dport,
            "transport": transport,
            "app_protocol": app_proto,
            "packet_len": len(pkt) if pkt is not None else 0,
            "tcp_flags": tcp_flags if transport == "TCP" else "",
            "secure": ("Secure" if is_secure is True else "Insecure" if is_secure is False else "Unknown"),
        }
        return record
    except Exception:
        return None

def packet_handler(pkt):
    global events_buffer
    rec = extract_record(pkt)
    if rec:
        events_buffer.append(rec)

sniffer = None

def monitor_packets():
    global sniffer, monitoring_active
    try:
        if SCAPY_AVAILABLE:
            sniffer = AsyncSniffer(prn=packet_handler, store=False)
            sniffer.start()
            while monitoring_active:
                time.sleep(0.1)
            sniffer.stop()
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
    return render_template('packet_sniffer.html')

@app.route('/api/events')
def get_events():
    return jsonify(list(events_buffer))

@app.route('/api/start')
def start_monitoring():
    global monitoring_active, monitor_thread
    if not monitoring_active:
        monitoring_active = True
        monitor_thread = threading.Thread(target=monitor_packets, daemon=True)
        monitor_thread.start()
        return jsonify({"status": "started"})
    return jsonify({"status": "already running"})

@app.route('/api/stop')
def stop_monitoring():
    global monitoring_active, sniffer
    monitoring_active = False
    if sniffer:
        sniffer.stop()
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
    app.run(debug=True, port=5005, host='0.0.0.0')
