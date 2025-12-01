#!/usr/bin/env python3
"""
Packet Sniffer: CLI (JSON) + Tkinter UI (live table)
- Fields: timestamp, src_ip, dst_ip, src_port, dst_port, transport, app_protocol, packet_len, tcp_flags
- Classification: secure / insecure / unknown
"""

import threading
import queue
import json
import time
from datetime import datetime

try:
    # scapy import can be slow; keep it scoped
    from scapy.all import AsyncSniffer, Ether, IP, IPv6, TCP, UDP, ICMP
except Exception as e:
    raise SystemExit(
        "Scapy is required. Install with: pip install scapy\n"
        f"Import error: {e}"
    )

import tkinter as tk
from tkinter import ttk


# ---------- Port → Protocol → Security mapping ----------
# True  = secure-by-design (encrypted or typically encrypted)
# False = insecure/plaintext
# Note: STARTTLS ports are treated as secure for classification purposes here.
PORT_MAP = {
    # Web
    80:  ("HTTP", False),
    8080:("HTTP", False),
    8000:("HTTP", False),
    443: ("HTTPS", True),
    8443:("HTTPS", True),
    9443:("HTTPS", True),

    # File transfer
    21:  ("FTP", False),
    20:  ("FTP-DATA", False),
    22:  ("SSH/SFTP", True),
    989: ("FTPS-DATA", True),
    990: ("FTPS", True),

    # Email
    25:  ("SMTP", False),        # STARTTLS capable but plaintext by default
    587: ("SMTP-STARTTLS", True),
    465: ("SMTPS", True),
    110: ("POP3", False),
    995: ("POP3S", True),
    143: ("IMAP", False),
    993: ("IMAPS", True),

    # Remote access
    23:  ("Telnet", False),
    3389:("RDP", True),

    # Name resolution / directory
    53:  ("DNS", False),         # DoT/DoH handled on other ports
    853: ("DNS-over-TLS", True),
    389: ("LDAP", False),
    636: ("LDAPS", True),

    # VPNs (commonly encrypted)
    500: ("IKE", True),
    4500:("IPsec-NAT-T", True),
    1194:("OpenVPN", True),

    # Others
    1883:("MQTT", False),
    8883:("MQTTS", True),
    3306:("MySQL", False),
    5432:("PostgreSQL", False),
    27017:("MongoDB", False),
}

TLS_LIKE_PORTS = {443, 8443, 9443, 853, 993, 995, 465, 587, 990, 989}


def detect_app_and_security(transport: str, sport: int | None, dport: int | None, raw_first_bytes: bytes | None):
    """
    Infer application protocol & security using ports and a lightweight TLS hint.
    Returns: (app_protocol_str, is_secure_bool or None)
    """
    candidates = []
    for p in (sport, dport):
        if p in PORT_MAP:
            candidates.append(PORT_MAP[p])

    if candidates:
        # prefer the more secure mapping if asymmetric
        app, is_sec = sorted(candidates, key=lambda x: x[1], reverse=True)[0]
        return app, is_sec

    # Very light TLS heuristic: TLS record starts with 0x16 0x03
    if transport == "TCP" and raw_first_bytes:
        if len(raw_first_bytes) >= 2 and raw_first_bytes[0] == 0x16 and raw_first_bytes[1] == 0x03:
            return "TLS (heuristic)", True

    # If using a TLS-like port (but not in PORT_MAP for some reason)
    if (sport in TLS_LIKE_PORTS) or (dport in TLS_LIKE_PORTS):
        return "TLS-like", True

    return "Unknown", None


def tcp_flags_to_str(tcp_layer) -> str:
    # scapy can stringify flags via sprintf, but we’ll decode bits for clarity
    # Flags order: C(0x80) E(0x40) U(0x20) A(0x10) P(0x08) R(0x04) S(0x02) F(0x01)
    flags = tcp_layer.flags
    mapping = [
        ('C', 0x80), ('E', 0x40), ('U', 0x20), ('A', 0x10),
        ('P', 0x08), ('R', 0x04), ('S', 0x02), ('F', 0x01),
    ]
    return ''.join(ch for ch, bit in mapping if flags & bit)


def extract_record(pkt) -> dict | None:
    """
    Extract the 9 agreed fields + computed 'secure' label.
    Returns dict or None if not IP-layer traffic.
    """
    # Link/IP determination
    ip = None
    if IP in pkt:
        ip = pkt[IP]
    elif IPv6 in pkt:
        ip = pkt[IPv6]
    else:
        return None  # non-IP (ARP, etc.) — skip for classification

    transport = None
    sport = dport = None
    tcp_flags = ""
    raw_bytes = None

    if TCP in pkt:
        transport = "TCP"
        sport = int(pkt[TCP].sport)
        dport = int(pkt[TCP].dport)
        tcp_flags = tcp_flags_to_str(pkt[TCP])
        # Grab first few bytes if present (for TLS hint) without heavy parsing
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
        # other L4 types
        transport = str(ip.proto) if hasattr(ip, "proto") else "Unknown"

    app_proto, is_secure = detect_app_and_security(transport, sport, dport, raw_bytes)

    # Build the record
    ts = datetime.fromtimestamp(pkt.time).isoformat(timespec="milliseconds")
    src_ip = ip.src if hasattr(ip, "src") else ""
    dst_ip = ip.dst if hasattr(ip, "dst") else ""
    plen = len(pkt) if pkt is not None else 0

    record = {
        "timestamp": ts,
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": sport,
        "dst_port": dport,
        "transport": transport,
        "app_protocol": app_proto,
        "packet_len": plen,
        "tcp_flags": tcp_flags if transport == "TCP" else "",
        # Derived label (None -> "Unknown")
        "secure": (
            "Secure" if is_secure is True else
            "Insecure" if is_secure is False else
            "Unknown"
        ),
    }
    return record


# ---------- Sniffer Thread & Queues ----------
UI_QUEUE = queue.Queue(maxsize=5000)   # UI pipeline
CLI_QUEUE = queue.Queue(maxsize=5000)  # CLI JSON pipeline


def packet_handler(pkt):
    rec = extract_record(pkt)
    if not rec:
        return
    # Non-blocking put; drop if queues are full
    try:
        UI_QUEUE.put_nowait(rec)
    except queue.Full:
        pass
    try:
        CLI_QUEUE.put_nowait(rec)
    except queue.Full:
        pass


class CLILogger(threading.Thread):
    """Consumes records and prints JSON lines to stdout."""
    daemon = True

    def run(self):
        while True:
            rec = CLI_QUEUE.get()
            print(json.dumps(rec, ensure_ascii=False))
            CLI_QUEUE.task_done()


# ---------- Tkinter UI ----------
class SnifferUI:
    def __init__(self, root, iface: str | None = None, bpf_filter: str | None = None, row_limit: int = 1000):
        self.root = root
        self.root.title("Packet Sniffer – Secure vs Insecure (Tkinter)")
        self.row_limit = row_limit
        self.iface = iface
        self.bpf_filter = bpf_filter

        # Controls
        frm_top = ttk.Frame(root, padding=8)
        frm_top.pack(fill="x")

        self.iface_var = tk.StringVar(value=self.iface or "")
        self.filter_var = tk.StringVar(value=self.bpf_filter or "")
        self.status_var = tk.StringVar(value="Stopped")

        ttk.Label(frm_top, text="Interface:").pack(side="left")
        ttk.Entry(frm_top, textvariable=self.iface_var, width=18).pack(side="left", padx=(4, 12))

        ttk.Label(frm_top, text="BPF Filter:").pack(side="left")
        ttk.Entry(frm_top, textvariable=self.filter_var, width=28).pack(side="left", padx=(4, 12))

        self.start_btn = ttk.Button(frm_top, text="Start", command=self.start_sniffer)
        self.start_btn.pack(side="left", padx=4)

        self.stop_btn = ttk.Button(frm_top, text="Stop", command=self.stop_sniffer, state="disabled")
        self.stop_btn.pack(side="left", padx=4)

        ttk.Label(frm_top, textvariable=self.status_var, foreground="green").pack(side="right")

        # Table
        columns = [
            "timestamp", "src_ip", "dst_ip", "src_port", "dst_port",
            "transport", "app_protocol", "packet_len", "tcp_flags", "secure"
        ]
        self.tree = ttk.Treeview(root, columns=columns, show="headings", height=24)
        for col in columns:
            self.tree.heading(col, text=col)
            # Set reasonable column widths
            width = 140 if col in ("timestamp", "app_protocol") else \
                    120 if col in ("src_ip", "dst_ip") else \
                    80
            self.tree.column(col, width=width, anchor="w")
        self.tree.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # Vertical scrollbar
        vsb = ttk.Scrollbar(self.tree, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side="right", fill="y")

        # Sniffer object (AsyncScapy)
        self.sniffer = None

        # Start UI update loop
        self.root.after(100, self.drain_queue)

    def start_sniffer(self):
        if self.sniffer and self.sniffer.running:
            return
        iface = self.iface_var.get().strip() or None
        bpf = self.filter_var.get().strip() or None
        try:
            self.sniffer = AsyncSniffer(
                iface=iface,
                filter=bpf,
                prn=packet_handler,
                store=False
            )
            self.sniffer.start()
            self.status_var.set(f"Running (iface={iface or 'default'}; filter={bpf or 'none'})")
            self.start_btn.config(state="disabled")
            self.stop_btn.config(state="normal")
        except Exception as e:
            self.status_var.set(f"Error: {e}")

    def stop_sniffer(self):
        try:
            if self.sniffer and self.sniffer.running:
                self.sniffer.stop()
            self.status_var.set("Stopped")
        except Exception as e:
            self.status_var.set(f"Error stopping: {e}")
        finally:
            self.start_btn.config(state="normal")
            self.stop_btn.config(state="disabled")

    def drain_queue(self):
        drained = 0
        while True:
            try:
                rec = UI_QUEUE.get_nowait()
            except queue.Empty:
                break
            drained += 1
            # Insert row
            values = [
                rec["timestamp"], rec["src_ip"], rec["dst_ip"], rec["src_port"], rec["dst_port"],
                rec["transport"], rec["app_protocol"], rec["packet_len"], rec["tcp_flags"], rec["secure"]
            ]
            self.tree.insert("", "end", values=values)
            # Enforce row limit
            if len(self.tree.get_children()) > self.row_limit:
                first = self.tree.get_children()[0]
                self.tree.delete(first)
            UI_QUEUE.task_done()

        # Schedule next poll
        self.root.after(100 if drained < 200 else 10, self.drain_queue)


def main():
    # Start CLI logger
    cli = CLILogger()
    cli.start()

    # Build Tkinter UI
    root = tk.Tk()
    # Make it look decent on high-DPI displays as well
    try:
        root.tk.call('tk', 'scaling', 1.25)
    except Exception:
        pass

    style = ttk.Style()
    try:
        style.theme_use('clam')
    except Exception:
        pass

    app = SnifferUI(root, iface=None, bpf_filter=None, row_limit=2000)

    def on_close():
        app.stop_sniffer()
        # Give sniffer/threads a moment to settle
        root.after(200, root.destroy)

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
