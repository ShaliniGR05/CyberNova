from scapy.all import sniff, DNS, DNSQR, DNSRR

def process(pkt):
    if pkt.haslayer(DNS):
        dns = pkt[DNS]
        direction = "Response" if dns.qr == 1 else "Query"
        qname = dns[DNSQR].qname.decode(errors="ignore") if dns.qd else "<none>"
        
        if dns.qr == 0:  # Query
            print(f"[{direction}] {qname} type {dns.qd.qtype} from {pkt[0][1].src} -> {pkt[0][1].dst}")
        else:            # Response
            answers = []
            for i in range(dns.ancount):
                rr = dns.an[i]
                answers.append(f"{rr.rrname.decode()} {rr.type} {getattr(rr,'rdata', '')}")
            print(f"[{direction}] {qname} rcode={dns.rcode} answers={'; '.join(map(str,answers))}")

# Capture both UDP and TCP DNS traffic
sniff(filter="udp port 53 or tcp port 53", prn=process, store=0)
