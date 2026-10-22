from scapy.all import sniff, IP, TCP

def show(pkt):
    if IP in pkt and TCP in pkt:
        print(pkt[IP].src, "->", pkt[IP].dst, "port", pkt[TCP].dport, "len", len(pkt), flush=True)

print("Sniffing port 1883 on lo... press Ctrl+C to stop")
sniff(iface="lo", filter="tcp port 1883", prn=show, store=False)
