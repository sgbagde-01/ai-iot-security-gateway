import csv
import os
import sqlite3
import threading
import time
from collections import defaultdict
from datetime import datetime
from statistics import mean
from scapy.all import sniff, IP, TCP
from ai_model import predict

DB = "/opt/iot-gateway/gateway.db"
CSV_PATH = "/opt/iot-gateway/traffic.csv"
IFACE = "lo"
WINDOW = 5
STRIKES = 3

HEADER = [
    "ts", "src_ip", "pkt_count", "byte_count",
    "avg_pkt_size", "pkt_rate", "avg_iat", "syn_ratio", "label"
]

buf = defaultdict(list)
lock = threading.Lock()
strikes = defaultdict(int)
last_key = None

def on_packet(pkt):
    global last_key

    if IP in pkt and TCP in pkt and pkt[TCP].dport == 1883:
        key = (
            pkt[IP].src, pkt[TCP].sport, pkt[IP].id,
            pkt[TCP].seq, pkt[TCP].ack, len(pkt)
        )

        if IFACE == "lo":
            if key == last_key:
                return
            last_key = key

        flags = int(pkt[TCP].flags)
        syn = bool(flags & 0x02) and not bool(flags & 0x10)

        with lock:
            buf[pkt[IP].src].append(
                (float(pkt.time), len(pkt), syn)
            )

def features(pkts):
    pkts.sort()
    times = [p[0] for p in pkts]
    sizes = [p[1] for p in pkts]
    n = len(pkts)

    iats = [
        b - a for a, b in zip(times, times[1:])
    ]

    return [
        n,
        sum(sizes),
        mean(sizes),
        n / WINDOW,
        mean(iats) if iats else WINDOW,
        sum(p[2] for p in pkts) / n
    ]

def process_window(con, writer):
    global buf

    with lock:
        snap = buf
        buf = defaultdict(list)

    now = datetime.now().isoformat(timespec="seconds")

    for ip, pkts in snap.items():
        f = features(pkts)
        label = predict(f)

        writer.writerow([now, ip, *f, label])

        con.execute(
            """INSERT INTO traffic
            (ts,src_ip,pkt_count,byte_count,avg_pkt_size,
            pkt_rate,avg_iat,syn_ratio,label)
            VALUES(?,?,?,?,?,?,?,?,?)""",
            [now, ip, *f, label]
        )

        action = "none"

        if label == "ABNORMAL":
            strikes[ip] += 1

            if strikes[ip] == STRIKES:
                con.execute(
                    "INSERT INTO actions(ts,ip,command) VALUES(?,?,'block')",
                    (now, ip)
                )
                action = "block_requested"
            elif strikes[ip] > STRIKES:
                action = "already_flagged"
            else:
                action = f"strike_{strikes[ip]}"
        else:
            strikes[ip] = 0

        con.execute(
            """INSERT INTO events
            (ts,src_ip,prediction,action,note)
            VALUES(?,?,?,?,?)""",
            (now, ip, label, action, "")
        )

        print(
            now, ip, [round(x, 2) for x in f],
            label, action, flush=True
        )

    for ip in list(strikes):
        if ip not in snap:
            strikes[ip] = 0

    con.commit()

def main():
    con = sqlite3.connect(DB)

    new = not os.path.exists(CSV_PATH)
    f = open(CSV_PATH, "a", newline="")
    writer = csv.writer(f)

    if new:
        writer.writerow(HEADER)

    threading.Thread(
        target=lambda: sniff(
            iface=IFACE,
            filter="tcp port 1883",
            prn=on_packet,
            store=False
        ),
        daemon=True
    ).start()

    print(
        f"Monitoring {IFACE}, {WINDOW}s windows. Ctrl+C to stop.",
        flush=True
    )

    while True:
        time.sleep(WINDOW)
        process_window(con, writer)
        f.flush()

if __name__ == "__main__":
    main()
