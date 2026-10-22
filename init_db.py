import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "gateway.db")

con = sqlite3.connect(DB_PATH)

con.executescript("""
CREATE TABLE IF NOT EXISTS traffic (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src_ip TEXT,
    pkt_count REAL,
    byte_count REAL,
    avg_pkt_size REAL,
    pkt_rate REAL,
    avg_iat REAL,
    syn_ratio REAL,
    label TEXT
);

CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    ip TEXT,
    command TEXT,
    status TEXT DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts TEXT,
    src_ip TEXT,
    prediction TEXT,
    action TEXT,
    note TEXT
);
""")

con.commit()
con.close()
print("database ready")
