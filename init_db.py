import sqlite3
con = sqlite3.connect("/opt/iot-gateway/gateway.db")
con.executescript("""
CREATE TABLE IF NOT EXISTS traffic (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, src_ip TEXT,
  pkt_count REAL, byte_count REAL, avg_pkt_size REAL,
  pkt_rate REAL, avg_iat REAL, syn_ratio REAL,
  label TEXT);
CREATE TABLE IF NOT EXISTS actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, ip TEXT, command TEXT,
  status TEXT DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT, src_ip TEXT, prediction TEXT, action TEXT, note TEXT);
""")
con.commit()
print("database ready")
