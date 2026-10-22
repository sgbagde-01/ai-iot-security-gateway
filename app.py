import sqlite3
from flask import Flask, render_template

app = Flask(__name__)
DB_PATH = "/opt/iot-gateway/gateway.db"


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/")
def dashboard():
    conn = get_db()
    try:
        traffic = conn.execute(
            "SELECT * FROM traffic ORDER BY id DESC LIMIT 10"
        ).fetchall()

        stats = conn.execute("""
            SELECT
                COALESCE(SUM(pkt_count), 0) AS total_packets,
                COALESCE(AVG(pkt_rate), 0) AS avg_rate,
                COUNT(*) AS total_windows
            FROM traffic
        """).fetchone()

        abnormal = conn.execute("""
            SELECT COUNT(*) FROM traffic
            WHERE UPPER(label) = 'ABNORMAL'
        """).fetchone()[0]

        events = conn.execute(
            "SELECT * FROM events ORDER BY id DESC LIMIT 5"
        ).fetchall()

        actions = conn.execute(
            "SELECT * FROM actions ORDER BY id DESC LIMIT 5"
        ).fetchall()

        return render_template(
            "index.html",
            traffic=traffic,
            stats=stats,
            abnormal=abnormal,
            events=events,
            actions=actions
        )
    finally:
        conn.close()


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
