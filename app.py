from flask import Flask, render_template, request, jsonify
import hmac

app = Flask(__name__)
import os
import sqlite3

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "gateway.db")


def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


@app.route("/api/traffic", methods=["POST"])
def receive_traffic():
    expected_token = os.environ.get("GATEWAY_API_TOKEN", "")
    supplied_token = request.headers.get("X-API-Token", "")

    if not expected_token or not hmac.compare_digest(
        supplied_token, expected_token
    ):
        return jsonify({"error": "Unauthorized"}), 401

    data = request.get_json(silent=True)

    if not isinstance(data, dict):
        return jsonify({"error": "Expected a JSON object"}), 400

    required = [
        "ts", "src_ip", "pkt_count", "byte_count",
        "avg_pkt_size", "pkt_rate", "avg_iat", "syn_ratio", "label"
    ]

    if any(key not in data for key in required):
        return jsonify({"error": "Missing required fields"}), 400

    try:
        values = [
            data["ts"], data["src_ip"],
            float(data["pkt_count"]), float(data["byte_count"]),
            float(data["avg_pkt_size"]), float(data["pkt_rate"]),
            float(data["avg_iat"]), float(data["syn_ratio"]),
            str(data["label"]).upper()
        ]
    except (TypeError, ValueError):
        return jsonify({"error": "Invalid field values"}), 400

    if values[8] not in ("NORMAL", "ABNORMAL"):
        return jsonify({"error": "Invalid label"}), 400

    conn = get_db()
    try:
        conn.execute(
            """INSERT INTO traffic
            (ts, src_ip, pkt_count, byte_count, avg_pkt_size,
             pkt_rate, avg_iat, syn_ratio, label)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            values
        )
        conn.commit()
    finally:
        conn.close()

    return jsonify({"status": "received"}), 201
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
