import ipaddress
import sqlite3
from datetime import datetime

DB_PATH = "/opt/iot-gateway/gateway.db"

# Keep actual laptop and Raspberry Pi IP addresses here.
WHITELIST = {"127.0.0.1", "::1"}

# Safe testing mode: do not apply firewall changes.
DRY_RUN = True


def is_safe_ip(ip):
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False

    return (
        ip not in WHITELIST
        and not address.is_loopback
        and not address.is_unspecified
        and not address.is_multicast
    )


def process_actions():
    con = sqlite3.connect(DB_PATH)

    try:
        actions = con.execute(
            "SELECT id, ip, command FROM actions WHERE status = 'pending' ORDER BY id"
        ).fetchall()

        if not actions:
            print("No pending actions.")
            return

        for action_id, ip, command in actions:
            command = command.lower().strip()

            if command not in {"block", "unblock"}:
                status = "rejected"
                print(f"Action {action_id}: rejected unknown command.")
            elif not is_safe_ip(ip):
                status = "rejected"
                print(f"Action {action_id}: rejected unsafe IP {ip}.")
            elif DRY_RUN:
                status = "dry_run"
                print(
                    f"Action {action_id}: would {command} {ip}; "
                    "no firewall changes made."
                )
            else:
                status = "pending"
                print("Live firewall mode is disabled in this version.")

            con.execute(
                "UPDATE actions SET status = ? WHERE id = ?",
                (status, action_id),
            )

        con.commit()

    finally:
        con.close()


if __name__ == "__main__":
    process_actions()
