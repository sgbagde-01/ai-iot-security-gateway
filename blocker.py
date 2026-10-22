import ipaddress
import subprocess

# Add your actual laptop and Raspberry Pi IP addresses here.
# These example addresses are placeholders; replace them before use.
WHITELIST = {
    "127.0.0.1",
    "::1",
    # "192.168.1.10",  # Replace with your laptop's actual IP
    # "192.168.1.20",  # Replace with your Raspberry Pi's actual IP
}


def is_safe_ip(ip):
    """Validate an IP address and prevent blocking protected addresses."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        print(f"Invalid IP address: {ip}")
        return False

    if ip in WHITELIST:
        print(f"Protected IP; refusing to block: {ip}")
        return False

    if address.is_loopback or address.is_unspecified or address.is_multicast:
        print(f"Special IP address; refusing to block: {ip}")
        return False

    return True


def block(ip):
    """Add a temporary INPUT firewall rule for an IP address."""
    if not is_safe_ip(ip):
        return False

    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"Blocking rule already exists for {ip}")
        return True

    result = subprocess.run(
        ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"Blocked {ip}")
        return True

    print(f"Could not block {ip}: {result.stderr.strip()}")
    return False


def unblock(ip):
    """Remove the matching INPUT firewall rule for an IP address."""
    if not is_safe_ip(ip):
        return False

    result = subprocess.run(
        ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
        capture_output=True,
        text=True
    )

    if result.returncode == 0:
        print(f"Unblocked {ip}")
        return True

    print(f"No matching rule found, or removal failed: {ip}")
    return False
