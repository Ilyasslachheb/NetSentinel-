"""
firewall_engine.py
==================
Unified packet-filtering engine.
Merges: black_white_rule, icmp_rule, port_rule, protocole_rule, rate_rule, scan_rule

Fixes applied:
  [1] Shell injection  — os.system() replaced with subprocess.run(list)
  [2] JSON per packet  — rules cached, reloaded only every RULES_RELOAD_INTERVAL seconds
  [3] Duplicate rules  — iptables -C check before -A to avoid stacking
  [4] State persistence — blocked IPs saved to / loaded from BLOCKED_IPS_FILE on disk
  [5] Trusted IP logic — trusted IPs now get BROADER access (skip restricted-port checks)
  [6] Ping rate-limit  — pings are rate-limited, not unconditionally dropped
  [7] No crash guard   — process_packet wrapped in try/except; sniffer loop protected
"""

from scapy.all import sniff, TCP, UDP, IP, ICMP
from signature_engine import check_signatures
from collections import defaultdict, deque
import subprocess
import threading
import ipaddress
import time
import json
import logging

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
log = logging.getLogger("firewall")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
RULE_FILE              = "firewall_rules.json"
BLOCKED_IPS_FILE       = "blocked_ips.json"   # FIX [4]: persistence file
RULES_RELOAD_INTERVAL  = 30                   # FIX [2]: seconds between rule reloads

# Rate limiting
RATE_THRESHOLD  = 40    # packets/sec before block
RATE_WINDOW     = 10    # seconds

# Port scan detection
SCAN_PORT_THRESHOLD = 10   # unique ports within window triggers block
SCAN_WINDOW         = 10   # seconds

# ICMP
MAX_ICMP_PAYLOAD = 100   # bytes — above this = likely tunneling
ICMP_RATE_LIMIT  = 5     # FIX [6]: max pings per ICMP_RATE_WINDOW seconds
ICMP_RATE_WINDOW = 1     # seconds

# Ports associated with known malware / backdoors
SUSPICIOUS_PORTS = {
    4444, 5555, 6666, 6667, 6668, 6669,
    31337, 31338,
    12345, 12346, 27374,
    54321,
    6000, 6001, 6002, 6003,
    6660, 6661, 6662, 6663, 6664, 6665,
    8081, 8088, 9999, 10000,
    1337, 1338, 1999, 2000,
    2140, 2150, 2283,
    1604, 1605,
    3700, 3702, 4443,
    49152, 49153, 49154,
}

# FIX [5]: Ports blocked for UNTRUSTED IPs only — trusted IPs bypass this check
RESTRICTED_PORTS = {22, 3389, 3306}   # SSH, RDP, MySQL

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------
_rate_packets: dict[str, list[float]] = defaultdict(list)
_scan_history: dict[str, deque]       = defaultdict(deque)
_icmp_history: dict[str, list[float]] = defaultdict(list)  # FIX [6]
_blocked_ips:  set[str]               = set()

# FIX [2]: Rule cache
_rule_cache:      tuple | None = None
_rule_cache_time: float        = 0.0
_rule_cache_lock               = threading.Lock()


# ---------------------------------------------------------------------------
# FIX [1] + [3]: Safe iptables wrapper
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> bool:
    """Reject anything that is not a valid IP before touching iptables."""
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        log.error("Invalid IP rejected before iptables call: %r", ip)
        return False


def _iptables_rule_exists(src_ip: str) -> bool:
    """FIX [3]: Return True if a DROP rule already exists for this IP."""
    result = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"],
        capture_output=True
    )
    return result.returncode == 0


def block_ip(src_ip: str, reason: str) -> None:
    """
    Block an IP via iptables.
    FIX [1]: subprocess list — shell injection is impossible.
    FIX [3]: skips insert if rule already exists.
    FIX [4]: persists blocked IP to disk immediately.
    """
    if not _validate_ip(src_ip):
        return

    if src_ip in _blocked_ips:
        return  # already handled this session

    # FIX [3]: only append if the rule is not already there
    if not _iptables_rule_exists(src_ip):
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            log.error("iptables failed for %s: %s", src_ip, result.stderr.strip())
            return

    _blocked_ips.add(src_ip)
    log.info("BLOCKED %s — %s", src_ip, reason)
    _persist_blocked_ips()   # FIX [4]


# ---------------------------------------------------------------------------
# FIX [4]: Persistence — save/restore blocked IPs across restarts
# ---------------------------------------------------------------------------

def _persist_blocked_ips() -> None:
    """Write blocked IPs to disk so they survive a restart."""
    try:
        with open(BLOCKED_IPS_FILE, "w") as f:
            json.dump({"blocked_ips": sorted(_blocked_ips)}, f, indent=2)
    except OSError as exc:
        log.error("Could not write %s: %s", BLOCKED_IPS_FILE, exc)


def _load_persisted_blocked_ips() -> None:
    """
    On startup: reload previously blocked IPs and re-apply iptables rules
    so attackers blocked before the last restart stay blocked.
    """
    try:
        with open(BLOCKED_IPS_FILE) as f:
            data = json.load(f)
        ips = data.get("blocked_ips", [])
        for ip in ips:
            if _validate_ip(ip):
                _blocked_ips.add(ip)
                if not _iptables_rule_exists(ip):
                    subprocess.run(
                        ["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"],
                        capture_output=True
                    )
        log.info("Restored %d blocked IP(s) from disk", len(ips))
    except FileNotFoundError:
        log.info("No %s found — starting with empty block list", BLOCKED_IPS_FILE)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("Could not load %s: %s", BLOCKED_IPS_FILE, exc)


# ---------------------------------------------------------------------------
# FIX [2]: Rule caching — JSON file read at most once per RULES_RELOAD_INTERVAL
# ---------------------------------------------------------------------------

def get_rules() -> tuple[set[str], set[str], set[str]]:
    """
    Returns (whitelist, blacklist, trusted_list).
    Result is cached for RULES_RELOAD_INTERVAL seconds.
    Thread-safe.
    """
    global _rule_cache, _rule_cache_time

    with _rule_cache_lock:
        now = time.monotonic()
        if _rule_cache is not None and (now - _rule_cache_time) < RULES_RELOAD_INTERVAL:
            return _rule_cache

        try:
            with open(RULE_FILE) as f:
                data = json.load(f)
            _rule_cache = (
                set(data.get("ip_whitelist", [])),
                set(data.get("ip_blacklist", [])),
                set(data.get("trusted_list", [])),
            )
            log.debug("Rules reloaded from %s", RULE_FILE)
        except (FileNotFoundError, json.JSONDecodeError) as exc:
            log.warning("Could not load %s: %s — using empty rule sets", RULE_FILE, exc)
            _rule_cache = (set(), set(), set())

        _rule_cache_time = now
        return _rule_cache


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _dst_port(packet) -> int | None:
    if packet.haslayer(TCP):
        return packet[TCP].dport
    if packet.haslayer(UDP):
        return packet[UDP].dport
    return None


# ---------------------------------------------------------------------------
# Rule checks — return True = blocked, False = pass to next check
# ---------------------------------------------------------------------------

def check_blacklist_whitelist(packet, whitelist: set, blacklist: set) -> bool:
    src_ip = packet[IP].src

    if src_ip in blacklist:
        block_ip(src_ip, "blacklisted")
        return True

    if src_ip in whitelist:
        return False  # explicitly trusted — allow

    return False


def check_icmp(packet, whitelist: set) -> bool:
    """
    FIX [6]: Normal pings are rate-limited instead of unconditionally dropped.
             Oversized payload (tunneling) is still a hard block.
    """
    if not packet.haslayer(ICMP):
        return False

    src_ip      = packet[IP].src
    icmp        = packet[ICMP]
    icmp_type   = icmp.type
    payload_len = len(bytes(icmp.payload))

    if src_ip in whitelist:
        return False

    if icmp_type == 0:   # echo reply — benign
        return False

    if icmp_type == 8:   # echo request (ping)
        if payload_len > MAX_ICMP_PAYLOAD:
            block_ip(src_ip, f"ICMP tunneling suspected (payload {payload_len}B)")
            return True

        # FIX [6]: rate-limit pings, don't drop them all blindly
        now = time.time()
        _icmp_history[src_ip].append(now)
        _icmp_history[src_ip] = [
            t for t in _icmp_history[src_ip] if now - t < ICMP_RATE_WINDOW
        ]
        if len(_icmp_history[src_ip]) > ICMP_RATE_LIMIT:
            block_ip(src_ip, f"ICMP flood ({len(_icmp_history[src_ip])} pings/s)")
            return True

        return False   # normal ping within rate limit — allow

    # All other ICMP types (redirects, timestamps, etc.)
    block_ip(src_ip, f"ICMP type {icmp_type} not permitted")
    return True


def check_suspicious_port(packet) -> bool:
    port = _dst_port(packet)
    if port is None or port not in SUSPICIOUS_PORTS:
        return False

    block_ip(packet[IP].src, f"suspicious destination port {port}")
    return True


def check_trusted_protocol(packet, trusted_ips: set) -> bool:
    """
    FIX [5]: Trusted IPs skip restricted-port enforcement entirely — they get
             MORE access, not less. Untrusted IPs are blocked on RESTRICTED_PORTS.
    """
    if not packet.haslayer(TCP):
        return False

    src_ip   = packet[IP].src
    dst_port = packet[TCP].dport

    if src_ip in trusted_ips:
        return False   # trusted — no port restrictions apply

    if dst_port in RESTRICTED_PORTS:
        block_ip(src_ip, f"untrusted IP on restricted port {dst_port}")
        return True

    return False


def check_rate_limit(packet) -> bool:
    src_ip = packet[IP].src
    now    = time.time()

    _rate_packets[src_ip].append(now)
    _rate_packets[src_ip] = [
        t for t in _rate_packets[src_ip] if now - t < RATE_WINDOW
    ]

    rate = len(_rate_packets[src_ip]) / RATE_WINDOW
    if rate > RATE_THRESHOLD:
        block_ip(src_ip, f"rate exceeded ({rate:.1f} pkt/s)")
        _rate_packets[src_ip].clear()
        return True

    return False


def check_port_scan(packet) -> bool:
    src_ip = packet[IP].src
    port   = _dst_port(packet)
    if port is None:
        return False

    now     = time.time()
    history = _scan_history[src_ip]
    history.append((port, now))

    while history and now - history[0][1] > SCAN_WINDOW:
        history.popleft()

    unique_ports = {p for p, _ in history}
    if len(unique_ports) > SCAN_PORT_THRESHOLD:
        block_ip(src_ip, f"port scan ({len(unique_ports)} ports in {SCAN_WINDOW}s)")
        history.clear()
        return True

    return False


# ---------------------------------------------------------------------------
# FIX [7]: Main handler — try/except ensures one bad packet cannot kill the loop
# ---------------------------------------------------------------------------

def process_packet(packet) -> None:
    try:
        if not packet.haslayer(IP):
            return

        whitelist, blacklist, trusted_ips = get_rules()   # FIX [2]: cached

        checks = [
            lambda: check_blacklist_whitelist(packet, whitelist, blacklist),
            lambda: check_icmp(packet, whitelist),
            lambda: check_suspicious_port(packet),
            lambda: check_trusted_protocol(packet, trusted_ips),
            lambda: check_rate_limit(packet),
            lambda: check_port_scan(packet),
        ]

        for check in checks:
            if check():
                return   # packet handled — stop processing

        # Signature-based detection (runs after rule checks)
        check_signatures(packet)

    except Exception:
        # FIX [7]: never let an exception propagate to the sniffer
        log.exception("Unhandled error while processing packet — skipping")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    log.info("Firewall engine starting")
    _load_persisted_blocked_ips()   # FIX [4]: restore block list from disk
    log.info("Listening on all interfaces — Ctrl+C to stop")
    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        log.info("Shutting down — block list saved to %s", BLOCKED_IPS_FILE)
