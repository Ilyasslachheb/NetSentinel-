"""
signature_engine.py
===================
Signature-based attack detection engine.

Detectors:
  - ARP Spoofing        (Layer 2 — IP claimed by multiple MACs)
  - SYN Flood           (TCP volume — too many SYNs per second)
  - UDP Flood           (UDP volume — same logic as SYN flood)
  - Slowloris           (TCP behaviour — stale half-open connections)
  - FIN Scan            (TCP stateful — FIN without prior handshake)
  - NULL Scan           (TCP flags — all zero, never legitimate)
  - XMAS Scan           (TCP flags — FIN+PSH+URG, never legitimate)
  - DNS Amplification   (UDP payload — oversized DNS response)
  - ICMP Tunneling      (ICMP payload — large or signature-matched)

Architecture:
  Each detector is independent and returns True if attack detected.
  All detectors share a single _block_ip() helper.
  call check_signatures(packet) from firewall_engine.py
"""

from scapy.all import IP, TCP, UDP, ICMP, ARP, DNS, Raw
from collections import defaultdict, deque
import subprocess
import ipaddress
import logging
import time

log = logging.getLogger("firewall.signatures")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Ports monitored for TCP attacks
MONITORED_PORTS = {80, 443}

# SYN Flood
SYN_RATE_LIMIT = 20     # SYNs/sec per IP
SYN_WINDOW     = 5      # seconds

# UDP Flood
UDP_RATE_LIMIT = 150    # UDP packets/sec per IP
UDP_WINDOW     = 5      # seconds

# Slowloris
MAX_STALE_CONNS     = 50   # stale connections before block
CONN_TIME_WINDOW    = 60   # seconds before connection considered old
SLOWLORIS_IDLE_TIME = 10   # seconds of inactivity = suspicious

# ARP
MAX_MACS_PER_IP = 1     # more than this = someone lying about ownership

# DNS Amplification
DNS_AMPLIFICATION_SIZE = 512   # bytes
QUERY_TIMEOUT          = 5     # seconds to remember a query

# ICMP Tunneling
ICMP_ECHO_TYPE    = 8
PAYLOAD_THRESHOLD = 100   # bytes — above this is suspicious
TUNNEL_SIGNATURES = [
    b"GET ",
    b"POST ",
    b"SSH-",
    b"\x00\x00\x00\x00\x00\x00\x00\x00",   # ptunnel magic bytes
]

# ---------------------------------------------------------------------------
# Shared state
# ---------------------------------------------------------------------------

# Volume trackers
_syn_tracker: dict[str, list[float]] = defaultdict(list)
_udp_tracker: dict[str, list[float]] = defaultdict(list)

# Slowloris — IP: [[start_time, last_data_time], ...]
_open_connections: dict[str, list[list[float]]] = defaultdict(list)

# FIN scan — full handshake state tracking
# (src_ip, dst_port) → "half_open" | "synack_seen" | "established"
_connection_states: dict[tuple, str] = {}

# ARP — IP: {mac1, mac2, ...}
_arp_table: dict[str, set[str]] = defaultdict(set)

# DNS — (src_ip, query_name): timestamp
_recent_queries: dict[tuple, float] = {}
_dns_mitigation_installed: bool = False

# Already blocked this session
_blocked_ips: set[str] = set()


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _validate_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        log.error("Invalid IP rejected: %r", ip)
        return False


def _block_ip(src_ip: str, reason: str) -> None:
    """
    Single block function shared by all detectors.
    - Validates IP before touching iptables
    - Checks for duplicate rules before inserting
    - Tracks blocked IPs to avoid redundant calls
    """
    if not _validate_ip(src_ip) or src_ip in _blocked_ips:
        return

    exists = subprocess.run(
        ["iptables", "-C", "INPUT", "-s", src_ip, "-j", "DROP"],
        capture_output=True
    )
    if exists.returncode != 0:
        result = subprocess.run(
            ["iptables", "-A", "INPUT", "-s", src_ip, "-j", "DROP"],
            capture_output=True, text=True
        )
        if result.returncode != 0:
            log.error("iptables error for %s: %s", src_ip, result.stderr.strip())
            return

    _blocked_ips.add(src_ip)
    log.warning("BLOCKED %s — %s", src_ip, reason)


def _check_rate(
    tracker: dict,
    src_ip: str,
    window: float,
    limit: float
) -> tuple[bool, float]:
    """
    Shared rate-check logic used by SYN flood and UDP flood.
    Records timestamp, expires old entries, returns (exceeded, rate).
    """
    now = time.time()
    tracker[src_ip].append(now)
    tracker[src_ip] = [t for t in tracker[src_ip] if now - t < window]
    rate = len(tracker[src_ip]) / window
    return rate > limit, rate


# ---------------------------------------------------------------------------
# Detector 1 — ARP Spoofing
# ---------------------------------------------------------------------------

def check_arp_spoof(packet) -> bool:
    """
    Detects ARP spoofing — same IP claimed by more than one MAC.
    ARP operates at Layer 2 so iptables cannot block by IP here.
    We log the alert; MAC-level blocking requires ebtables/nftables.
    """
    try:
        if not packet.haslayer(ARP):
            return False

        if packet[ARP].op != 2:     # op=2 = ARP reply only
            return False

        src_ip  = packet[ARP].psrc
        src_mac = packet[ARP].hwsrc

        _arp_table[src_ip].add(src_mac)

        if len(_arp_table[src_ip]) > MAX_MACS_PER_IP:
            macs = ", ".join(_arp_table[src_ip])
            log.warning(
                "ARP SPOOF DETECTED — IP %s claimed by multiple MACs: %s",
                src_ip, macs
            )
            return True

    except Exception:
        log.exception("Error in check_arp_spoof")

    return False


# ---------------------------------------------------------------------------
# Detector 2 — SYN Flood
# ---------------------------------------------------------------------------

def check_syn_flood(packet) -> bool:
    """
    Detects SYN flood — high rate of SYN-only packets.
    Signature: SYN flag only + high volume from one IP.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        if packet[TCP].dport not in MONITORED_PORTS:
            return False

        if packet[TCP].flags != "S":
            return False

        src_ip = packet[IP].src
        exceeded, rate = _check_rate(_syn_tracker, src_ip, SYN_WINDOW, SYN_RATE_LIMIT)

        if exceeded:
            _block_ip(src_ip, f"SYN flood ({rate:.1f} SYNs/s)")
            _syn_tracker[src_ip].clear()
            return True

    except Exception:
        log.exception("Error in check_syn_flood")

    return False


# ---------------------------------------------------------------------------
# Detector 3 — UDP Flood
# ---------------------------------------------------------------------------

def check_udp_flood(packet) -> bool:
    """
    Detects UDP flood — same logic as SYN flood, different protocol.
    Higher threshold because UDP is used legitimately more often.
    Signature: high UDP packet rate from one IP.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return False

        src_ip = packet[IP].src
        exceeded, rate = _check_rate(_udp_tracker, src_ip, UDP_WINDOW, UDP_RATE_LIMIT)

        if exceeded:
            _block_ip(src_ip, f"UDP flood ({rate:.1f} pkts/s)")
            _udp_tracker[src_ip].clear()
            return True

    except Exception:
        log.exception("Error in check_udp_flood")

    return False


# ---------------------------------------------------------------------------
# Detector 4 — Slowloris
# ---------------------------------------------------------------------------

def check_slowloris(packet) -> bool:
    """
    Detects Slowloris — many connections held open with minimal data.
    Attacker completes TCP handshake then sends headers one fragment
    at a time, never finishing the HTTP request.
    Signature: many long-lived connections with near-zero data activity.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        src_ip   = packet[IP].src
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        now      = time.time()

        if dst_port not in MONITORED_PORTS:
            return False

        # New connection
        if flags == "S":
            _open_connections[src_ip].append([now, now])

        # Data arriving — update last_data_time
        elif packet.haslayer(Raw) and "P" in str(flags):
            if _open_connections[src_ip]:
                _open_connections[src_ip][-1][1] = now

        # Clean close or reset
        elif "F" in str(flags) or "R" in str(flags):
            if _open_connections[src_ip]:
                _open_connections[src_ip].pop()

        # Classify: stale vs active
        stale  = []
        active = []
        for conn in _open_connections[src_ip]:
            start_time, last_data = conn
            age       = now - start_time
            idle_time = now - last_data

            if age > CONN_TIME_WINDOW and idle_time > SLOWLORIS_IDLE_TIME:
                stale.append(conn)
            else:
                active.append(conn)

        _open_connections[src_ip] = active

        if len(stale) > MAX_STALE_CONNS:
            _block_ip(src_ip, f"Slowloris ({len(stale)} stale connections)")
            _open_connections[src_ip].clear()
            return True

    except Exception:
        log.exception("Error in check_slowloris")

    return False


# ---------------------------------------------------------------------------
# Detector 5 — FIN Scan
# ---------------------------------------------------------------------------

def check_fin_scan(packet) -> bool:
    """
    Detects FIN scan — FIN packet sent with no prior established connection.
    Uses full 3-way handshake state tracking to prevent bypass via lone SYN.
    Signature: FIN flag with no completed handshake for this IP+port.

    States:
        half_open    → SYN seen
        synack_seen  → SYN-ACK seen
        established  → ACK seen after SYN-ACK (full handshake complete)
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        src_ip   = packet[IP].src
        dst_port = packet[TCP].dport
        flags    = packet[TCP].flags
        key      = (src_ip, dst_port)

        # Track full handshake
        if flags == "S":
            _connection_states[key] = "half_open"
            return False

        elif flags == "SA":
            if _connection_states.get(key) == "half_open":
                _connection_states[key] = "synack_seen"
            return False

        elif flags == "A":
            if _connection_states.get(key) == "synack_seen":
                _connection_states[key] = "established"
            return False

        # FIN packet
        elif flags == "F":
            state = _connection_states.get(key)

            # Legitimate FIN — connection was fully established
            if state == "established":
                del _connection_states[key]
                return False

            # FIN with no complete handshake = scan
            _block_ip(src_ip, f"FIN scan (state={state}, port={dst_port})")
            _connection_states.pop(key, None)
            return True

        # RST — clean up state
        elif "R" in str(flags):
            _connection_states.pop(key, None)

    except Exception:
        log.exception("Error in check_fin_scan")

    return False


# ---------------------------------------------------------------------------
# Detector 6 + 7 — NULL Scan and XMAS Scan
# ---------------------------------------------------------------------------

def check_flag_scans(packet) -> bool:
    """
    Detects NULL scan (0x00) and XMAS scan (FIN+PSH+URG).
    Both are impossible in legitimate traffic — one packet is enough to block.

    NULL: all flags zero — TCP standard says this should never exist.
    XMAS: FIN+PSH+URG simultaneously — no legitimate use case ever.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(TCP):
            return False

        src_ip = packet[IP].src
        flags  = packet[TCP].flags

        if flags == 0x00:
            _block_ip(src_ip, "NULL scan detected (all flags zero)")
            return True

        elif flags == 0x29:   # FIN + PSH + URG
            _block_ip(src_ip, "XMAS scan detected (FIN+PSH+URG)")
            return True

    except Exception:
        log.exception("Error in check_flag_scans")

    return False


# ---------------------------------------------------------------------------
# Detector 8 — DNS Amplification
# ---------------------------------------------------------------------------

def _install_dns_mitigation() -> None:
    """Install size-based iptables rule once per session."""
    global _dns_mitigation_installed
    if _dns_mitigation_installed:
        return

    result = subprocess.run(
        [
            "iptables", "-A", "INPUT",
            "-p", "udp", "--sport", "53",
            "-m", "length", "--length", f"{DNS_AMPLIFICATION_SIZE}:",
            "-j", "DROP"
        ],
        capture_output=True, text=True
    )
    if result.returncode == 0:
        _dns_mitigation_installed = True
        log.info("DNS amplification mitigation rule installed")
    else:
        log.error("DNS mitigation rule failed: %s", result.stderr.strip())


def _cleanup_dns_queries() -> None:
    """Remove stale DNS query records to prevent memory growth."""
    now   = time.time()
    stale = [k for k, t in _recent_queries.items() if now - t > QUERY_TIMEOUT]
    for k in stale:
        del _recent_queries[k]


def check_dns_amplification(packet) -> bool:
    """
    Detects DNS amplification — oversized DNS responses sent to a victim
    whose IP was spoofed in the original query.
    Signature: UDP port 53 response with payload > 512 bytes.
    Mitigation: size-based iptables rule (not IP-based — src is innocent DNS server).
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(UDP):
            return False

        if not packet.haslayer(DNS):
            return False

        dns    = packet[DNS]
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        query_name = dns.qd.qname.decode() if dns.qd else "unknown"

        # DNS Query — record it
        if dns.qr == 0:
            _recent_queries[(src_ip, query_name)] = time.time()
            return False

        # DNS Response
        if dns.qr == 1:
            payload_size = len(packet[UDP].payload)
            key          = (dst_ip, query_name)

            _cleanup_dns_queries()

            unsolicited = key not in _recent_queries
            oversized   = payload_size > DNS_AMPLIFICATION_SIZE

            if oversized:
                log.warning(
                    "DNS amplification — server: %s | victim: %s | "
                    "query: %s | size: %d bytes | unsolicited: %s",
                    src_ip, dst_ip, query_name, payload_size, unsolicited
                )
                _install_dns_mitigation()

                if key in _recent_queries:
                    del _recent_queries[key]

                return True

    except Exception:
        log.exception("Error in check_dns_amplification")

    return False


# ---------------------------------------------------------------------------
# Detector 9 — ICMP Tunneling
# ---------------------------------------------------------------------------

def check_icmp_tunnel(packet) -> bool:
    """
    Detects ICMP tunneling — real data hidden inside ICMP echo requests.
    Two detection levels:
      1. Confirmed tunnel: large payload + known tool signature → block
      2. Suspicious:       large payload only → log and flag, no block
    Signature: ICMP type 8 + payload > threshold + optional content match.
    """
    try:
        if not packet.haslayer(IP) or not packet.haslayer(ICMP):
            return False

        if packet[ICMP].type != ICMP_ECHO_TYPE:
            return False

        if not packet.haslayer(Raw):
            return False

        payload      = packet[Raw].load
        payload_size = len(payload)
        src_ip       = packet[IP].src

        if payload_size > PAYLOAD_THRESHOLD:

            # Check for known tunneling tool signatures
            signature_found = None
            for sig in TUNNEL_SIGNATURES:
                if sig in payload:
                    signature_found = sig
                    break

            if signature_found:
                # Confirmed tunnel signature — block immediately
                _block_ip(
                    src_ip,
                    f"ICMP tunnel confirmed (signature={signature_found}, "
                    f"size={payload_size}B)"
                )
                return True
            else:
                # Large payload but no known signature — log only
                log.warning(
                    "Suspicious ICMP from %s — large payload (%dB), "
                    "possible covert channel",
                    src_ip, payload_size
                )
                return True   # flagged but not blocked

    except Exception:
        log.exception("Error in check_icmp_tunnel")

    return False


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def check_signatures(packet) -> bool:
    """
    Run all signature detectors against a packet.
    Called from firewall_engine.py after rule-based checks.
    Returns True if any signature matched.

    Order:
      Layer 2 first (ARP — no IP needed)
      Flag-based (cheapest — single packet, no state)
      Stateful TCP (FIN scan needs history)
      Volume-based (rate tracking)
      Payload-based (most expensive — reads packet content)
    """
    checks = [
        check_arp_spoof,        # Layer 2
        check_flag_scans,       # NULL + XMAS — cheapest, no state
        check_fin_scan,         # TCP stateful
        check_syn_flood,        # TCP volume
        check_udp_flood,        # UDP volume
        check_slowloris,        # TCP behaviour
        check_dns_amplification,# UDP payload
        check_icmp_tunnel,      # ICMP payload — most expensive last
    ]

    for check in checks:
        if check(packet):
            return True

    return False
