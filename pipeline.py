"""
pipeline.py
===========
Central pipeline connecting firewall_engine and signature_engine.

Packet flow:
    Network
       │
       ▼
  [ Stage 1 ] — Whitelist / Blacklist       (instant allow or block)
       │
       ▼
  [ Stage 2 ] — Rule-based filtering        (ports, rates, ICMP, scan)
       │
       ▼
  [ Stage 3 ] — Signature-based detection   (NULL, XMAS, FIN, SYN flood,
       │          UDP flood, Slowloris,        DNS amp, ICMP tunnel, ARP)
       ▼
      PASS  (packet allowed through)

Each stage returns a verdict:
    BLOCK  — packet dropped, stop processing
    PASS   — continue to next stage
    ALLOW  — whitelist hit, skip all remaining stages

Run this file directly to start the full engine:
    sudo python3 pipeline.py
"""

from scapy.all import sniff, IP, ARP
import logging
import time
import sys
import os

# ---------------------------------------------------------------------------
# Logging — single shared config for both engines
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("firewall.log"),   # log to file as well
    ]
)
log = logging.getLogger("pipeline")

# ---------------------------------------------------------------------------
# Import both engines
# ---------------------------------------------------------------------------
try:
    from firewall_engine import (
        get_rules,
        check_blacklist_whitelist,
        check_icmp,
        check_suspicious_port,
        check_trusted_protocol,
        check_rate_limit,
        check_port_scan,
        _load_persisted_blocked_ips,
    )
except ImportError as e:
    log.critical("Could not import firewall_engine: %s", e)
    sys.exit(1)

try:
    from signature_engine import (
        check_arp_spoof,
        check_flag_scans,
        check_fin_scan,
        check_syn_flood,
        check_udp_flood,
        check_slowloris,
        check_dns_amplification,
        check_icmp_tunnel,
    )
except ImportError as e:
    log.critical("Could not import signature_engine: %s", e)
    sys.exit(1)

# ---------------------------------------------------------------------------
# Verdict constants
# ---------------------------------------------------------------------------
ALLOW = "ALLOW"
BLOCK = "BLOCK"
PASS  = "PASS"

# ---------------------------------------------------------------------------
# Pipeline statistics — how many packets each stage handled
# ---------------------------------------------------------------------------
_stats = {
    "total":       0,
    "allowed":     0,
    "blocked":     0,
    "passed":      0,
    "stage1_hits": 0,   # whitelist/blacklist
    "stage2_hits": 0,   # rule-based
    "stage3_hits": 0,   # signature-based
}

_stats_start_time = time.time()


def print_stats() -> None:
    """Print pipeline statistics summary."""
    uptime  = time.time() - _stats_start_time
    minutes = int(uptime // 60)
    seconds = int(uptime % 60)
    log.info(
        "── Pipeline Stats ── uptime: %dm%ds | "
        "total: %d | allowed: %d | blocked: %d | passed: %d | "
        "stage1: %d | stage2: %d | stage3: %d",
        minutes, seconds,
        _stats["total"], _stats["allowed"],
        _stats["blocked"], _stats["passed"],
        _stats["stage1_hits"], _stats["stage2_hits"], _stats["stage3_hits"],
    )


# ---------------------------------------------------------------------------
# Stage definitions
# ---------------------------------------------------------------------------

def stage1_access_control(packet, whitelist, blacklist, trusted_ips) -> str:
    """
    Stage 1 — Whitelist / Blacklist
    Fastest decision — if we know this IP, handle it immediately.
    Whitelisted: ALLOW (skip all further checks)
    Blacklisted: BLOCK
    Unknown:     PASS (continue to stage 2)
    """
    src_ip = packet[IP].src if packet.haslayer(IP) else None
    if src_ip is None:
        return PASS

    # Blacklist — block immediately
    if check_blacklist_whitelist(packet, whitelist, blacklist):
        return BLOCK

    # Whitelist — allow, skip everything else
    if src_ip in whitelist:
        return ALLOW

    return PASS


def stage2_rule_checks(packet, whitelist, trusted_ips) -> str:
    """
    Stage 2 — Rule-based filtering
    Stateless checks on packet properties.
    Any rule hit = BLOCK.
    All pass = PASS to stage 3.
    """
    rule_checks = [
        lambda: check_icmp(packet, whitelist),
        lambda: check_suspicious_port(packet),
        lambda: check_trusted_protocol(packet, trusted_ips),
        lambda: check_rate_limit(packet),
        lambda: check_port_scan(packet),
    ]

    for check in rule_checks:
        if check():
            return BLOCK

    return PASS


def stage3_signature_checks(packet) -> str:
    """
    Stage 3 — Signature-based detection
    Deeper inspection — stateful, payload, behaviour.
    Ordered cheapest to most expensive.
    Any hit = BLOCK.
    All pass = PASS (packet allowed through).
    """
    signature_checks = [
        check_arp_spoof,         # Layer 2 — no IP needed
        check_flag_scans,        # NULL + XMAS — single packet, no state
        check_fin_scan,          # TCP stateful — handshake tracking
        check_syn_flood,         # TCP volume
        check_udp_flood,         # UDP volume
        check_slowloris,         # TCP behaviour
        check_dns_amplification, # UDP payload
        check_icmp_tunnel,       # ICMP payload — most expensive last
    ]

    for check in signature_checks:
        if check(packet):
            return BLOCK

    return PASS


# ---------------------------------------------------------------------------
# Main packet processor
# ---------------------------------------------------------------------------

def process_packet(packet) -> None:
    """
    Entry point for every captured packet.
    Runs the three-stage pipeline and records statistics.
    """
    try:
        _stats["total"] += 1

        # Non-IP and non-ARP packets skip straight to signature stage
        # (ARP spoofing check needs them)
        if not packet.haslayer(IP) and not packet.haslayer(ARP):
            return

        # Load cached rules (refreshed every 30s, not per packet)
        whitelist, blacklist, trusted_ips = get_rules()

        # ── Stage 1: Access control ──────────────────────────────────────
        if packet.haslayer(IP):
            verdict = stage1_access_control(packet, whitelist, blacklist, trusted_ips)

            if verdict == ALLOW:
                _stats["allowed"]     += 1
                _stats["stage1_hits"] += 1
                return

            if verdict == BLOCK:
                _stats["blocked"]     += 1
                _stats["stage1_hits"] += 1
                return

        # ── Stage 2: Rule-based filtering ────────────────────────────────
        if packet.haslayer(IP):
            verdict = stage2_rule_checks(packet, whitelist, trusted_ips)

            if verdict == BLOCK:
                _stats["blocked"]     += 1
                _stats["stage2_hits"] += 1
                return

        # ── Stage 3: Signature detection ─────────────────────────────────
        verdict = stage3_signature_checks(packet)

        if verdict == BLOCK:
            _stats["blocked"]     += 1
            _stats["stage3_hits"] += 1
            return

        # Packet passed all stages
        _stats["passed"] += 1

    except Exception:
        log.exception("Unhandled error in pipeline — packet skipped")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":

    # Check for root — iptables requires it
    if os.geteuid() != 0:
        log.critical("Must run as root (iptables requires root privileges)")
        sys.exit(1)

    log.info("=" * 60)
    log.info("  Firewall + Signature Pipeline Starting")
    log.info("=" * 60)

    # Restore previously blocked IPs from disk
    _load_persisted_blocked_ips()

    log.info("Pipeline ready — 3 stages active")
    log.info("  Stage 1: Whitelist / Blacklist")
    log.info("  Stage 2: Rule-based filtering  (6 checks)")
    log.info("  Stage 3: Signature detection   (8 signatures)")
    log.info("Listening on all interfaces — Ctrl+C to stop")
    log.info("-" * 60)

    try:
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        log.info("-" * 60)
        log.info("Shutting down")
        print_stats()
