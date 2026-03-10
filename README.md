# 🛡️ Python Network Firewall & Intrusion Detection System

A packet-level firewall and signature-based intrusion detection system built with Python and Scapy. Designed as a learning project covering real network attack detection techniques.

---

## 📋 What It Does

The system runs a **3-stage pipeline** that inspects every packet passing through the network interface:

```
Packet
  │
  ▼
Stage 1 — Access Control      (Whitelist / Blacklist)
  │
  ▼
Stage 2 — Rule-Based Filtering (Ports, Rates, ICMP, Scan Detection)
  │
  ▼
Stage 3 — Signature Detection  (Attack pattern matching)
  │
  ▼
PASS or BLOCK
```

---

## 🔍 Attacks Detected

### Rule-Based (Stage 2)
| Attack | Detection Method |
|--------|-----------------|
| Port Scan | Too many unique ports in time window |
| Rate Flood | Packet rate exceeds threshold |
| ICMP Flood | Ping rate limiting |
| Suspicious Ports | Known malware/backdoor ports |

### Signature-Based (Stage 3)
| Attack | Detection Method |
|--------|-----------------|
| NULL Scan | TCP flags == 0x00 |
| XMAS Scan | TCP flags == FIN+PSH+URG |
| FIN Scan | FIN without completed 3-way handshake |
| SYN Flood | High SYN rate per second |
| UDP Flood | High UDP packet rate |
| Slowloris | Many stale half-open HTTP connections |
| DNS Amplification | Oversized DNS response (>512 bytes) |
| ICMP Tunneling | Large ICMP payload + known tool signatures |
| ARP Spoofing | Same IP claimed by multiple MACs |

---

## 📁 Project Structure

```
.
├── pipeline.py            # Main entry point — runs the full 3-stage pipeline
├── firewall_engine.py     # Stage 1 + 2 — rule-based filtering
├── signature_engine.py    # Stage 3 — signature-based detection
├── firewall_rules.json    # Configuration — whitelist, blacklist, trusted IPs
├── blocked_ips.json       # Auto-generated — persists blocked IPs across restarts
└── firewall.log           # Auto-generated — full activity log
```

---

## ⚙️ Requirements

### System
- Linux (Ubuntu / Debian recommended)
- Python 3.10+
- Root privileges (iptables requires root)

### Python packages
```bash
pip install scapy
```

---

## 🚀 How to Run

### 1. Clone the repository
```bash
git clone https://github.com/YOURNAME/YOURREPO.git
cd YOURREPO
```

### 2. Configure your rules
Edit `firewall_rules.json` to add your IPs:
```json
{
  "ip_whitelist": ["127.0.0.1", "192.168.1.1"],
  "ip_blacklist": ["10.0.0.99"],
  "trusted_list": ["192.168.1.1"]
}
```

### 3. Run the pipeline
```bash
sudo python3 pipeline.py
```

### 4. Stop
```
Ctrl+C
```
Statistics are printed on shutdown.

---

## 🔧 Configuration

### `firewall_rules.json`

| Field | Description |
|-------|-------------|
| `ip_whitelist` | These IPs skip all checks — always allowed |
| `ip_blacklist` | These IPs are blocked immediately at Stage 1 |
| `trusted_list` | These IPs bypass restricted port checks (SSH, RDP, MySQL) |

Rules reload automatically every 30 seconds — no restart needed.

### Key thresholds (editable in each engine file)

| Setting | Default | File |
|---------|---------|------|
| Rate limit | 40 pkt/s | `firewall_engine.py` |
| SYN flood | 20 SYNs/s | `signature_engine.py` |
| UDP flood | 150 pkts/s | `signature_engine.py` |
| Port scan window | 10 ports / 10s | `firewall_engine.py` |
| ICMP payload limit | 100 bytes | `signature_engine.py` |
| DNS response limit | 512 bytes | `signature_engine.py` |

---

## 🧪 Testing

Run these from a **second machine or VM** on your network.

```bash
# Test NULL scan detection
nmap -sN <target_ip>

# Test XMAS scan detection
nmap -sX <target_ip>

# Test FIN scan detection
nmap -sF <target_ip>

# Test SYN flood detection
hping3 -S --flood -p 80 <target_ip>

# Test ping flood (ICMP rate limit)
ping -f <target_ip>

# Test port scan detection
nmap -p 1-1000 <target_ip>
```

> ⚠️ Only test on networks you own or have explicit permission to test on.

---

## 📊 Pipeline Output

On shutdown, the pipeline prints a statistics summary:

```
Pipeline Stats — uptime: 5m32s | total: 4821 |
allowed: 120 | blocked: 43 | passed: 4658 |
stage1: 15 | stage2: 12 | stage3: 16
```

Full activity is logged to `firewall.log`.

---

## ⚠️ Known Limitations

This is a **student learning project**, not a production firewall. Known limitations:

- Uses Scapy (Python userspace) — not suitable for high-traffic environments
- No concurrency locks on shared state
- ARP spoofing detection logs only — MAC-level blocking requires `ebtables`
- No web interface or management console
- Tested on Ubuntu 22.04 / Python 3.11

For production use, consider `nftables`, `eBPF`, or `Suricata`.

---

## 📚 What I Learned

- TCP/IP packet structure and flag combinations
- How network attacks work at the packet level (both offensive and defensive)
- Stateful vs stateless packet inspection
- Python Scapy for packet capture and analysis
- iptables rule management from Python
- Designing a modular, extensible detection pipeline

---

## 👤 Author

**Your Name**  
Ilyass Lachheb — Cybersecurity / Networks  
Year: 2025–2026
