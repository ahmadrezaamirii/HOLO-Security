# HOLO Security

An SDN-based network security system built on Ryu (OpenFlow 1.3) that detects and automatically mitigates ARP/IP spoofing, SYN/UDP/ICMP flood (DDoS), and horizontal port/host scanning — with a real, online/incremental machine-learning layer on top, not a static rule engine dressed up as AI.

Built as a final-semester computer engineering thesis project. Every number in this README comes from an actual run recorded by [`tools/run_benchmarks.py`](tools/run_benchmarks.py) on a real Mininet + Open vSwitch + Ryu setup — see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for the raw CSVs and methodology.

## What it does

- **Detects** ARP spoofing, IP/MAC binding inconsistency, MAC-move, SYN/UDP/ICMP flood, and horizontal scanning (one host probing many others).
- **Mitigates automatically** — pushes `OFPFlowMod` drop rules to every connected switch, no human in the loop required.
- **Learns**, genuinely — an online anomaly model (Welford mean/variance + Mahalanobis distance, chi-square scored) updates with every check and persists across restarts, instead of a batch model retrained from scratch.
- **Compares itself honestly** — every analysis computes a fixed-threshold baseline, a batch-retrained scikit-learn `IsolationForest`, and the online model side by side on identical data, so "our method vs. baseline" numbers are always real.
- **Enforces for real** — unblocking a host actually removes the OpenFlow drop rule; this is verified by the benchmark harness, not assumed.

## Results (n=3 repetitions, real Mininet run)

| Scenario | Detection Rate | Label Accuracy | Attacker Blocked | False Positives | Mean Detection Latency |
|---|---|---|---|---|---|
| ARP/IP Spoofing | 100% | — | 100% | 0 | — |
| SYN Flood | 100% | 100% | 100% | 0 | 7.68s |
| UDP Flood | 100% | 100% | 100% | 0 | 6.82s |
| ICMP Flood | 100% | 100% | 100% | 0 | 6.33s |
| Horizontal Scan | 100% | 100% | 100% | 0 | 2.07s |
| Legitimate multi-host traffic | — | — | — | **0% false alarm** | — |

Scan detects faster because it fires on the first matching PacketIn; flood detection waits on the controller's periodic flow-stats poll (tunable, default every 3s). See [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for the full methodology, caveats (e.g. why scan's *block* latency looks inflated in this specific test), and raw per-repetition data.

## Architecture

```
Mininet / Open vSwitch  <--OpenFlow 1.3-->  Ryu Controller (controller/sec_switch.py)
                                                   |
                                         shared JSON state (atomic writes)
                                                   |
                                         Flask Dashboard (dashboard/app.py)
                                         - alert feed, blocklist, manual override
                                         - rule-based triage + online ML model
                                         - 3-way method comparison
```

Full breakdown of each detection mechanism (why flood detection needs flow-stats polling instead of PacketIn counting, why scan detection works differently, the online learning algorithm) is in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## Quick start

### Default dashboard credentials

For local development the dashboard defaults to:

- Username: `admin`
- Password: `admin123`

For local demo use only. The dashboard listens on `127.0.0.1` by default, so it is not reachable from the network. To set your own credentials:

```bash
export HOLO_ADMIN_USER="your_username"
export HOLO_ADMIN_PASSWORD="your_password"
python3 app.py
```


```bash
# 1. Controller (needs Python 3.9 — see docs/INSTALL.md for why)
cd controller
ryu-manager --verbose sec_switch.py

# 2. Dashboard (separate terminal)
cd dashboard
pip install -r requirements.txt
export HOLO_ADMIN_PASSWORD="choose-a-real-password"
python3 app.py
# -> http://127.0.0.1:5000

# 3. Test topology (separate terminal, as root)
sudo mn --topo single,6 --controller=remote,ip=127.0.0.1,port=6653
```

Full install instructions (including the Ryu/Python version pitfalls that cost real time to work through) are in [`docs/INSTALL.md`](docs/INSTALL.md).

## Generating test traffic

```bash
mininet> h1 python3 mininet_script/flood.py syn 10.0.0.2 --iface h1-eth0 --duration 10
mininet> h1 python3 mininet_script/flood.py udp 10.0.0.2 --iface h1-eth0 --duration 10
mininet> h1 python3 mininet_script/flood.py icmp 10.0.0.2 --iface h1-eth0 --duration 10
mininet> h1 python3 mininet_script/flood.py scan x --iface h1-eth0 --scan-hosts 10.0.0.2,10.0.0.3,10.0.0.4
```

To reproduce the full benchmark suite:

```bash
sudo python3 tools/run_benchmarks.py \
  --admin-password <your-password> \
  --flood-script mininet_script/flood.py \
  --flow-idle-timeout 10 --scan-window-seconds 20 \
  --repetitions 3 --output results.csv
```

## Project structure

```
controller/          Ryu SDN controller — detection + enforcement
dashboard/            Flask web dashboard — visualization, manual control, AI analysis
mininet_scripts/      Scapy-based attack traffic generator for testing
tools/                Automated benchmark harness
docs/                 Architecture, install guide, benchmark methodology, limitations
benchmarks/results/   Raw CSV output from real benchmark runs
```

## Known limitations

- **Slowloris and single-host vertical port scanning are not detected.** Both need L4 (port-level) flow visibility; flows here are matched at L2 (MAC pair) by design. Documented in detail in [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).
- Validated in Mininet only — no physical OpenFlow hardware tested.
- Single-controller, single-process — no documented ceiling established beyond the tested 6-host topology.
- The online anomaly model uses diagonal covariance (per-feature variance), not a full covariance matrix.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the complete, honest limitations list, including why each one is a deliberate tradeoff rather than an oversight.

## Tech stack

Ryu (OpenFlow 1.3) · Open vSwitch · Mininet · Flask · scikit-learn · NumPy/SciPy · Scapy

## License

MIT — see [`LICENSE`](LICENSE).
