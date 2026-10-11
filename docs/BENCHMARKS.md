# Benchmarks

All numbers below, except the ARP/IP Spoofing row (see footnote ¹), come from an actual run of [`tools/run_benchmarks.py`](../tools/run_benchmarks.py) (`test_run8` in `benchmarks/results/`), on a single Kali VM running Mininet + Open vSwitch + the controller + the dashboard together. 3 repetitions per scenario. Nothing here is hand-written or estimated — see the raw CSV for every individual repetition.

## Results

| Scenario | n | Detection Rate | Label Accuracy | Attacker Blocked | Victim Also Blocked | Uninvolved Hosts Blocked (false positives) | Mean Detection Latency | Mean Block Latency | Mean CPU Overhead |
|---|---|---|---|---|---|---|---|---|---|
| ARP/IP Spoofing | — | manual¹ | — | manual¹ | — | manual¹ | — | — | — |
| SYN Flood | 3 | 100% | 100% | 100% | 100% | 0 | 7.68s | 10.59s | 0.06% |
| UDP Flood | 3 | 100% | 100% | 100% | 0% | 0 | 6.82s | 9.87s | 0.17% |
| ICMP Flood | 3 | 100% | 100% | 100% | 100% | 0 | 6.33s | 9.39s | 0.10% |
| Horizontal Scan | 3 | 100% | 100% | 100% | 0% | 0 | 2.07s | 15.37s² | 0.45% |
| Baseline (no attack) | 3 | — | — | — | — | — | — | — | false alarm rate: 0% |
| Legitimate multi-host traffic | 3 | — | — | — | — | — | — | — | false alarm rate: 0% |

¹ Verified manually during development (predates the automated harness); not yet re-run through `run_benchmarks.py` with n=3 — a reasonable next step before citing this number in a paper.
² See caveat below — this number is inflated by test methodology, not representative of real-world scan-block latency.

## How to read these columns

- **Detection Rate**: a qualifying alert (any flood-family type for floods, `PORT_SCAN` for scans) was raised and attributed to the attacker's MAC.
- **Label Accuracy**: the alert additionally carried the *correct* protocol-specific type (`SYN_FLOOD` vs. just some flood-family alert). Reported separately from detection on purpose — these are different claims, and conflating them would overstate precision.
- **Attacker/Victim Blocked**: which hosts actually ended up with a live OpenFlow drop rule, confirmed via the dashboard's `blocked_macs`, *not* inferred from alert text.
- **Uninvolved hosts blocked**: a host that was neither the attacker nor the victim getting blocked — this is the real false-positive metric for attack scenarios.
- **Detection/Block latency**: wall-clock measured entirely on the harness machine (attack launch → first qualifying alert observed / → attacker appears in `blocked_macs`), avoiding any cross-machine clock-sync assumption.
- **CPU overhead**: instantaneous controller CPU (from `/proc/<pid>/stat` deltas, not `ps`'s lifetime average), scenario mean minus a pre-scenario idle baseline. The controller shares the machine with Mininet, Scapy, and the harness itself, so treat this as an upper bound on the controller's own overhead, not an isolated measurement.

## Why victim-blocked rate differs by protocol (UDP: 0%, SYN/ICMP: 100%)

A flood provokes a reply from the victim: an OS typically answers unsolicited SYNs with RSTs and ICMP echo requests with echo replies, at the same rate as the incoming flood — which is itself enough to cross `FLOOD_PPS_THRESHOLD` in the *reverse* direction and get the victim blocked too. UDP to a closed port on Linux usually gets a single rate-limited ICMP port-unreachable rather than a reply per packet, so it doesn't reach the same reverse rate. This is expected behavior given the detection design, not a bug — but it's a real operational property worth stating plainly: this system can and does sometimes block the victim of an attack, not just the attacker, depending on protocol.

## Important caveat: horizontal scan's block latency (15.37s)

This number is **inflated by the test methodology**, not representative of a real scanner's block latency. Our scan detector requires two *separate, flow-cache-expired* over-threshold events before auto-blocking (to avoid blocking on a single burst). A real attacker's own repeated scanning cadence would trigger this naturally, but to test the mechanism deterministically, the harness forces two sweeps spaced apart by `FLOW_IDLE_TIMEOUT + margin` seconds specifically so each sweep generates fresh PacketIns. That forced spacing — not detection or enforcement overhead — accounts for most of the 15.37s. **Detection latency (2.07s) is the number that reflects real responsiveness**; block latency here is an artifact of proving the escalation path works at all.

## Reproducing these results

```bash
sudo python3 tools/run_benchmarks.py \
  --admin-password <your-password> \
  --flood-script mininet_script/flood.py \
  --flow-idle-timeout 10 \
  --scan-window-seconds 20 \
  --repetitions 3 \
  --output results.csv
```

Controller must be started with matching environment variables first — see [`docs/INSTALL.md`](INSTALL.md) §7. The harness auto-generates `results.csv` (one row per scenario per repetition) and `results_summary.csv` (aggregated rates/means, same shape as the table above).

## What isn't benchmarked yet

- Scalability beyond 6 hosts / 1 switch.
- Distribution shift (traffic pattern changes mid-run).
- Unseen-attack generalization (train the online model on one attack type, test on another).
- Statistical significance testing (current n=3 gives point estimates, not confidence intervals).

These are Phase 2 (research) items — see the project's working notes for the full research roadmap.
