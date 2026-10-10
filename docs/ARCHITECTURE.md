# Architecture

## 1. How this is "an SDN" — what it replaces

In a traditional network, the logic that decides "learn this MAC on this port," "is this ARP reply suspicious," and "should I drop this frame" is baked into each switch's own firmware/ASIC. Smarter security behavior (Dynamic ARP Inspection, port security) either requires a specific switch model that already has that feature, or a separate IDS/IPS appliance watching a mirrored copy of traffic — which can alert but not directly instruct the switch to block anything.

SDN splits the switch into two planes:
- **Data plane** — Open vSwitch, which only matches packets against flow-table rules and executes an action. No decision-making of its own.
- **Control plane** — pulled out and run centrally as ordinary software: [`controller/sec_switch.py`](../controller/sec_switch.py). Every switch asks this one controller "what do I do with a packet I don't have a rule for?" over OpenFlow.

| Traditional component | What replaces it here |
|---|---|
| Switch ASIC's built-in MAC learning | `packet_in_handler()` learning `mac_to_port` in software |
| Dynamic ARP Inspection (vendor-locked switch feature) | ARP/IP binding consistency check, running as a controller app — vendor-independent |
| A separate IDS/IPS watching mirrored traffic | The same controller that forwards traffic also inspects it inline, no mirror port needed |
| A NAC system pushing ACLs out-of-band | `OFPFlowMod` block rules pushed directly and immediately to every connected switch |

## 2. Component overview

```
Mininet / Open vSwitch  <--OpenFlow 1.3-->  Ryu Controller (sec_switch.py)
                                                   |
                                         shared JSON state (atomic writes)
                                                   |
                                         Flask Dashboard (app.py)
```

**Controller (`controller/sec_switch.py`)**
- L2 learning switch (MAC → port)
- ARP/IP binding consistency checks (spoof detection)
- Periodic `OFPFlowStatsRequest` polling (flood detection)
- Destination fan-out tracking per source MAC (scan detection)
- Auto-block via `OFPFlowMod`, pushed to every connected switch
- A background command-monitor greenthread applies dashboard block/unblock commands promptly instead of waiting for the next PacketIn
- Writes `shared/state.json` (alerts, ARP table) and `shared/blocked.json` (blocklist)

**Dashboard (`dashboard/app.py`)**
- Reads shared state, renders alerts/ARP table/blocklist, manual block/unblock
- Two layers of AI analysis, kept honestly separate:
  1. Rule-based threat triage (fixed thresholds) — fast, not real ML
  2. Genuine online/incremental anomaly model (see §4)
- A real, always-computed 3-way method comparison (fixed threshold vs. batch `IsolationForest` vs. the online model), run on identical data every request

## 3. Why flood detection needs flow-stats polling, not PacketIn counting

Once a flow is installed on the switch, matching traffic is handled entirely in hardware and never reaches the controller again. A flood's packets after the first one are therefore invisible to a naive "count PacketIn events" approach. The controller instead polls each switch's flow table directly every `FLOOD_POLL_INTERVAL` seconds (`OFPFlowStatsRequest`), computes the packet-count delta between polls, and flags a flow whose packets/sec exceeds `FLOOD_PPS_THRESHOLD` for `FLOOD_CONSECUTIVE_POLLS_TO_BLOCK` consecutive polls (avoiding a false positive from one legitimate burst).

The L4 protocol label (SYN/UDP/ICMP) is recorded once, when a flow is first installed, from whatever packet triggered that install — flow stats don't carry L4 info once traffic is cached in hardware. This is why unicast forwarding flows carry an `idle_timeout` (`FLOW_IDLE_TIMEOUT_SECONDS`, env `HOLO_FLOW_IDLE_TIMEOUT`): without it, a pair's very first packet (e.g. an ARP-triggered ping during a connectivity check) would label every future flood between that pair forever. With the timeout, an idle pair's flow expires and the next burst re-installs it with a fresh, correct label. A continuous attack keeps its own flow alive (traffic keeps matching), so this doesn't cause churn mid-attack.

## 4. Why scan detection works differently (and faster)

A host contacting many **distinct destination MACs** in a short window is the signature of horizontal scanning (e.g. `nmap` sweeping a subnet). Unlike floods, this *is* visible via PacketIn, because each new destination is by definition a new flow. The controller tracks, per source MAC, the set of distinct destinations touched within `SCAN_WINDOW_SECONDS`; crossing `SCAN_DISTINCT_DEST_THRESHOLD` raises an alert, and sustaining it for `FLOOD_CONSECUTIVE_POLLS_TO_BLOCK` separate over-threshold events triggers a block.

This is why scan detection has much lower latency than flood detection in the benchmark results — it reacts to the event stream directly rather than waiting on a polling cycle.

**Important interaction with the idle timeout:** because flows are cached, a second scan sweep against the *same* destinations within `FLOW_IDLE_TIMEOUT_SECONDS` of the first will match the existing flows in hardware and never generate a new PacketIn at all — so it won't register as a second "strike" toward auto-block. A real, sustained scanner probing fresh hosts each time doesn't hit this; it only matters for *repeated* scans of the same target set, which is also why the benchmark harness spaces its two test sweeps apart by more than the idle timeout.

## 5. The online anomaly model

Classic online multivariate anomaly detection: per-feature running mean and variance are updated incrementally with **Welford's algorithm** (the standard numerically-stable method for streaming mean/variance), and a new observation is scored by its **squared Mahalanobis distance** from the running mean, converted to a **chi-square percentile**.

```
For each MAC's feature vector x, on every check:
  if fewer than 5 total observations learned model-wide:
    report "cold start", don't score
  else:
    z_i = (x_i - running_mean_i) / sqrt(running_variance_i)
    d²  = Σ z_i²
    anomaly_percentile = chi2.cdf(d², df = num_features) × 100
    flag as anomalous if anomaly_percentile >= 95
  update running_mean, running_variance incrementally via Welford's algorithm
    using x (AFTER scoring, so this observation doesn't influence its own score)
  persist (running_mean, running_variance, n) to disk
```

**Why not a linear one-class model.** An earlier version used scikit-learn's `SGDOneClassSVM` for online learning via `partial_fit()`. Testing found a real methodological flaw: a linear one-class classifier only learns a single half-space, so a point far from training data in the half-space's "normal" direction can still score as an inlier. Mahalanobis distance grows for deviation in *any* direction, which is what's actually needed here.

**Feature vector** (per MAC, derived from alert history): total alerts, ARP-spoof count, IP-spoof count, MAC-move count, flood count, scan count, distinct IPs touched, distinct switches, alert rate/sec, average seconds between alerts. Count/rate features are `log1p`-transformed before scoring (heavy-tailed: a normal host has ~0-2 alerts, an attacker can have dozens).

## 6. Known, documented limitations

1. **Slowloris and single-host vertical port scanning are undetectable** with the current L2 (MAC-pair) flow granularity. Both require L4 5-tuple flow matching — a larger architectural change, deliberately deferred rather than approximated with a detector that wouldn't actually work.
2. The online anomaly model uses **diagonal covariance** (per-feature variance, not a full covariance matrix) — doesn't capture correlations between features. A documented simplification for implementation simplicity and numerical stability with small sample counts.
3. Controller in-memory state (`mac_to_port`, `ip_to_mac`, offense counters) is per-process; a full restart loses it. Only the online model and blocklist persist to disk. Per-switch learned state is also cleared on switch reconnect (not on blocklist) to avoid stale-state false positives after a topology restart.
4. Flood protocol labeling is a single snapshot at flow-install time (see §3) — recalibrated by the idle timeout, but still a point-in-time label, not continuous re-classification.
5. All validation to date is in Mininet; no physical OpenFlow hardware has been tested.
6. Ryu is single-threaded/single-controller; no documented scalability ceiling has been established beyond the tested 6-host topology.
7. The horizontal-scan heuristic cannot distinguish a legitimate "contact many hosts briefly" pattern (e.g. a connectivity health-check, or `pingAll()` itself) from reconnaissance — both look identical: 5+ distinct destinations in a short window. Deployers should scope `SCAN_DISTINCT_DEST_THRESHOLD`/`SCAN_WINDOW_SECONDS` to their network's actual baseline behavior.
