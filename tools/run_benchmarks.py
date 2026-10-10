#!/usr/bin/env python3
"""
tools/run_benchmarks.py — HOLO Security automated benchmark harness.

RUN ON: the same machine as the controller + dashboard (Kali), as root
(Mininet's Python API needs it). Controller and dashboard must already be
running; this script builds/tears down only the Mininet topology.

    sudo python3 run_benchmarks.py --admin-password \\
        --flood-script ~/Desktop/Holo-Security/mininet_script/flood.py \\
        --repetitions 3 --output results.csv

IMPORTANT — keep these in sync with how you started the controller:
    --flow-idle-timeout  must equal HOLO_FLOW_IDLE_TIMEOUT (default 10)
The harness waits that long (+ margin) between scenarios so that the
controller's cached per-pair flows expire and every scenario starts from a
clean flow/label state. Start the controller with thresholds that suit
your hardware (HOLO_FLOOD_PPS_THRESHOLD etc.) and check the "Active
thresholds" line it prints at startup.

WHAT IS MEASURED (one CSV row per scenario per repetition)
  detected              the system raised a qualifying alert attributed to
                        the attacker's MAC (any flood-family alert for
                        floods; PORT_SCAN for scans)
  label_correct         the alert carried the protocol-specific label
                        (SYN_FLOOD/UDP_FLOOD/ICMP_FLOOD) — reported
                        separately from `detected` on purpose: detecting an
                        attack and naming its protocol are different claims
  detection_latency_s   harness wall-clock from launching the attack to
                        first observing the qualifying alert via the
                        dashboard API (single machine => no clock sync;
                        includes generator start-up such as ARP resolution
                        and the controller's flow-stats poll interval)
  block_latency_s       same clock, until the attacker's MAC shows up as
                        blocked
  attacker_blocked / victim_blocked / uninvolved_blocked_count
                        who ended up blocked. `uninvolved` = hosts that were
                        neither attacker nor victim => real false positives.
                        The victim is reported separately because a flood
                        provokes victim replies (RST / ICMP unreachable)
                        that can themselves exceed the rate threshold.
  enforcement_verified  after a block, a ping from the attacker actually
                        FAILS (the drop rule is really on the switch, not
                        just recorded in a file)
  false_alarm           (benign scenarios only) any block or attack-type
                        alert during traffic that should be ignored
  cpu_*_pct             controller CPU as % of ONE core, INSTANTANEOUS,
                        computed from /proc/<pid>/stat deltas — idle
                        baseline vs. during the scenario. (ps's %cpu is a
                        lifetime average and is not used.) The controller
                        shares the machine with Mininet/Scapy/this script,
                        so treat as an upper bound on controller overhead.
  rule_threshold_flagged / iforest_flagged / online_flagged / online_score
                        what each of the 3 comparison methods said about
                        the attacker's MAC, from /api/ai/analyze right
                        after the scenario (the online model keeps learning
                        across the run unless you pass --keep-model)

NOT COVERED: Slowloris and single-host port scans (documented L2 limit).
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time

import requests

try:
    from mininet.net import Mininet
    from mininet.node import RemoteController
    from mininet.log import setLogLevel
    MININET_AVAILABLE = True
except ImportError:  # allows importing this module for unit tests
    MININET_AVAILABLE = False


FLOOD_FAMILY = {"SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "FLOOD_SUSPECTED"}
ATTACK_ALERT_TYPES = FLOOD_FAMILY | {
    "PORT_SCAN", "ARP_SPOOF", "IP_SPOOF", "MAC_MOVE", "MAC_BLOCKED", "SPOOF",
}

FIELDNAMES = [
    "scenario", "kind", "repetition", "actor", "actor_mac", "victim", "victim_mac",
    "expected_label", "detected", "label_correct", "detection_latency_s",
    "block_latency_s", "attacker_blocked", "victim_blocked", "enforcement_verified",
    "uninvolved_blocked_count", "uninvolved_blocked_macs", "false_alarm",
    "new_alert_count", "new_alert_types",
    "cpu_idle_mean_pct", "cpu_during_mean_pct", "cpu_during_max_pct",
    "cpu_overhead_pct", "controller_rss_mb",
    "rule_threshold_flagged", "iforest_flagged", "online_flagged",
    "online_score", "online_cold_start",
    "cleanup_ok", "generator_output", "error",
]


# ---------------------------------------------------------------------------
# Dashboard HTTP client
# ---------------------------------------------------------------------------

class DashboardClient:
    def __init__(self, base_url, password, username="admin"):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.csrf_token = None
        self._login(username, password)

    def _login(self, username, password):
        r = self.session.post(
            "%s/login" % self.base_url,
            data={"username": username, "password": password}, timeout=5,
        )
        r.raise_for_status()
        data = r.json()
        if not data.get("success"):
            raise RuntimeError("Dashboard login failed: %s" % data)
        r = self.session.get("%s/" % self.base_url, timeout=5)
        m = re.search(r'name="csrf-token" content="([a-f0-9]*)"', r.text)
        self.csrf_token = m.group(1) if m else None
        if not self.csrf_token:
            raise RuntimeError("Could not extract CSRF token from dashboard index page")

    def _post(self, path, **kw):
        return self.session.post(
            "%s%s" % (self.base_url, path),
            headers={"X-CSRFToken": self.csrf_token}, timeout=kw.pop("timeout", 10), **kw
        )

    def get_state(self):
        r = self.session.get("%s/api/state" % self.base_url, timeout=5)
        r.raise_for_status()
        return r.json()

    def unblock(self, mac=None, ip=None):
        payload = {}
        if mac:
            payload["mac"] = mac
        if ip:
            payload["ip"] = ip
        return self._post("/api/unblock", json=payload).json()

    def reset_online_model(self):
        return self._post("/api/ai/reset-model").json()

    def analyze(self):
        r = self._post("/api/ai/analyze", timeout=30)
        r.raise_for_status()
        return r.json()


# ---------------------------------------------------------------------------
# Instantaneous controller CPU / memory from /proc (Linux, same machine)
# ---------------------------------------------------------------------------

class ControllerSampler:
    def __init__(self):
        self.clk = os.sysconf("SC_CLK_TCK")
        self.pids = []
        self._last = None

    @staticmethod
    def find_pids():
        try:
            out = subprocess.check_output(["pgrep", "-f", "ryu-manager"], timeout=3)
        except Exception:
            return []
        me = os.getpid()
        return [int(p) for p in out.decode().split() if int(p) != me]

    @staticmethod
    def _ticks(pid):
        try:
            with open("/proc/%d/stat" % pid) as f:
                data = f.read()
            tail = data[data.rindex(")") + 2:].split()
            return int(tail[11]) + int(tail[12])      # utime + stime
        except Exception:
            return None

    def _total_ticks(self):
        total, ok = 0, False
        for pid in self.pids:
            t = self._ticks(pid)
            if t is not None:
                total += t
                ok = True
        return total if ok else None

    def prime(self):
        self.pids = self.find_pids()
        t = self._total_ticks()
        self._last = (time.time(), t) if t is not None else None

    def sample(self):
        """CPU% of one core since the previous call, or None if unavailable."""
        if self._last is None:
            self.prime()
            return None
        t = self._total_ticks()
        now = time.time()
        if t is None:
            return None
        wall0, t0 = self._last
        dt = now - wall0
        if dt <= 0:
            return None
        self._last = (now, t)
        return max(0.0, (t - t0) / float(self.clk) / dt * 100.0)

    def rss_mb(self):
        total_kb, ok = 0, False
        for pid in self.pids:
            try:
                with open("/proc/%d/status" % pid) as f:
                    for line in f:
                        if line.startswith("VmRSS:"):
                            total_kb += int(line.split()[1])
                            ok = True
            except Exception:
                pass
        return round(total_kb / 1024.0, 1) if ok else None


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------

def alert_key(a):
    return json.dumps(a, sort_keys=True)


def mean(xs):
    return sum(xs) / len(xs) if xs else None


def rnd(x, nd=3):
    return "" if x is None else round(x, nd)


def ping_ok(host, ip, wait=1):
    out = host.cmd("ping -c 1 -W %d %s" % (wait, ip))
    return " 1 received" in out or "1 received" in out


def pick_probe(net, *exclude):
    for h in reversed(net.hosts):
        if h.name not in exclude:
            return h
    return net.hosts[0]


def wait_reachable(net, host, timeout, poll=1.0):
    probe = pick_probe(net, host.name)
    end = time.time() + timeout
    while time.time() < end:
        if ping_ok(host, probe.IP()):
            return True
        time.sleep(poll)
    return False


def comparison_flags(analysis, mac):
    """Extract what each of the 3 methods said about `mac`."""
    out = {"rule_threshold_flagged": "n/a", "iforest_flagged": "n/a",
           "online_flagged": "n/a", "online_score": "", "online_cold_start": ""}
    mc = (analysis or {}).get("method_comparison") or {}
    for key, col in (("rule_threshold", "rule_threshold_flagged"),
                     ("batch_isolation_forest", "iforest_flagged"),
                     ("our_online_method", "online_flagged")):
        res = mc.get(key) or {}
        if not res.get("available"):
            continue
        h = next((x for x in res.get("hosts", []) if x.get("mac") == mac), None)
        out[col] = "" if h is None else bool(h.get("is_anomaly"))
        if key == "our_online_method" and h is not None:
            out["online_score"] = "" if h.get("anomaly_score") is None else h["anomaly_score"]
            out["online_cold_start"] = bool(h.get("cold_start"))
    return out


# ---------------------------------------------------------------------------
# Scenarios
# ---------------------------------------------------------------------------

SCENARIOS = [
    {"name": "baseline_no_attack", "kind": "baseline", "actor": "h3", "peer": "h4"},
    {"name": "syn_flood", "kind": "flood", "actor": "h1", "victim": "h2",
     "mode": "syn", "expected_label": "SYN_FLOOD"},
    {"name": "udp_flood", "kind": "flood", "actor": "h1", "victim": "h2",
     "mode": "udp", "expected_label": "UDP_FLOOD"},
    {"name": "icmp_flood", "kind": "flood", "actor": "h1", "victim": "h2",
     "mode": "icmp", "expected_label": "ICMP_FLOOD"},
    {"name": "horizontal_scan", "kind": "scan", "actor": "h1",
     "expected_label": "PORT_SCAN"},
    {"name": "legitimate_multihost_access", "kind": "legit", "actor": "h5"},
]


def observe_seconds(scenario, args):
    kind = scenario["kind"]
    if kind == "flood":
        return args.flood_duration + args.detect_margin
    if kind == "scan":
        if args.scan_observe is not None:
            return args.scan_observe
        # Covers: ARP resolution for round 1 + round 1 send + the
        # idle-timeout-spaced gap before round 2 + round 2 send + margin
        # for the controller to process the resulting PacketIns and poll.
        return args.flow_idle_timeout + 20
    if kind == "legit":
        return 12
    return 10


def launch_traffic(net, scenario, args, rep, logfile):
    """Start the scenario's traffic in the BACKGROUND so we can poll the
    dashboard while it runs (otherwise latency would be measured only after
    the traffic ends)."""
    kind = scenario["kind"]
    actor = next(h for h in net.hosts if h.name == scenario["actor"])
    iface = "%s-eth0" % actor.name
    if kind == "flood":
        victim = next(h for h in net.hosts if h.name == scenario["victim"])
        cmd = "python3 -u %s %s %s --iface %s --duration %d" % (
            args.flood_script, scenario["mode"], victim.IP(), iface, args.flood_duration)
    elif kind == "scan":
        ips = ",".join(h.IP() for h in net.hosts if h.name != actor.name)
        # --repeat 2: a single sweep only ever raises an alert (one
        # over-threshold check); two sweeps let us also exercise the
        # sustained-scan auto-block path, same as the flood scenarios do
        # naturally via repeated flow-stats polls. The delay between
        # sweeps MUST exceed FLOW_IDLE_TIMEOUT: round 1 installs a flow
        # per destination, and while that flow is still alive, round 2's
        # identical traffic matches it in hardware and never reaches the
        # controller as a new PacketIn at all -- so a short delay here
        # silently produces only one alert no matter how many rounds you
        # run. A margin is added on top of the raw idle timeout for
        # scheduling jitter under CPU contention.
        scan_repeat_delay = args.flow_idle_timeout + 3
        cmd = "python3 -u %s scan x --iface %s --scan-hosts %s --repeat 2 --repeat-delay %d" % (
            args.flood_script, iface, ips, scan_repeat_delay)
    elif kind == "legit":
        ips = " ".join([h.IP() for h in net.hosts if h.name != actor.name][:4])
        cmd = ("(for ip in %s; do ping -c 1 -W 1 $ip; sleep 1.5; done)" % ips)
    else:  # baseline: light, ordinary traffic between two hosts
        peer = next(h for h in net.hosts if h.name == scenario["peer"])
        cmd = "ping -c 4 -i 1 -W 1 %s" % peer.IP()
    actor.cmd("%s > %s 2>&1 &" % (cmd, logfile))
    return actor


def settle_seconds(args):
    """How long to wait for ALL per-source detector state to naturally
    age out: both the flow/label cache (FLOW_IDLE_TIMEOUT) and the scan
    fan-out window (SCAN_WINDOW_SECONDS) -- whichever is longer, since
    pingAll() and horizontal_scan both leave scan-tracking entries that
    only expire after SCAN_WINDOW_SECONDS regardless of flow idle timeout.
    """
    return max(args.flow_idle_timeout, args.scan_window_seconds) + args.settle_margin


def cleanup_after_scenario(net, dash, macs, args):
    """Unblock, wait until the hosts are truly reachable again (the drop
    rule must actually be gone from the switch), then wait long enough for
    ALL per-source detector state (flow/label cache AND scan window) to
    naturally age out before the next scenario starts."""
    mac_to_host = {h.MAC(): h for h in net.hosts}
    ok = True
    for mac in macs:
        try:
            dash.unblock(mac=mac)
        except Exception:
            ok = False
    for mac in macs:
        host = mac_to_host.get(mac)
        if host is not None and not wait_reachable(net, host, args.unblock_timeout):
            ok = False
    time.sleep(settle_seconds(args))
    return ok


def run_scenario(net, dash, sampler, scenario, args, rep):
    kind = scenario["kind"]
    hosts = {h.name: h for h in net.hosts}
    actor = hosts[scenario["actor"]]
    victim = hosts.get(scenario.get("victim"))
    row = {
        "scenario": scenario["name"], "kind": kind, "repetition": rep,
        "actor": actor.name, "actor_mac": actor.MAC(),
        "victim": victim.name if victim else "",
        "victim_mac": victim.MAC() if victim else "",
        "expected_label": scenario.get("expected_label", ""),
    }
    logfile = "/tmp/holo_gen_%s_%d.log" % (scenario["name"], rep)

    base = dash.get_state()
    base_keys = {alert_key(a) for a in base.get("alerts", [])}
    base_blocked = set(base.get("blocked_macs", []))

    # idle CPU baseline
    sampler.prime()
    idle = []
    t_end = time.time() + args.cpu_idle_seconds
    while time.time() < t_end:
        time.sleep(args.poll_interval)
        v = sampler.sample()
        if v is not None:
            idle.append(v)

    # ---- run the scenario and observe concurrently ----
    start = time.time()
    launch_traffic(net, scenario, args, rep, logfile)

    attack_kind = kind in ("flood", "scan")
    actor_mac = actor.MAC()
    detect_types = FLOOD_FAMILY if kind == "flood" else {"PORT_SCAN"}
    first_detect = first_label = first_block = None
    seen_types = set()
    new_alerts_all = []
    during = []
    deadline = start + observe_seconds(scenario, args)

    while time.time() < deadline:
        state = dash.get_state()
        now = time.time()
        new = [a for a in state.get("alerts", []) if alert_key(a) not in base_keys]
        new_alerts_all = new
        for a in new:
            seen_types.add(a.get("type"))
            if attack_kind and a.get("mac") == actor_mac:
                if first_detect is None and a.get("type") in detect_types:
                    first_detect = now - start
                if first_label is None and a.get("type") == scenario.get("expected_label"):
                    first_label = now - start
        blocked_now = set(state.get("blocked_macs", [])) - base_blocked
        if attack_kind and first_block is None and actor_mac in blocked_now:
            first_block = now - start
        v = sampler.sample()
        if v is not None:
            during.append(v)
        time.sleep(args.poll_interval)

    row["generator_output"] = actor.cmd("cat %s 2>/dev/null" % logfile).strip().replace("\n", " | ")

    final = dash.get_state()
    newly_blocked = set(final.get("blocked_macs", [])) - base_blocked
    involved = {actor_mac} | ({victim.MAC()} if victim else set())
    uninvolved = newly_blocked - involved
    types_str = ",".join(sorted(t for t in seen_types if t))

    row.update({
        "new_alert_count": len(new_alerts_all),
        "new_alert_types": types_str,
        "uninvolved_blocked_count": len(uninvolved),
        "uninvolved_blocked_macs": ",".join(sorted(uninvolved)),
    })

    if attack_kind:
        row["detected"] = first_detect is not None
        row["label_correct"] = first_label is not None
        row["detection_latency_s"] = rnd(first_detect)
        row["block_latency_s"] = rnd(first_block)
        row["attacker_blocked"] = actor_mac in newly_blocked
        row["victim_blocked"] = bool(victim and victim.MAC() in newly_blocked)
        row["false_alarm"] = ""
        if row["attacker_blocked"]:
            probe = pick_probe(net, actor.name, victim.name if victim else "")
            row["enforcement_verified"] = not ping_ok(actor, probe.IP())
        else:
            row["enforcement_verified"] = ""
    else:
        # benign traffic: ANY block or attack-type alert is a false alarm
        bad_alerts = [a for a in new_alerts_all if a.get("type") in ATTACK_ALERT_TYPES]
        row["detected"] = ""
        row["label_correct"] = ""
        row["detection_latency_s"] = ""
        row["block_latency_s"] = ""
        row["attacker_blocked"] = actor_mac in newly_blocked
        row["victim_blocked"] = ""
        row["enforcement_verified"] = ""
        row["false_alarm"] = bool(newly_blocked or bad_alerts)

    # resource usage
    idle_m, during_m = mean(idle), mean(during)
    row["cpu_idle_mean_pct"] = rnd(idle_m)
    row["cpu_during_mean_pct"] = rnd(during_m)
    row["cpu_during_max_pct"] = rnd(max(during) if during else None)
    row["cpu_overhead_pct"] = rnd(
        (during_m - idle_m) if (during_m is not None and idle_m is not None) else None)
    row["controller_rss_mb"] = rnd(sampler.rss_mb(), 1)

    # 3-way method comparison for this scenario's actor
    if args.collect_comparison:
        try:
            row.update(comparison_flags(dash.analyze(), actor_mac))
        except Exception as e:
            row.update({"rule_threshold_flagged": "error", "iforest_flagged": "error",
                        "online_flagged": "error", "online_score": "", "online_cold_start": ""})
            row["error"] = "analyze failed: %s" % e
    else:
        row.update({"rule_threshold_flagged": "", "iforest_flagged": "",
                    "online_flagged": "", "online_score": "", "online_cold_start": ""})

    row["cleanup_ok"] = cleanup_after_scenario(net, dash, newly_blocked, args)
    return row


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def _pct(n, d):
    return "n/a" if d == 0 else "%.0f%% (%d/%d)" % (100.0 * n / d, n, d)


def summarize(rows):
    good = [r for r in rows if not r.get("error", "").startswith("scenario failed")]
    out = []
    by = {}
    for r in good:
        by.setdefault(r["scenario"], []).append(r)
    for name, rs in by.items():
        kind = rs[0]["kind"]
        n = len(rs)
        lat = [float(r["detection_latency_s"]) for r in rs if r.get("detection_latency_s") not in ("", None)]
        blat = [float(r["block_latency_s"]) for r in rs if r.get("block_latency_s") not in ("", None)]
        ovh = [float(r["cpu_overhead_pct"]) for r in rs if r.get("cpu_overhead_pct") not in ("", None)]
        entry = {"scenario": name, "kind": kind, "n": n,
                 "mean_cpu_overhead_pct": rnd(mean(ovh), 2)}
        if kind in ("flood", "scan"):
            entry["detection_rate"] = _pct(sum(1 for r in rs if r["detected"] is True), n)
            entry["label_accuracy"] = _pct(sum(1 for r in rs if r["label_correct"] is True), n)
            entry["attacker_blocked_rate"] = _pct(sum(1 for r in rs if r["attacker_blocked"] is True), n)
            entry["victim_blocked_rate"] = _pct(sum(1 for r in rs if r["victim_blocked"] is True), n)
            entry["uninvolved_fp_hosts"] = sum(int(r["uninvolved_blocked_count"] or 0) for r in rs)
            entry["mean_detection_latency_s"] = rnd(mean(lat), 2)
            entry["mean_block_latency_s"] = rnd(mean(blat), 2)
        else:
            entry["false_alarm_rate"] = _pct(sum(1 for r in rs if r["false_alarm"] is True), n)
        out.append(entry)
    return out


def print_summary(summary):
    print("\n================ SUMMARY (real measured values; n = repetitions) ================")
    for e in summary:
        print("\n[%s] kind=%s n=%d" % (e["scenario"], e["kind"], e["n"]))
        for k, v in e.items():
            if k not in ("scenario", "kind", "n"):
                print("   %-26s %s" % (k, v))
    print("\nNote: small n => wide uncertainty; report n alongside any percentage.")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def parse_args(argv=None):
    p = argparse.ArgumentParser(description="HOLO Security benchmark harness")
    p.add_argument("--dashboard-url", default="http://127.0.0.1:5000")
    p.add_argument("--admin-username", default="admin")
    p.add_argument("--admin-password", required=True)
    p.add_argument("--controller-ip", default="127.0.0.1")
    p.add_argument("--controller-port", type=int, default=6653)
    p.add_argument("--flood-script", required=True)
    p.add_argument("--topology-hosts", type=int, default=6)
    p.add_argument("--repetitions", type=int, default=3)
    p.add_argument("--output", default="benchmark_results.csv")
    p.add_argument("--flow-idle-timeout", type=int, default=10,
                   help="must match the controller's HOLO_FLOW_IDLE_TIMEOUT")
    p.add_argument("--scan-window-seconds", type=int, default=20,
                   help="must match the controller's HOLO_SCAN_WINDOW_SECONDS -- "
                        "pingAll() itself touches 5+ distinct hosts per source "
                        "in seconds, i.e. it looks exactly like a horizontal scan "
                        "to the detector, so waits between scenarios must clear "
                        "this window too, not just the flow idle timeout")
    p.add_argument("--flood-duration", type=int, default=15)
    p.add_argument("--detect-margin", type=int, default=8)
    p.add_argument("--scan-observe", type=int, default=None,
                   help="default: flow-idle-timeout + 20, enough room for two "
                        "scan rounds spaced past the idle timeout")
    p.add_argument("--unblock-timeout", type=int, default=30)
    p.add_argument("--settle-margin", type=float, default=3.0)
    p.add_argument("--poll-interval", type=float, default=0.5)
    p.add_argument("--cpu-idle-seconds", type=float, default=2.0)
    p.add_argument("--skip-comparison", dest="collect_comparison", action="store_false")
    p.add_argument("--keep-model", action="store_true",
                   help="don't reset the online model at the start")
    return p.parse_args(argv)


def wait_for_switch(s1, tries=15):
    for attempt in range(tries):
        time.sleep(2)
        status = s1.cmd("ovs-vsctl get controller %s is_connected" % s1.name)
        if "true" in status.lower():
            print("Switch connected to controller after %d attempt(s)." % (attempt + 1))
            return True
        print("  not connected yet (attempt %d/%d)..." % (attempt + 1, tries))
    return False


def main():
    args = parse_args()
    args.flood_script = os.path.abspath(os.path.expanduser(args.flood_script))
    if not os.path.isfile(args.flood_script):
        sys.exit("ERROR: flood script not found at %s" % args.flood_script)
    if not MININET_AVAILABLE:
        sys.exit("ERROR: mininet not importable — run on the Mininet machine with sudo.")
    if os.geteuid() != 0:
        sys.exit("ERROR: must run as root (sudo).")

    setLogLevel("info")
    print("Logging into dashboard at %s ..." % args.dashboard_url)
    dash = DashboardClient(args.dashboard_url, args.admin_password, args.admin_username)
    print("Login OK.")

    if not args.keep_model:
        print("Resetting online model:", dash.reset_online_model())
    stale = dash.get_state().get("blocked_macs", [])
    for mac in stale:
        dash.unblock(mac=mac)
    if stale:
        print("Cleared %d pre-existing block(s); waiting for controller to apply..." % len(stale))
        time.sleep(args.settle_margin + 3)

    net = Mininet(controller=None)
    net.addController("c0", controller=RemoteController,
                      ip=args.controller_ip, port=args.controller_port)
    s1 = net.addSwitch("s1", protocols="OpenFlow13")
    for i in range(1, args.topology_hosts + 1):
        net.addLink(net.addHost("h%d" % i), s1)

    rows = []
    sampler = ControllerSampler()
    try:
        net.start()
        print("Waiting for switch-controller connection...")
        if not wait_for_switch(s1):
            print("WARNING: switch never reported connected; is ryu-manager running on "
                  "%s:%d?" % (args.controller_ip, args.controller_port))
        net.pingAll()
        # pingAll() itself touches 5+ distinct hosts per source in quick
        # succession -- to the scan detector that IS a horizontal scan, so
        # we must wait out the scan window too, not just the flow cache.
        wait = settle_seconds(args)
        print("pingAll() looks like a scan to our own detector by design; "
              "waiting %ds for that (and the flow/label cache) to clear "
              "before starting scenarios..." % wait)
        time.sleep(wait)

        with open(args.output, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=FIELDNAMES, extrasaction="ignore")
            writer.writeheader()
            for rep in range(1, args.repetitions + 1):
                for sc in SCENARIOS:
                    print("\n=== %s (rep %d/%d) ===" % (sc["name"], rep, args.repetitions))
                    try:
                        row = run_scenario(net, dash, sampler, sc, args, rep)
                        print("  detected=%s label_ok=%s lat=%s blocked=%s uninvolved_fp=%s false_alarm=%s cpu_ovh=%s" % (
                            row["detected"], row["label_correct"], row["detection_latency_s"],
                            row["attacker_blocked"], row["uninvolved_blocked_count"],
                            row["false_alarm"], row["cpu_overhead_pct"]))
                    except Exception as e:
                        print("  SCENARIO FAILED: %s" % e)
                        row = {"scenario": sc["name"], "kind": sc["kind"], "repetition": rep,
                               "error": "scenario failed: %s" % e}
                    rows.append(row)
                    writer.writerow(row)
                    f.flush()
    finally:
        net.stop()

    summary = summarize(rows)
    print_summary(summary)
    if summary:
        keys = []
        for e in summary:
            for k in e:
                if k not in keys:
                    keys.append(k)
        spath = os.path.splitext(args.output)[0] + "_summary.csv"
        with open(spath, "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys, restval="")
            w.writeheader()
            w.writerows(summary)
        print("\nPer-run rows: %s\nSummary:      %s" % (args.output, spath))


if __name__ == "__main__":
    main()
