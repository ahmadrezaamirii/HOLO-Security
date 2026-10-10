# -*- coding: utf-8 -*-

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types
from ryu.lib.packet import arp, ipv4, tcp, udp, icmp
from ryu.lib import hub
import logging
import sys
import json
import time
import os
import re
import tempfile

# Force unbuffered stdout for immediate log visibility in Docker
sys.stdout = sys.__stdout__

# State file paths for Flask dashboard communication.
# Defaults to <project_root>/shared (a sibling of controller/ and dashboard/),
# which is the same folder the Flask dashboard writes to. Override with the
# HOLO_SHARED_DIR env var (e.g. for a Docker deployment using /app/shared).
SHARED_DIR = os.environ.get(
    "HOLO_SHARED_DIR",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "shared"),
)
STATE_FILE = os.path.join(SHARED_DIR, "state.json")
COMMAND_FILE = os.path.join(SHARED_DIR, "commands.json")
BLOCKED_FILE = os.path.join(SHARED_DIR, "blocked.json")

# Simple validators shared conceptually with the dashboard's own validators.
# Kept duplicated here (rather than imported) since the controller and the
# Flask app are separate processes/runtimes and may not share a Python path.
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def _is_valid_mac(mac):
    return bool(mac and _MAC_RE.match(mac))


def _is_valid_ip(ip):
    if not ip or not _IP_RE.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def _atomic_write_json(path, data):
    """
    Write JSON to `path` atomically so concurrent readers (e.g. the Flask
    dashboard) never see a half-written / corrupted file.
    """
    directory = os.path.dirname(path) or "."
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
        fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp_path, path)
        except Exception:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)
            raise
    except Exception as e:
        print("State update error: %s" % e)


def _safe_read_json(path, default):
    """Read JSON from `path`, returning `default` on any failure."""
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


class SecureSwitch(app_manager.RyuApp):
    """
    A learning Layer-2 switch with MAC-based access control and basic
    anti-spoofing detection.

    Features:
    - Learns source MAC -> port mappings per switch (DPID).
    - Forwards packets based on the learned MAC table, otherwise floods.
    - Detects ARP/IP spoofing and MAC-move attempts, with a decaying
      per-MAC offense counter (so a stale/legacy false positive doesn't
      accumulate forever into a permanent block).
    - Maintains a set of blocked MAC addresses, enforced with high-priority
      drop flows installed on every connected switch.
    - Exposes state to a Flask dashboard via a shared JSON file, and accepts
      block/unblock commands from the dashboard via another shared file.
    """

    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # After this many suspicious events for a MAC *within the window*,
    # it gets blocked automatically.
    SPOOF_THRESHOLD = 3
    # Offense counters reset if no new offense happens within this window,
    # so a MAC that misbehaved once long ago isn't blocked forever.
    SPOOF_WINDOW_SECONDS = 300
    # How often (in seconds) to poll the command file / reload blocklist.
    # Driven by its own background greenthread (see _command_monitor), so
    # block/unblock commands from the dashboard are applied even when the
    # network is quiet and no PacketIn events are arriving.
    COMMAND_POLL_INTERVAL = float(os.environ.get("HOLO_COMMAND_POLL_INTERVAL", "2.0"))

    # --- DDoS / flood detection tuning ------------------------------------
    # How often (seconds) to poll each switch for flow statistics. This is
    # necessary (not optional) because our L2 forwarding flows are cached
    # in the switch after the first packet of a MAC pair — a flood's later
    # packets never reach the controller as PacketIn events, so the only
    # way to see their volume is to periodically read counters directly
    # off the switch's flow table.
    #
    # All thresholds below are environment variables, not fixed constants,
    # because "what rate counts as a flood" depends entirely on how fast
    # your testbed can actually generate traffic. On a dedicated Mininet
    # VM we measured 600-700+ pps from a single Scapy flood; running
    # everything (Mininet + Ryu + Flask + a benchmark harness) on one
    # resource-constrained VM at the same time can push a Python-generated
    # flood down to ~20 pps purely from CPU contention, with no change to
    # the attack itself. Recalibrate these for your actual hardware rather
    # than assuming the defaults are universal.
    FLOOD_POLL_INTERVAL = float(os.environ.get("HOLO_FLOOD_POLL_INTERVAL", "3.0"))
    # Packets/sec on a single (src MAC -> dst MAC) flow above this is
    # considered a flood candidate.
    FLOOD_PPS_THRESHOLD = float(os.environ.get("HOLO_FLOOD_PPS_THRESHOLD", "150.0"))
    # A flood candidate must be seen for this many *consecutive* polls
    # before we auto-block, so a single legitimate burst (e.g. an iperf
    # test) doesn't get blocked as a false positive.
    FLOOD_CONSECUTIVE_POLLS_TO_BLOCK = int(os.environ.get("HOLO_FLOOD_CONSECUTIVE_POLLS", "2"))

    # Idle timeout (seconds) applied to the L2 unicast forwarding flows we
    # install (NOT to the table-miss rule or to block rules, which must
    # stay permanent until explicitly removed). Two reasons this matters:
    #   1. Flow-table hygiene: without it, every MAC pair ever seen leaves
    #      a permanent entry.
    #   2. Correct protocol labeling: the flood alert label (SYN/UDP/ICMP)
    #      is recorded when a flow is (re)installed. With permanent flows,
    #      a pair whose FIRST packet was e.g. a ping would be labeled
    #      "ICMP" forever, even if it later carries a UDP flood. With an
    #      idle timeout, an idle pair's flow expires and the next burst's
    #      first packet re-installs it with a fresh, correct label.
    # A continuous flood keeps its flow alive (traffic keeps matching), so
    # this does not cause churn during an attack. 0 disables the timeout.
    FLOW_IDLE_TIMEOUT_SECONDS = int(os.environ.get("HOLO_FLOW_IDLE_TIMEOUT", "10"))

    # --- Horizontal scan detection tuning ---------------------------------
    # A host contacting many *distinct destination MACs* in a short window
    # is the classic signature of a horizontal port/host scan (e.g. nmap
    # sweeping the subnet). This is detectable at our current L2 flow
    # granularity because each new destination MAC is, by definition, a
    # new flow and triggers a fresh PacketIn -- unlike per-port scanning
    # of a single target, which our MAC-pair-level flows can't see (see
    # Limitations: this only catches *horizontal* scans, not per-port
    # scanning of one host).
    #
    # SCAN_WINDOW_SECONDS also needs headroom for how long ARP resolution
    # itself takes on your hardware (the scan generator resolves each
    # target's MAC via a real ARP request before probing it) -- under CPU
    # contention this can take much longer than on an idle testbed.
    SCAN_WINDOW_SECONDS = float(os.environ.get("HOLO_SCAN_WINDOW_SECONDS", "5.0"))
    SCAN_DISTINCT_DEST_THRESHOLD = int(os.environ.get("HOLO_SCAN_DISTINCT_DEST_THRESHOLD", "5"))

    def __init__(self, *args, **kwargs):
        super(SecureSwitch, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.mac_to_port = {}
        self.blocked_macs = set()
        # Per-switch IP-to-MAC bindings learned mainly from ARP packets
        self.ip_to_mac = {}
        # Per-switch, per-MAC spoof offense tracking: {"count": int, "window_start": ts}
        self.spoof_counters = {}
        # List of security alerts for the Flask dashboard
        self.alerts = []
        self.max_alerts = 1000

        # --- Flood/DDoS tracking state ---
        # (dpid, eth_src, eth_dst) -> {"packets": int, "bytes": int, "t": float}
        # from the most recent flow-stats poll, used to compute deltas.
        self._flow_stats_prev = {}
        # (dpid, eth_src, eth_dst) -> "TCP-SYN" | "UDP" | "ICMP" | "OTHER",
        # recorded at flow-install time since flow stats alone don't carry
        # L4 protocol info once traffic is already flowing.
        self._flow_protocol_hint = {}
        # dpid -> mac -> consecutive-high-rate-poll count, mirrors
        # spoof_counters' shape/logic but for flood candidates.
        self.flood_suspect_counters = {}
        # dpid -> src_mac -> list of (dst_mac, timestamp) seen recently,
        # used to detect horizontal scanning (many distinct destinations
        # in a short window). Pruned to SCAN_WINDOW_SECONDS on each check.
        self._scan_tracking = {}
        # dpid -> mac -> consecutive-over-threshold-poll count, mirrors
        # flood_suspect_counters but for scan detection.
        self.scan_suspect_counters = {}

        self._last_command_check = 0

        self._setup_logging()
        self.logger.info("SecureSwitch application initialized")
        self.logger.info(
            "Active thresholds: FLOOD_PPS_THRESHOLD=%.1f FLOOD_POLL_INTERVAL=%.1fs "
            "FLOOD_CONSECUTIVE_POLLS_TO_BLOCK=%d SCAN_WINDOW_SECONDS=%.1fs "
            "SCAN_DISTINCT_DEST_THRESHOLD=%d SPOOF_THRESHOLD=%d "
            "FLOW_IDLE_TIMEOUT=%ds COMMAND_POLL_INTERVAL=%.1fs",
            self.FLOOD_PPS_THRESHOLD, self.FLOOD_POLL_INTERVAL,
            self.FLOOD_CONSECUTIVE_POLLS_TO_BLOCK, self.SCAN_WINDOW_SECONDS,
            self.SCAN_DISTINCT_DEST_THRESHOLD, self.SPOOF_THRESHOLD,
            self.FLOW_IDLE_TIMEOUT_SECONDS, self.COMMAND_POLL_INTERVAL,
        )

        # Load blocked MACs from file if it exists
        self._load_blocked_hosts()

        # Initialize state file for the Flask dashboard
        self._update_state_file()

        # Background greenthread that periodically polls every connected
        # switch for flow statistics (see FLOOD_POLL_INTERVAL above).
        self._flood_monitor_thread = hub.spawn(self._flow_stats_monitor)
        # Background greenthread that applies dashboard commands promptly.
        self._command_monitor_thread = hub.spawn(self._command_monitor)

    def _setup_logging(self):
        log_formatter = logging.Formatter(
            "%(asctime)s - [SecureSwitch] - %(levelname)s - %(message)s"
        )

        stdout_handler = logging.StreamHandler(sys.stdout)
        stdout_handler.setFormatter(log_formatter)
        stdout_handler.setLevel(logging.INFO)

        file_handler = logging.FileHandler("sec_switch.log")
        file_handler.setFormatter(log_formatter)
        file_handler.setLevel(logging.INFO)

        # Clear existing handlers and add our own to ensure stdout output
        self.logger.handlers = []
        self.logger.addHandler(stdout_handler)
        self.logger.addHandler(file_handler)
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False

    @staticmethod
    def _is_control_traffic(eth):
        """
        Return True for control/management frames that we don't want
        to learn or forward like normal data traffic (e.g., LLDP).
        """
        return eth.ethertype == ether_types.ETH_TYPE_LLDP

    def add_flow(self, datapath, priority, match, actions=None, buffer_id=None,
                 idle_timeout=0):
        """
        Helper to install a flow entry on the switch.
        If 'actions' is empty or None, the flow acts as a drop rule.
        """
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if actions is None:
            actions = []

        instructions = []
        if actions:
            instructions.append(
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)
            )

        kwargs = dict(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
        )
        if buffer_id is not None:
            kwargs["buffer_id"] = buffer_id
        if idle_timeout:
            kwargs["idle_timeout"] = int(idle_timeout)

        mod = parser.OFPFlowMod(**kwargs)
        try:
            datapath.send_msg(mod)
        except Exception as e:
            self.logger.warning("Failed to send FlowMod to datapath: %s", e)

    def _increment_spoof_counter(self, dpid, mac_address):
        """
        Increase and return the spoof counter for the given MAC on this
        switch. The counter resets if the last offense fell outside the
        rolling window, so old/one-off events don't accumulate forever.
        """
        per_switch = self.spoof_counters.setdefault(dpid, {})
        now = time.time()
        entry = per_switch.get(mac_address)
        if entry is None or (now - entry["window_start"]) > self.SPOOF_WINDOW_SECONDS:
            entry = {"count": 0, "window_start": now}
        entry["count"] += 1
        per_switch[mac_address] = entry
        return entry["count"]

    def _build_arp_table(self):
        arp_table = []
        for dpid, ip_mac_map in self.ip_to_mac.items():
            for ip, mac in ip_mac_map.items():
                arp_table.append({"ip": ip, "mac": mac, "dpid": dpid})
        return arp_table

    def _add_alert(self, alert_type, ip=None, mac=None, dpid=None, reason=None):
        alert = {
            "type": alert_type,
            "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if ip:
            alert["ip"] = ip
        if mac:
            alert["mac"] = mac
        if dpid:
            alert["dpid"] = dpid
        if reason:
            alert["reason"] = reason

        self.alerts.append(alert)
        if len(self.alerts) > self.max_alerts:
            self.alerts = self.alerts[-self.max_alerts:]

        self._update_state_file()

    def _update_state_file(self):
        state = {
            "alerts": self.alerts,
            "arp_table": self._build_arp_table(),
            "blocked_macs": list(self.blocked_macs),
            "last_update": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        _atomic_write_json(STATE_FILE, state)

    def _install_block_flow_everywhere(self, mac_address):
        """Install a high-priority drop rule for `mac_address` on every
        connected switch, so a block takes effect network-wide immediately
        rather than waiting for the next packet on each switch."""
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=mac_address)
            try:
                self.add_flow(datapath, priority=200, match=match, actions=[])
            except Exception as e:
                self.logger.warning(
                    "Failed to install block flow on DPID=%s for %s: %s",
                    dpid, mac_address, e,
                )

    def _remove_block_flow_everywhere(self, mac_address):
        """Remove the drop rule previously installed for `mac_address` on
        every connected switch. Must be called on unblock, otherwise the
        switch keeps dropping that MAC's traffic even after it's been
        removed from self.blocked_macs."""
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_src=mac_address)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE_STRICT,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                priority=200,
                match=match,
            )
            try:
                datapath.send_msg(mod)
            except Exception as e:
                self.logger.warning(
                    "Failed to remove block flow on DPID=%s for %s: %s",
                    dpid, mac_address, e,
                )

    def _handle_spoof(self, datapath, src_mac, in_port, reason, src_ip=None):
        """
        Centralized handling of detected spoofing attempts.
        """
        dpid = datapath.id
        count = self._increment_spoof_counter(dpid, src_mac)

        self.logger.error(
            "Spoofing detected: DPID=%s SRC=%s PORT=%s REASON=%s COUNT=%s",
            dpid, src_mac, in_port, reason, count,
        )

        alert_type = "SPOOF"
        reason_lower = reason.lower()
        if "arp" in reason_lower:
            alert_type = "ARP_SPOOF"
        elif "ipv4" in reason_lower:
            alert_type = "IP_SPOOF"
        elif "multiple ports" in reason_lower:
            alert_type = "MAC_MOVE"

        self._add_alert(
            alert_type=alert_type, ip=src_ip, mac=src_mac, dpid=dpid, reason=reason,
        )

        if count >= self.SPOOF_THRESHOLD and src_mac not in self.blocked_macs:
            self.blocked_macs.add(src_mac)
            self._update_blocked_file()
            self.logger.error(
                "MAC %s reached spoof threshold on DPID=%s; blocking network-wide",
                src_mac, dpid,
            )
            self._install_block_flow_everywhere(src_mac)
            self._add_alert(
                alert_type="MAC_BLOCKED",
                mac=src_mac,
                dpid=dpid,
                reason="Reached spoof threshold (%d) within %ds window"
                % (count, self.SPOOF_WINDOW_SECONDS),
            )

    def _reset_offense_counters(self, mac_address):
        """Clear spoof, flood, and scan offense counters for a MAC across
        all switches, called on manual unblock so it isn't instantly
        re-flagged/re-blocked by a stale counter on the next check."""
        for per_switch in self.spoof_counters.values():
            per_switch.pop(mac_address, None)
        for per_switch in self.flood_suspect_counters.values():
            per_switch.pop(mac_address, None)
        for per_switch in self.scan_suspect_counters.values():
            per_switch.pop(mac_address, None)

    def _update_blocked_file(self):
        """Write the current in-memory blocked_macs set back to
        blocked.json, preserving whatever blocked_ips the dashboard has
        recorded. Called any time blocked_macs changes — from automatic
        detection (spoof/flood/scan) as well as manual commands — so the
        dashboard's view of "what's blocked" never drifts from what the
        controller is actually enforcing."""
        existing = _safe_read_json(BLOCKED_FILE, {"blocked_ips": [], "blocked_macs": []})
        existing["blocked_macs"] = list(self.blocked_macs)
        _atomic_write_json(BLOCKED_FILE, existing)

    def _load_blocked_hosts(self):
        """Load blocked MACs (and, where resolvable, blocked IPs) from
        blocked.json, ignoring malformed entries. Reconciles the dashboard's
        blocked_ips/blocked_macs split with the controller's MAC-only
        enforcement, so a host blocked only by IP isn't silently dropped
        the next time the controller (re)loads this file."""
        blocked_data = _safe_read_json(BLOCKED_FILE, {})
        blocked_macs = blocked_data.get("blocked_macs", [])
        blocked_ips = blocked_data.get("blocked_ips", [])
        known_before = len(self.blocked_macs)
        loaded = 0
        for mac in blocked_macs:
            if _is_valid_mac(mac):
                self.blocked_macs.add(mac)
                loaded += 1
            else:
                self.logger.warning("Ignoring malformed MAC in blocked.json: %r", mac)

        for ip in blocked_ips:
            if not _is_valid_ip(ip):
                self.logger.warning("Ignoring malformed IP in blocked.json: %r", ip)
                continue
            resolved = False
            for ip_mac_map in self.ip_to_mac.values():
                mac_from_ip = ip_mac_map.get(ip)
                if mac_from_ip:
                    self.blocked_macs.add(mac_from_ip)
                    loaded += 1
                    resolved = True
            if not resolved:
                # We haven't seen this IP on the wire yet (e.g. fresh
                # controller restart before any ARP traffic), so there's no
                # known MAC to block yet. It will be picked up once this IP
                # is observed and re-blocked via a future command, or on
                # the next _load_blocked_hosts() poll after ip_to_mac fills in.
                self.logger.debug(
                    "Blocked IP %s has no known MAC binding yet; will retry on next poll", ip,
                )

        if len(self.blocked_macs) > known_before:
            self.logger.info(
                "Loaded %d new blocked host(s) from file", len(self.blocked_macs) - known_before
            )

    def _process_commands(self):
        """Process pending commands from commands.json."""
        commands = _safe_read_json(COMMAND_FILE, [])
        if not commands:
            return

        for cmd in commands:
            if not isinstance(cmd, dict):
                continue
            action = cmd.get("action")
            mac = cmd.get("mac")
            ip = cmd.get("ip")

            if action == "block":
                if mac:
                    if not _is_valid_mac(mac):
                        self.logger.warning("Rejected block command: invalid MAC %r", mac)
                    else:
                        self.blocked_macs.add(mac)
                        self.logger.warning("MAC added to block list: %s", mac)
                        self._install_block_flow_everywhere(mac)
                if ip:
                    if not _is_valid_ip(ip):
                        self.logger.warning("Rejected block command: invalid IP %r", ip)
                    else:
                        for dpid, ip_mac_map in self.ip_to_mac.items():
                            if ip in ip_mac_map:
                                mac_from_ip = ip_mac_map[ip]
                                self.blocked_macs.add(mac_from_ip)
                                self._install_block_flow_everywhere(mac_from_ip)
                        self.logger.info("IP blocking requested for: %s", ip)

            elif action == "unblock":
                if mac and mac in self.blocked_macs:
                    self.blocked_macs.discard(mac)
                    self._remove_block_flow_everywhere(mac)
                    self._reset_offense_counters(mac)
                    self.logger.info("MAC unblocked: %s", mac)
                if ip:
                    for dpid, ip_mac_map in self.ip_to_mac.items():
                        mac_from_ip = ip_mac_map.get(ip)
                        if mac_from_ip:
                            self.blocked_macs.discard(mac_from_ip)
                            self._remove_block_flow_everywhere(mac_from_ip)
                            self._reset_offense_counters(mac_from_ip)
                            self.logger.info("MAC unblocked via IP %s: %s", ip, mac_from_ip)

        # Clear processed commands
        _atomic_write_json(COMMAND_FILE, [])
        self._update_blocked_file()
        self._update_state_file()

    # --- DDoS / flood detection: periodic flow-stats polling --------------

    def _periodic_command_check(self):
        """Apply pending dashboard commands and reload the blocklist, at
        most once per COMMAND_POLL_INTERVAL. Safe to call from any handler."""
        now = time.time()
        if now - self._last_command_check > self.COMMAND_POLL_INTERVAL:
            self._last_command_check = now
            self._process_commands()
            self._load_blocked_hosts()

    def _command_monitor(self):
        while True:
            try:
                self._periodic_command_check()
            except Exception as e:
                self.logger.warning("Command monitor iteration failed: %s", e)
            hub.sleep(self.COMMAND_POLL_INTERVAL)

    def _flow_stats_monitor(self):
        """Background loop (runs as a Ryu/eventlet greenthread) that asks
        every connected switch for its flow table statistics every
        FLOOD_POLL_INTERVAL seconds. See the class docstring note on why
        packet-in counting alone can't see flood volume."""
        while True:
            for dpid, datapath in list(self.datapaths.items()):
                parser = datapath.ofproto_parser
                try:
                    req = parser.OFPFlowStatsRequest(datapath)
                    datapath.send_msg(req)
                except Exception as e:
                    self.logger.warning(
                        "Failed to request flow stats from DPID=%s: %s", dpid, e
                    )
            hub.sleep(self.FLOOD_POLL_INTERVAL)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        now = time.time()

        for stat in ev.msg.body:
            match = stat.match
            eth_src = match.get("eth_src")
            eth_dst = match.get("eth_dst")
            if not eth_src or not eth_dst:
                continue  # skip the table-miss/broadcast-style entries

            key = (dpid, eth_src, eth_dst)
            packets = stat.packet_count
            byte_count = stat.byte_count

            prev = self._flow_stats_prev.get(key)
            self._flow_stats_prev[key] = {"packets": packets, "bytes": byte_count, "t": now}

            if prev is None:
                continue  # first sighting of this flow, no delta yet

            elapsed = now - prev["t"]
            if elapsed <= 0:
                continue

            delta_packets = packets - prev["packets"]
            if delta_packets < 0:
                # Counter reset (flow was reinstalled) — treat as a fresh start.
                continue

            pps = delta_packets / elapsed
            if pps >= self.FLOOD_PPS_THRESHOLD:
                self._handle_flood_candidate(dpid, eth_src, eth_dst, pps, key)

    def _handle_flood_candidate(self, dpid, eth_src, eth_dst, pps, key):
        """A flow's packet rate exceeded FLOOD_PPS_THRESHOLD on this poll.
        Track consecutive high-rate polls before acting, so a single
        legitimate burst isn't treated as an attack."""
        per_switch = self.flood_suspect_counters.setdefault(dpid, {})
        entry = per_switch.get(eth_src, {"count": 0, "last_seen": 0.0})
        now = time.time()
        # "Consecutive" must actually mean consecutive: if the previous
        # over-threshold poll was too long ago (more than 2.5 polling
        # intervals -- tolerating one skipped poll, e.g. after a flow
        # counter reset), the earlier strike no longer counts.
        if entry["count"] and now - entry["last_seen"] > self.FLOOD_POLL_INTERVAL * 2.5:
            entry["count"] = 0
        entry["count"] += 1
        entry["last_seen"] = now
        per_switch[eth_src] = entry

        protocol_hint = self._flow_protocol_hint.get(key, "OTHER")
        alert_type = {
            "TCP-SYN": "SYN_FLOOD",
            "UDP": "UDP_FLOOD",
            "ICMP": "ICMP_FLOOD",
        }.get(protocol_hint, "FLOOD_SUSPECTED")

        self.logger.warning(
            "Flood candidate: DPID=%s SRC=%s -> DST=%s rate=%.1f pps proto=%s (poll %d/%d)",
            dpid, eth_src, eth_dst, pps, protocol_hint,
            entry["count"], self.FLOOD_CONSECUTIVE_POLLS_TO_BLOCK,
        )

        self._add_alert(
            alert_type=alert_type,
            mac=eth_src,
            dpid=dpid,
            reason="%.1f pkt/s toward %s (threshold %.1f)"
            % (pps, eth_dst, self.FLOOD_PPS_THRESHOLD),
        )

        if (
            entry["count"] >= self.FLOOD_CONSECUTIVE_POLLS_TO_BLOCK
            and eth_src not in self.blocked_macs
        ):
            self.blocked_macs.add(eth_src)
            self._update_blocked_file()
            self.logger.error(
                "MAC %s sustained flood rate on DPID=%s; blocking network-wide",
                eth_src, dpid,
            )
            self._install_block_flow_everywhere(eth_src)
            self._add_alert(
                alert_type="MAC_BLOCKED",
                mac=eth_src,
                dpid=dpid,
                reason="Sustained %s at %.1f pkt/s for %d consecutive polls"
                % (alert_type, pps, entry["count"]),
            )

    def _track_scan_activity(self, dpid, src_mac, dst_mac):
        """Record that src_mac just started a new flow toward dst_mac, and
        check whether it has touched too many distinct destinations within
        the recent window (horizontal scan signature)."""
        now = time.time()
        per_switch = self._scan_tracking.setdefault(dpid, {})
        history = per_switch.setdefault(src_mac, [])
        history.append((dst_mac, now))

        cutoff = now - self.SCAN_WINDOW_SECONDS
        history[:] = [(d, t) for (d, t) in history if t >= cutoff]

        distinct_destinations = {d for d, _ in history}
        if len(distinct_destinations) < self.SCAN_DISTINCT_DEST_THRESHOLD:
            return

        counters = self.scan_suspect_counters.setdefault(dpid, {})
        entry = counters.get(src_mac, {"count": 0, "last_seen": 0.0})
        # Same idea as the flood counter: an over-threshold event from
        # longer ago than one detection window is not a "consecutive" one.
        if entry["count"] and now - entry.get("last_seen", 0.0) > self.SCAN_WINDOW_SECONDS:
            entry["count"] = 0
        entry["count"] += 1
        entry["last_seen"] = now
        counters[src_mac] = entry

        self.logger.warning(
            "Scan candidate: DPID=%s SRC=%s touched %d distinct destinations "
            "in %.0fs (poll %d/%d)",
            dpid, src_mac, len(distinct_destinations), self.SCAN_WINDOW_SECONDS,
            entry["count"], self.FLOOD_CONSECUTIVE_POLLS_TO_BLOCK,
        )

        self._add_alert(
            alert_type="PORT_SCAN",
            mac=src_mac,
            dpid=dpid,
            reason="Contacted %d distinct hosts within %.0fs (threshold %d)"
            % (len(distinct_destinations), self.SCAN_WINDOW_SECONDS,
               self.SCAN_DISTINCT_DEST_THRESHOLD),
        )

        if (
            entry["count"] >= self.FLOOD_CONSECUTIVE_POLLS_TO_BLOCK
            and src_mac not in self.blocked_macs
        ):
            self.blocked_macs.add(src_mac)
            self._update_blocked_file()
            self.logger.error(
                "MAC %s sustained scan behavior on DPID=%s; blocking network-wide",
                src_mac, dpid,
            )
            self._install_block_flow_everywhere(src_mac)
            self._add_alert(
                alert_type="MAC_BLOCKED",
                mac=src_mac,
                dpid=dpid,
                reason="Sustained horizontal scan (%d distinct hosts) for %d consecutive checks"
                % (len(distinct_destinations), entry["count"]),
            )

    @staticmethod
    def _classify_ip_protocol(pkt):
        """Inspect a parsed packet for TCP/UDP/ICMP, returning a short
        protocol hint used to label flood alerts. TCP is further split
        into SYN vs. established since a SYN flood is the classic case."""
        tcp_pkt = pkt.get_protocol(tcp.tcp)
        if tcp_pkt is not None:
            if tcp_pkt.bits & 0x02:  # SYN flag set
                return "TCP-SYN"
            return "TCP"
        if pkt.get_protocol(udp.udp) is not None:
            return "UDP"
        if pkt.get_protocol(icmp.icmp) is not None:
            return "ICMP"
        return "OTHER"

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id

        if dpid in self.datapaths:
            self.logger.warning(
                "DPID=%s reconnected; clearing stale learned state for this "
                "switch (MAC/port bindings, ARP bindings, spoof/flood/scan "
                "counters). The persistent blocklist is left untouched.",
                dpid,
            )
        self.datapaths[dpid] = datapath
        self.mac_to_port.pop(dpid, None)
        self.ip_to_mac.pop(dpid, None)
        self.spoof_counters.pop(dpid, None)
        self.flood_suspect_counters.pop(dpid, None)
        self.scan_suspect_counters.pop(dpid, None)
        self._scan_tracking.pop(dpid, None)
        for key in [k for k in self._flow_stats_prev if k[0] == dpid]:
            del self._flow_stats_prev[key]
        for key in [k for k in self._flow_protocol_hint if k[0] == dpid]:
            del self._flow_protocol_hint[key]

        # Table-miss flow: send unmatched packets to the controller
        match = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)
        ]
        self.add_flow(datapath, priority=0, match=match, actions=actions)

        self.logger.info("SecureSwitch connected (DPID=%s)", dpid)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        self._periodic_command_check()

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        in_port = msg.match.get("in_port")
        if in_port is None:
            self.logger.warning("PacketIn without in_port; dropping")
            return

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth is None:
            return
        if self._is_control_traffic(eth):
            return

        src = eth.src
        dst = eth.dst
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # 1) Port-based anti-spoofing: same MAC suddenly on a different port.
        known_port = self.mac_to_port[dpid].get(src)
        if known_port is not None and known_port != in_port:
            self._handle_spoof(
                datapath, src, in_port,
                "MAC seen on multiple ports of the same switch",
                src_ip=None,
            )
            return

        self.mac_to_port[dpid][src] = in_port

        # 2) IP/MAC consistency checks (ARP and IPv4 inspection)
        self.ip_to_mac.setdefault(dpid, {})

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt is not None:
            src_ip = arp_pkt.src_ip
            bound_mac = self.ip_to_mac[dpid].get(src_ip)

            if bound_mac is None:
                self.ip_to_mac[dpid][src_ip] = src
                self.logger.info(
                    "Learned ARP binding on DPID=%s: IP=%s -> MAC=%s", dpid, src_ip, src,
                )
                self._update_state_file()
            elif bound_mac != src:
                self._handle_spoof(
                    datapath, src, in_port,
                    "ARP binding conflict for IP %s (was %s, now %s)"
                    % (src_ip, bound_mac, src),
                    src_ip=src_ip,
                )
                return

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        if ip_pkt is not None:
            src_ip = ip_pkt.src
            bound_mac = self.ip_to_mac[dpid].get(src_ip)

            if bound_mac is not None and bound_mac != src:
                self._handle_spoof(
                    datapath, src, in_port,
                    "IPv4 source IP %s does not match ARP binding MAC %s"
                    % (src_ip, bound_mac),
                    src_ip=src_ip,
                )
                return

        # Security Policy: MAC-based blocking
        if src in self.blocked_macs:
            self.logger.warning("BLOCKED MAC detected: %s on DPID=%s", src, dpid)
            match = parser.OFPMatch(eth_src=src)
            self.add_flow(datapath, priority=100, match=match, actions=[])
            return

        # Decide output port: known unicast vs. unknown/flood
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)

            # Remember what kind of traffic started this flow, since flow
            # stats polled later won't carry L4 info once cached in hardware.
            self._flow_protocol_hint[(dpid, src, dst)] = self._classify_ip_protocol(pkt)

            # Horizontal scan check: does this source now touch too many
            # distinct destinations within the recent window?
            self._track_scan_activity(dpid, src, dst)

            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(
                    datapath, priority=10, match=match, actions=actions,
                    buffer_id=msg.buffer_id,
                    idle_timeout=self.FLOW_IDLE_TIMEOUT_SECONDS,
                )
                self.logger.info(
                    "Flow installed (buffered): DPID=%s SRC=%s DST=%s IN=%s OUT=%s",
                    dpid, src, dst, in_port, out_port,
                )
                return
            else:
                self.add_flow(
                    datapath, priority=10, match=match, actions=actions,
                    idle_timeout=self.FLOW_IDLE_TIMEOUT_SECONDS,
                )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data,
        )
        datapath.send_msg(out)

        self.logger.info(
            "Packet: DPID=%s SRC=%s DST=%s IN_PORT=%s OUT_PORT=%s",
            dpid, src, dst, in_port, out_port,
        )
