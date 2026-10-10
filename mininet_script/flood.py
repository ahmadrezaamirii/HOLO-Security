"""
Flood / scan traffic generator for testing HOLO Security's DDoS and
port/host scan detection.

Run from inside a Mininet host, e.g.:
    mininet> h1 python3 /tmp/flood.py syn 10.0.0.2 --iface h1-eth0 --duration 10
    mininet> h1 python3 /tmp/flood.py udp 10.0.0.2 --iface h1-eth0 --duration 10
    mininet> h1 python3 /tmp/flood.py icmp 10.0.0.2 --iface h1-eth0 --duration 10
    mininet> h1 python3 /tmp/flood.py scan 10.0.0.2 --iface h1-eth0 --scan-hosts 10.0.0.2,10.0.0.3,10.0.0.4,10.0.0.5,10.0.0.6,10.0.0.7

Each flood mode sends packets as fast as Scapy allows for --duration
seconds. Scan mode ignores --duration and instead sends one probe per host
in --scan-hosts, as fast as possible, to trigger the horizontal fan-out
detector (see SCAN_DISTINCT_DEST_THRESHOLD / SCAN_WINDOW_SECONDS in
sec_switch.py — by default 5+ distinct destinations within 5 seconds).
Note the target_ip positional argument is unused in scan mode (kept for a
consistent CLI shape) — pass any placeholder value.

This is meant for lab/benchmark use against your own Mininet topology only.
"""
import argparse
import random
import time

from scapy.all import IP, ICMP, TCP, UDP, Raw, sendp, srp, Ether, ARP, get_if_hwaddr


def resolve_mac(target_ip, iface, timeout=3):
    """Resolve target_ip's MAC address via a real ARP request/reply on
    iface. Required because sending to the broadcast MAC (ff:ff:ff:ff:ff:ff)
    never installs a dedicated (src MAC -> dst MAC) flow on the switch --
    it always takes the OFPP_FLOOD path instead, which our flow-stats-based
    flood detector doesn't (and can't meaningfully) monitor per-source."""
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    answered, _ = srp(arp_request, iface=iface, timeout=timeout, verbose=False)
    if not answered:
        raise RuntimeError(
            "Could not resolve MAC for %s on %s (no ARP reply within %ss). "
            "Make sure the target host is reachable, e.g. run a `pingall` "
            "in Mininet first so ARP entries exist." % (target_ip, iface, timeout)
        )
    return answered[0][1].hwsrc


def syn_flood(iface, target_ip, duration, src_mac, dst_mac):
    end_time = time.time() + duration
    sent = 0
    while time.time() < end_time:
        sport = random.randint(1024, 65535)
        dport = random.choice([80, 443, 22, 8080])
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(dst=target_ip)
            / TCP(sport=sport, dport=dport, flags="S")
        )
        sendp(pkt, iface=iface, verbose=False)
        sent += 1
    print("syn_flood: sent %d packets toward %s (%s)" % (sent, target_ip, dst_mac))


def udp_flood(iface, target_ip, duration, src_mac, dst_mac):
    end_time = time.time() + duration
    sent = 0
    payload = Raw(load=b"x" * 64)
    while time.time() < end_time:
        sport = random.randint(1024, 65535)
        dport = random.randint(1024, 65535)
        pkt = (
            Ether(src=src_mac, dst=dst_mac)
            / IP(dst=target_ip)
            / UDP(sport=sport, dport=dport)
            / payload
        )
        sendp(pkt, iface=iface, verbose=False)
        sent += 1
    print("udp_flood: sent %d packets toward %s (%s)" % (sent, target_ip, dst_mac))


def icmp_flood(iface, target_ip, duration, src_mac, dst_mac):
    end_time = time.time() + duration
    sent = 0
    while time.time() < end_time:
        pkt = Ether(src=src_mac, dst=dst_mac) / IP(dst=target_ip) / ICMP()
        sendp(pkt, iface=iface, verbose=False)
        sent += 1
    print("icmp_flood: sent %d packets toward %s (%s)" % (sent, target_ip, dst_mac))


def horizontal_scan(iface, scan_hosts, src_mac, repeat=1, repeat_delay=1.0):
    """Send one probe to each distinct host in scan_hosts, as fast as
    possible — this is what our detector's "distinct destinations in a
    short window" signature is looking for. Each host's MAC is resolved
    via a real ARP request first (see resolve_mac) since the controller's
    scan detector only counts unicast flows, not broadcast traffic.

    `repeat` matters for testing auto-block specifically: the detector
    only blocks after seeing the over-threshold condition on 2+ separate
    checks (to avoid blocking on a single burst), so a single sweep will
    correctly raise an alert but never trigger a block on its own. Pass
    repeat=2 (with repeat_delay small enough to stay inside the
    controller's scan window) to exercise that escalation path too."""
    resolved = []
    for host_ip in scan_hosts:
        try:
            mac = resolve_mac(host_ip, iface)
            resolved.append((host_ip, mac))
        except RuntimeError as e:
            print("WARNING: skipping %s — %s" % (host_ip, e))

    if not resolved:
        print("horizontal_scan: no hosts resolved, nothing sent")
        return

    total_sent = 0
    for round_num in range(1, repeat + 1):
        sent = 0
        for host_ip, mac in resolved:
            pkt = Ether(src=src_mac, dst=mac) / IP(dst=host_ip) / ICMP()
            sendp(pkt, iface=iface, verbose=False)
            sent += 1
        total_sent += sent
        print(
            "horizontal_scan: round %d/%d probed %d/%d hosts: %s"
            % (round_num, repeat, sent, len(scan_hosts), ", ".join(ip for ip, _ in resolved))
        )
        if round_num < repeat:
            time.sleep(repeat_delay)
    print("horizontal_scan: done, %d probe(s) sent across %d round(s)" % (total_sent, repeat))


def main():
    parser = argparse.ArgumentParser(description="HOLO Security flood/scan test generator")
    parser.add_argument("mode", choices=["syn", "udp", "icmp", "scan"])
    parser.add_argument("target_ip", help="Unused in scan mode; pass a placeholder")
    parser.add_argument("--iface", required=True, help="e.g. h1-eth0")
    parser.add_argument("--duration", type=float, default=10.0, help="seconds (flood modes only)")
    parser.add_argument(
        "--scan-hosts",
        default="",
        help="Comma-separated target IPs for scan mode, e.g. 10.0.0.2,10.0.0.3,10.0.0.4",
    )
    parser.add_argument(
        "--repeat", type=int, default=1,
        help="scan mode only: repeat the full sweep this many times, to test "
             "sustained-scan auto-block (a single sweep only ever raises an "
             "alert, never a block -- see horizontal_scan() docstring)",
    )
    parser.add_argument(
        "--repeat-delay", type=float, default=1.0,
        help="scan mode only: seconds between repeat sweeps",
    )
    args = parser.parse_args()

    src_mac = get_if_hwaddr(args.iface)

    if args.mode == "scan":
        scan_hosts = [h.strip() for h in args.scan_hosts.split(",") if h.strip()]
        if len(scan_hosts) < 2:
            parser.error("scan mode requires --scan-hosts with at least 2 comma-separated IPs")
        print("Starting horizontal scan: iface=%s src_mac=%s hosts=%s repeat=%d" % (
            args.iface, src_mac, scan_hosts, args.repeat))
        horizontal_scan(args.iface, scan_hosts, src_mac, repeat=args.repeat, repeat_delay=args.repeat_delay)
        return

    print(
        "Starting %s flood: iface=%s src_mac=%s target=%s duration=%.1fs"
        % (args.mode, args.iface, src_mac, args.target_ip, args.duration)
    )

    try:
        dst_mac = resolve_mac(args.target_ip, args.iface)
    except RuntimeError as e:
        print("ERROR: %s" % e)
        return
    print("Resolved %s -> %s" % (args.target_ip, dst_mac))

    if args.mode == "syn":
        syn_flood(args.iface, args.target_ip, args.duration, src_mac, dst_mac)
    elif args.mode == "udp":
        udp_flood(args.iface, args.target_ip, args.duration, src_mac, dst_mac)
    elif args.mode == "icmp":
        icmp_flood(args.iface, args.target_ip, args.duration, src_mac, dst_mac)


if __name__ == "__main__":
    main()
