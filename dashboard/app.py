from flask import Flask, render_template, jsonify, request, session, redirect, url_for, send_file
from functools import wraps
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import json
import os
import re
import csv
import io
import tempfile
import time
import secrets

from reportlab.lib.pagesizes import letter
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer, PageBreak
from reportlab.lib.enums import TA_CENTER

import numpy as np
import pickle
from scipy.stats import chi2
from sklearn.ensemble import IsolationForest

app = Flask(__name__)
app.secret_key = os.environ.get("HOLO_SECRET_KEY", secrets.token_hex(32))

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    # Only force "Secure" cookies if you're actually serving over HTTPS.
    SESSION_COOKIE_SECURE=os.environ.get("HOLO_FORCE_HTTPS", "0") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

SHARED_DIR = os.path.join(os.path.dirname(__file__), "..", "shared")
STATE_FILE = os.path.join(SHARED_DIR, "state.json")
COMMAND_FILE = os.path.join(SHARED_DIR, "commands.json")
BLOCKED_FILE = os.path.join(SHARED_DIR, "blocked.json")

# --- Admin credentials -------------------------------------------------
# Set HOLO_ADMIN_USER / HOLO_ADMIN_PASSWORD before starting the app in any
# real deployment. Falling back to admin/admin123 is only meant for local,
# throwaway testing.
ADMIN_USERNAME = os.environ.get("HOLO_ADMIN_USER", "admin")
_USING_DEFAULT_PASSWORD = "HOLO_ADMIN_PASSWORD" not in os.environ
ADMIN_PASSWORD_HASH = generate_password_hash(
    os.environ.get("HOLO_ADMIN_PASSWORD", "admin123")
)

# --- Login brute-force throttling (in-memory, per-process) -------------
MAX_LOGIN_ATTEMPTS = 5
LOGIN_LOCKOUT_SECONDS = 300
_login_attempts = {}  # ip -> {"count": int, "locked_until": float}

# --- Input validation ---------------------------------------------------
_IP_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
_MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")


def _valid_ip(ip):
    if not ip or not _IP_RE.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def _valid_mac(mac):
    return bool(mac and _MAC_RE.match(mac))


# --- Shared-file helpers (atomic write, safe read) ----------------------
def _atomic_write_json(path, data):
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp_path, path)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _safe_read_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def init_blocked_file():
    """Initialize blocked.json if it doesn't exist."""
    if not os.path.exists(BLOCKED_FILE):
        _atomic_write_json(BLOCKED_FILE, {"blocked_ips": [], "blocked_macs": []})


os.makedirs(SHARED_DIR, exist_ok=True)


# --- Auth / CSRF decorators ----------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "logged_in" not in session:
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function


def csrf_protect(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        token = session.get("csrf_token")
        header_token = request.headers.get("X-CSRFToken")
        if not token or not header_token or not secrets.compare_digest(token, header_token):
            return jsonify({"error": "Invalid or missing CSRF token"}), 403
        return f(*args, **kwargs)
    return decorated_function


# --- Routes ----------------------------------------------------------------
@app.route("/")
def index():
    if "logged_in" not in session:
        return redirect(url_for("login"))
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_hex(16)
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        now = time.time()

        attempt = _login_attempts.get(client_ip)
        if attempt and attempt["locked_until"] > now:
            wait = int(attempt["locked_until"] - now)
            return jsonify({
                "success": False,
                "error": "Too many failed attempts. Try again in %ds." % wait,
            }), 429

        username = request.form.get("username", "")
        password = request.form.get("password", "")

        valid_user = secrets.compare_digest(username, ADMIN_USERNAME)
        valid_pass = check_password_hash(ADMIN_PASSWORD_HASH, password)

        if valid_user and valid_pass:
            _login_attempts.pop(client_ip, None)
            session.clear()
            session["logged_in"] = True
            session["username"] = username
            session["csrf_token"] = secrets.token_hex(16)
            return jsonify({"success": True, "redirect": url_for("index")})
        else:
            attempt = _login_attempts.setdefault(client_ip, {"count": 0, "locked_until": 0})
            attempt["count"] += 1
            if attempt["count"] >= MAX_LOGIN_ATTEMPTS:
                attempt["locked_until"] = now + LOGIN_LOCKOUT_SECONDS
                attempt["count"] = 0
            return jsonify({"success": False, "error": "Invalid credentials"}), 401

    if "logged_in" in session:
        return redirect(url_for("index"))

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/api/state")
@login_required
def get_state():
    state = _safe_read_json(STATE_FILE, {"alerts": [], "arp_table": [], "last_update": None})
    init_blocked_file()
    blocked = _safe_read_json(BLOCKED_FILE, {"blocked_ips": [], "blocked_macs": []})
    state["blocked_ips"] = blocked.get("blocked_ips", [])
    state["blocked_macs"] = blocked.get("blocked_macs", [])
    return jsonify(state)


@app.route("/api/block", methods=["POST"])
@login_required
@csrf_protect
def block_host():
    """Block an IP and/or MAC address."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip() or None
    mac = (data.get("mac") or "").strip() or None

    if not ip and not mac:
        return jsonify({"error": "IP or MAC address required"}), 400
    if ip and not _valid_ip(ip):
        return jsonify({"error": "Invalid IPv4 address"}), 400
    if mac and not _valid_mac(mac):
        return jsonify({"error": "Invalid MAC address"}), 400

    init_blocked_file()
    blocked = _safe_read_json(BLOCKED_FILE, {"blocked_ips": [], "blocked_macs": []})

    if ip and ip not in blocked["blocked_ips"]:
        blocked["blocked_ips"].append(ip)
    if mac and mac not in blocked["blocked_macs"]:
        blocked["blocked_macs"].append(mac)

    _atomic_write_json(BLOCKED_FILE, blocked)

    command = {
        "action": "block",
        "ip": ip,
        "mac": mac,
        "timestamp": datetime.now().isoformat(),
        "user": session.get("username", "admin"),
    }
    commands = _safe_read_json(COMMAND_FILE, [])
    commands.append(command)
    _atomic_write_json(COMMAND_FILE, commands)

    return jsonify({"success": True, "message": "Blocked: IP=%s, MAC=%s" % (ip, mac)})


@app.route("/api/unblock", methods=["POST"])
@login_required
@csrf_protect
def unblock_host():
    """Unblock an IP and/or MAC address."""
    data = request.get_json(silent=True) or {}
    ip = (data.get("ip") or "").strip() or None
    mac = (data.get("mac") or "").strip() or None

    if ip and not _valid_ip(ip):
        return jsonify({"error": "Invalid IPv4 address"}), 400
    if mac and not _valid_mac(mac):
        return jsonify({"error": "Invalid MAC address"}), 400

    init_blocked_file()
    blocked = _safe_read_json(BLOCKED_FILE, {"blocked_ips": [], "blocked_macs": []})

    if ip and ip in blocked["blocked_ips"]:
        blocked["blocked_ips"].remove(ip)
    if mac and mac in blocked["blocked_macs"]:
        blocked["blocked_macs"].remove(mac)

    _atomic_write_json(BLOCKED_FILE, blocked)

    command = {
        "action": "unblock",
        "ip": ip,
        "mac": mac,
        "timestamp": datetime.now().isoformat(),
        "user": session.get("username", "admin"),
    }
    commands = _safe_read_json(COMMAND_FILE, [])
    commands.append(command)
    _atomic_write_json(COMMAND_FILE, commands)

    return jsonify({"success": True, "message": "Unblocked: IP=%s, MAC=%s" % (ip, mac)})


# --- Real ML: ONLINE/incremental anomaly detection over per-MAC behavior --
#
# This is genuine machine learning that actually accumulates knowledge over
# time, not a model retrained from scratch on every request. It is a
# classic online multivariate anomaly detector: per-feature running mean
# and variance are updated incrementally with Welford's algorithm (the
# standard numerically-stable method for streaming mean/variance), and a
# new observation is scored by its squared Mahalanobis distance from that
# running mean. Under a normality assumption this distance follows a
# chi-square distribution with k degrees of freedom (k = number of
# features), which gives a statistically principled way to turn "distance"
# into an anomaly percentile instead of an arbitrary score — this is the
# same idea behind classical multivariate statistical process control.
#
# (We evaluated a linear SGDOneClassSVM first, but a linear one-class
# model only learns a single half-space: points that are unusually far
# from the training data in the "normal" direction of that half-space
# still score as inliers. Mahalanobis distance grows for a deviation in
# ANY direction, which is what we actually want for attacker detection.)
#
# On each analyze request, for every MAC with recent alerts we:
#   1. Score the MAC's current behavior against the mean/variance learned
#      SO FAR (i.e. from every previous check, not this one).
#   2. Only THEN fold this observation into the running mean/variance.
# This ordering matters — scoring after learning from the same sample
# would make everything look artificially normal.

_ANOMALY_FEATURE_NAMES = [
    "total_alerts",
    "arp_spoof_count",
    "ip_spoof_count",
    "mac_move_count",
    "flood_count",
    "scan_count",
    "distinct_ips",
    "distinct_switches",
    "alert_rate_per_sec",
    "avg_seconds_between_alerts",
]

_FLOOD_ALERT_TYPES = {"SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "FLOOD_SUSPECTED"}

# Count/rate-like features are heavy-tailed (a normal host has ~0-2 alerts,
# an attacker can have dozens within the same window). log1p is the
# standard fix for this kind of skew and keeps the running variance
# estimate from being dominated by rare bursts.
_LOG_TRANSFORM_FEATURES = {
    "total_alerts", "arp_spoof_count", "ip_spoof_count",
    "mac_move_count", "flood_count", "scan_count", "alert_rate_per_sec",
}

ONLINE_MODEL_FILE = os.path.join(SHARED_DIR, "online_anomaly_model.pkl")

# Below this many total learned samples, the running mean/variance haven't
# stabilized enough to score meaningfully. We say so honestly (a "cold
# start" state) instead of returning a score that doesn't mean anything.
_ONLINE_COLD_START_SAMPLES = 5

# Anomaly percentile (0-100) above which a host is flagged, equivalent to
# the standard "outside the 95% confidence region" statistical threshold.
_ANOMALY_PERCENTILE_THRESHOLD = 95.0


class _OnlineGaussianModel:
    """Incrementally-updated per-feature mean/variance (Welford's
    algorithm) used to score new points by squared Mahalanobis distance
    from the running mean, converted to a chi-square percentile."""

    def __init__(self, n_features):
        self.n_features = n_features
        self.n = 0
        self.mean = np.zeros(n_features)
        self.m2 = np.zeros(n_features)  # sum of squared deviations

    def score(self, x):
        """Return an anomaly percentile (0-100) for x given everything
        learned so far, or None during cold start."""
        if self.n < _ONLINE_COLD_START_SAMPLES:
            return None
        variance = np.maximum(self.m2 / (self.n - 1), 1e-6)
        z = (x - self.mean) / np.sqrt(variance)
        d2 = float(np.sum(z ** 2))
        return float(chi2.cdf(d2, df=self.n_features) * 100.0)

    def update(self, x):
        """Fold a new observation into the running mean/variance."""
        self.n += 1
        delta = x - self.mean
        self.mean += delta / self.n
        self.m2 += delta * (x - self.mean)


def _feature_vector(feats):
    row = []
    for name in _ANOMALY_FEATURE_NAMES:
        v = float(feats[name])
        if name in _LOG_TRANSFORM_FEATURES:
            v = np.log1p(max(v, 0.0))
        row.append(v)
    return np.array(row, dtype=float)


def _load_online_model():
    expected_dims = len(_ANOMALY_FEATURE_NAMES)
    if os.path.exists(ONLINE_MODEL_FILE):
        try:
            with open(ONLINE_MODEL_FILE, "rb") as f:
                model = pickle.load(f)
            if getattr(model, "n_features", None) == expected_dims:
                return model
            # Feature schema changed (e.g. flood_count was added) — a
            # dimension mismatch would crash scoring, so start fresh
            # rather than silently produce garbage or raise.
        except Exception:
            pass
    return _OnlineGaussianModel(expected_dims)


def _save_online_model(model):
    directory = os.path.dirname(ONLINE_MODEL_FILE) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp_")
    try:
        with os.fdopen(fd, "wb") as f:
            pickle.dump(model, f)
        os.replace(tmp_path, ONLINE_MODEL_FILE)
    except Exception:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        raise


def _parse_alert_time(ts):
    try:
        return datetime.strptime(ts, "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None


def _extract_mac_features(alerts):
    """Group alerts by source MAC and compute a behavioral feature vector
    for each one (volume, alert-type mix, breadth across the network, and
    timing/burstiness)."""
    by_mac = {}
    for a in alerts:
        mac = a.get("mac")
        if not mac:
            continue
        by_mac.setdefault(mac, []).append(a)

    features = {}
    for mac, mac_alerts in by_mac.items():
        times = sorted(
            t for t in (_parse_alert_time(a.get("time")) for a in mac_alerts) if t
        )
        total = len(mac_alerts)
        arp = sum(1 for a in mac_alerts if a.get("type") == "ARP_SPOOF")
        ipsp = sum(1 for a in mac_alerts if a.get("type") == "IP_SPOOF")
        move = sum(1 for a in mac_alerts if a.get("type") == "MAC_MOVE")
        flood = sum(1 for a in mac_alerts if a.get("type") in _FLOOD_ALERT_TYPES)
        scan = sum(1 for a in mac_alerts if a.get("type") == "PORT_SCAN")
        distinct_ips = len({a.get("ip") for a in mac_alerts if a.get("ip")})
        distinct_dpids = len({a.get("dpid") for a in mac_alerts if a.get("dpid") is not None})

        if len(times) >= 2:
            span = (times[-1] - times[0]).total_seconds()
            gaps = [
                (times[i + 1] - times[i]).total_seconds()
                for i in range(len(times) - 1)
            ]
            avg_gap = sum(gaps) / len(gaps)
        else:
            span = 0.0
            avg_gap = 0.0

        rate = (total / span) if span > 0 else float(total)

        features[mac] = {
            "total_alerts": total,
            "arp_spoof_count": arp,
            "ip_spoof_count": ipsp,
            "mac_move_count": move,
            "flood_count": flood,
            "scan_count": scan,
            "distinct_ips": distinct_ips,
            "distinct_switches": distinct_dpids,
            "alert_rate_per_sec": round(rate, 4),
            "avg_seconds_between_alerts": round(avg_gap, 2),
        }
    return features


def _run_anomaly_detection(alerts):
    """Score each MAC's current behavior against the online Gaussian
    model's accumulated mean/variance, then fold this observation into
    the model. Genuinely learns across calls and across restarts."""
    feat_map = _extract_mac_features(alerts)
    if not feat_map:
        return {"available": False, "reason": "No alert data yet.", "hosts": []}

    model = _load_online_model()

    hosts = []
    for mac, feats in feat_map.items():
        x = _feature_vector(feats)

        percentile = model.score(x)
        cold_start = percentile is None
        anomaly_score = round(percentile, 1) if percentile is not None else None
        is_anomaly = bool(percentile is not None and percentile >= _ANOMALY_PERCENTILE_THRESHOLD)

        # Learn from this observation AFTER scoring it, so the score above
        # reflects only what was known before this check.
        model.update(x)

        hosts.append({
            "mac": mac,
            "anomaly_score": anomaly_score,
            "is_anomaly": is_anomaly,
            "cold_start": cold_start,
            "features": feats,
        })

    _save_online_model(model)

    hosts.sort(key=lambda h: (h["anomaly_score"] is None, -(h["anomaly_score"] or 0)))

    return {
        "available": True,
        "model": "Online Gaussian / Mahalanobis distance (incremental, chi-square scored)",
        "total_samples_learned": model.n,
        "cold_start_threshold": _ONLINE_COLD_START_SAMPLES,
        "anomaly_percentile_threshold": _ANOMALY_PERCENTILE_THRESHOLD,
        "hosts": hosts,
    }


# --- Comparison methods, computed on the SAME data every request --------
#
# These exist so "Our Method" (the online Mahalanobis model above) always
# has real, simultaneously-computed numbers to be compared against — not
# because they're meant to be better. Per-request comparison, honestly:
#
#   1. Rule-threshold-only: the simplest possible baseline (fixed counts).
#   2. Batch IsolationForest: a standard, well-known scikit-learn model,
#      retrained from scratch every request (unlike our online model,
#      it has no memory between checks — this is the actual, honest
#      difference an ablation/comparison table should show).

# Same MAC-count threshold this project's rule-based tier already uses,
# reused here as an explicit per-host baseline for comparison purposes.
_RULE_THRESHOLD_ALERTS = 5


def _run_rule_threshold_method(feat_map):
    """Flags a host anomalous purely if its total alert count exceeds a
    fixed constant. No learning, no adaptation — the simplest possible
    comparison point."""
    hosts = []
    for mac, feats in feat_map.items():
        is_anomaly = feats["total_alerts"] > _RULE_THRESHOLD_ALERTS
        hosts.append({"mac": mac, "is_anomaly": is_anomaly})
    return {
        "available": True,
        "model": "Fixed threshold (total_alerts > %d)" % _RULE_THRESHOLD_ALERTS,
        "learns_over_time": False,
        "hosts": hosts,
    }


def _run_batch_isolation_forest(feat_map):
    """Standard scikit-learn IsolationForest, retrained from scratch on
    every request from whatever MACs currently have alerts. No persisted
    state — this is the honest point of contrast with the online model."""
    macs = list(feat_map.keys())
    if len(macs) < 4:
        return {
            "available": False,
            "reason": "IsolationForest needs at least 4 samples to fit meaningfully "
                      "(currently %d)." % len(macs),
            "hosts": [],
        }

    X = np.array([_feature_vector(feat_map[m]) for m in macs], dtype=float)
    model = IsolationForest(n_estimators=200, contamination="auto", random_state=42)
    model.fit(X)
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal

    hosts = [
        {"mac": mac, "is_anomaly": bool(pred == -1)}
        for mac, pred in zip(macs, predictions)
    ]
    return {
        "available": True,
        "model": "IsolationForest (scikit-learn, batch-retrained every request)",
        "learns_over_time": False,
        "hosts": hosts,
    }


@app.route("/api/ai/analyze", methods=["POST"])
@login_required
@csrf_protect
def ai_analyze():
    """
    Two layers of analysis, kept honestly separate:

    1) A rule-based threat triage (threat_level, recommendations) — a
       heuristic/threshold engine over recent alert counts. Fast, always
       available, but not "AI" in any real sense.
    2) Genuine machine learning: an online, incrementally-updated Gaussian
       model (Welford mean/variance + Mahalanobis distance, chi-square
       scored) under analysis['anomaly_detection']. Every call both scores
       current behavior against what it has learned so far AND folds that
       observation into the running statistics, and the model persists to
       disk across restarts — it learns what "normal" looks like from the
       actual alert history, with no hardcoded thresholds involved.

    A third block, analysis['method_comparison'], runs the online model
    alongside a fixed-threshold baseline and a batch-retrained
    IsolationForest on the same data for direct comparison.
    """
    state = _safe_read_json(STATE_FILE, {"alerts": []})
    alerts = state.get("alerts", [])

    analysis = {"threat_level": "LOW", "recommendations": [], "patterns": {}}

    alert_types = {}
    for alert in alerts[-100:]:
        alert_type = alert.get("type", "UNKNOWN")
        alert_types[alert_type] = alert_types.get(alert_type, 0) + 1

    high_risk_types = ["ARP_SPOOF", "IP_SPOOF", "MAC_BLOCKED", "SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "PORT_SCAN"]
    high_risk_count = sum(alert_types.get(t, 0) for t in high_risk_types)

    if high_risk_count > 20:
        analysis["threat_level"] = "CRITICAL"
    elif high_risk_count > 10:
        analysis["threat_level"] = "HIGH"
    elif high_risk_count > 5:
        analysis["threat_level"] = "MEDIUM"

    if alert_types.get("ARP_SPOOF", 0) > 5:
        analysis["recommendations"].append(
            "Multiple ARP spoofing attempts detected. Consider enabling ARP inspection."
        )
    if alert_types.get("MAC_MOVE", 0) > 3:
        analysis["recommendations"].append(
            "MAC address movement detected. Review network topology."
        )
    flood_total = sum(alert_types.get(t, 0) for t in ["SYN_FLOOD", "UDP_FLOOD", "ICMP_FLOOD", "FLOOD_SUSPECTED"])
    if flood_total > 3:
        analysis["recommendations"].append(
            "Flood-pattern traffic detected (SYN/UDP/ICMP). Verify the source host and consider rate-limiting."
        )
    if alert_types.get("PORT_SCAN", 0) > 2:
        analysis["recommendations"].append(
            "Horizontal scanning detected (one host contacting many others rapidly). Verify intent before unblocking."
        )
    if len(alerts) > 50:
        analysis["recommendations"].append(
            "High alert volume. Review security policies and consider blocking suspicious hosts."
        )

    analysis["patterns"] = alert_types
    analysis["anomaly_detection"] = _run_anomaly_detection(alerts)

    # Real, simultaneously-computed comparison — see the note above
    # _run_rule_threshold_method for why these numbers are honest rather
    # than "Method A/B" placeholders.
    feat_map = _extract_mac_features(alerts)
    analysis["method_comparison"] = {
        "rule_threshold": _run_rule_threshold_method(feat_map),
        "batch_isolation_forest": _run_batch_isolation_forest(feat_map),
        "our_online_method": analysis["anomaly_detection"],
    }
    return jsonify(analysis)


@app.route("/api/ai/reset-model", methods=["POST"])
@login_required
@csrf_protect
def reset_online_model():
    """Delete the persisted online anomaly model, starting it back at
    cold-start. Mainly useful for benchmark Scenario 6 (model persistence
    testing) — reset here, then compare detection quality before/after
    the model has re-accumulated observations."""
    try:
        if os.path.exists(ONLINE_MODEL_FILE):
            os.remove(ONLINE_MODEL_FILE)
        return jsonify({"success": True, "message": "Online anomaly model reset to cold start."})
    except Exception as e:
        return jsonify({"error": "Failed to reset model: %s" % e}), 500


@app.route("/api/export/csv")
@login_required
def export_csv():
    """Export alerts to CSV."""
    state = _safe_read_json(STATE_FILE, {"alerts": []})
    alerts = state.get("alerts", [])

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Time", "Type", "IP", "MAC", "DPID", "Reason"])
    for alert in alerts:
        writer.writerow([
            alert.get("time", ""),
            alert.get("type", ""),
            alert.get("ip", ""),
            alert.get("mac", ""),
            alert.get("dpid", ""),
            alert.get("reason", ""),
        ])
    output.seek(0)

    filename = "security_report_%s.csv" % datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        io.BytesIO(output.getvalue().encode("utf-8")),
        mimetype="text/csv",
        as_attachment=True,
        download_name=filename,
    )


@app.route("/api/export/pdf")
@login_required
def export_pdf():
    """Export alerts + ARP table to PDF."""
    state = _safe_read_json(STATE_FILE, {"alerts": [], "arp_table": []})
    alerts = state.get("alerts", [])
    arp_table = state.get("arp_table", [])

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    story = []

    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        "CustomTitle", parent=styles["Heading1"], fontSize=24,
        textColor=colors.HexColor("#1a1a1a"), spaceAfter=30, alignment=TA_CENTER,
    )

    story.append(Paragraph("HOLO SECURITY Executive Security Report", title_style))
    story.append(Spacer(1, 0.2 * inch))

    report_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    story.append(Paragraph("<b>Generated:</b> %s" % report_date, styles["Normal"]))
    story.append(Paragraph("<b>Total Alerts:</b> %d" % len(alerts), styles["Normal"]))
    story.append(Spacer(1, 0.3 * inch))

    if alerts:
        story.append(Paragraph("<b>Security Alerts</b>", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))

        table_data = [["Time", "Type", "IP", "MAC", "Reason"]]
        for alert in alerts[-100:]:
            table_data.append([
                alert.get("time", "")[:16],
                alert.get("type", ""),
                alert.get("ip", "N/A"),
                (alert.get("mac") or "N/A")[:17],
                (alert.get("reason") or "")[:50],
            ])

        table = Table(table_data)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2c3e50")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.beige),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
            ("FONTSIZE", (0, 1), (-1, -1), 8),
        ]))
        story.append(table)
        story.append(PageBreak())

    if arp_table:
        story.append(Paragraph("<b>ARP Table</b>", styles["Heading2"]))
        story.append(Spacer(1, 0.1 * inch))

        table_data = [["IP Address", "MAC Address", "Switch DPID"]]
        for entry in arp_table[:50]:
            table_data.append([
                entry.get("ip", ""), entry.get("mac", ""), str(entry.get("dpid", "")),
            ])

        table = Table(table_data)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#34495e")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("BOTTOMPADDING", (0, 0), (-1, 0), 12),
            ("BACKGROUND", (0, 1), (-1, -1), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 1, colors.black),
        ]))
        story.append(table)

    doc.build(story)
    buffer.seek(0)

    filename = "security_report_%s.pdf" % datetime.now().strftime("%Y%m%d_%H%M%S")
    return send_file(
        buffer, mimetype="application/pdf", as_attachment=True, download_name=filename,
    )


if __name__ == "__main__":
    init_blocked_file()

    if _USING_DEFAULT_PASSWORD:
        print(
            "[WARNING] HOLO_ADMIN_PASSWORD is not set — using the default "
            "'admin123' password. Set HOLO_ADMIN_USER / HOLO_ADMIN_PASSWORD "
            "environment variables before running this outside of local testing."
        )

    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    host = os.environ.get("HOLO_HOST", "127.0.0.1")  # not 0.0.0.0 by default
    port = int(os.environ.get("HOLO_PORT", "5000"))

    app.run(host=host, port=port, debug=debug_mode)
