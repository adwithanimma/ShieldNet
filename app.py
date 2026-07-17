import psutil
import smtplib
import requests
from email.mime.text import MIMEText
from flask import Flask, request, jsonify, render_template, session, redirect, url_for, Response
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
from collections import defaultdict
import time
import os
import statistics
import secrets

# Load .env file if python-dotenv is installed (optional but recommended)
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)

# Secret key for signing session cookies. Set SHIELDNET_SECRET_KEY in .env
# for a stable value across restarts; otherwise a random one is generated
# each time the server starts (which will log everyone out on restart).
app.secret_key = os.environ.get("SHIELDNET_SECRET_KEY", secrets.token_hex(32))

# Admin credentials for the dashboard/admin endpoints.
ADMIN_USERNAME = os.environ.get("SHIELDNET_ADMIN_USERNAME", "admin")
# Password is stored as a hash, either supplied directly via env or derived
# from a plaintext env password on first run (see below).
_admin_password_hash_env = os.environ.get("SHIELDNET_ADMIN_PASSWORD_HASH")
_admin_password_plain = os.environ.get("SHIELDNET_ADMIN_PASSWORD")

if _admin_password_hash_env:
    ADMIN_PASSWORD_HASH = _admin_password_hash_env
elif _admin_password_plain:
    ADMIN_PASSWORD_HASH = generate_password_hash(_admin_password_plain)
else:
    # No credentials configured at all - fall back to a default so the app
    # still runs, but this should always be overridden via .env in practice.
    ADMIN_PASSWORD_HASH = generate_password_hash("shieldnet")
    print("⚠️  No SHIELDNET_ADMIN_PASSWORD set in .env — using default password "
          "'shieldnet'. Set SHIELDNET_ADMIN_USERNAME / SHIELDNET_ADMIN_PASSWORD "
          "in .env before any real use.")


def login_required(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("logged_in"):
            wants_json = "application/json" in (request.headers.get("Accept") or "") \
                or request.headers.get("X-Requested-With") == "XMLHttpRequest"
            if wants_json:
                return jsonify({"status": "unauthorized", "message": "Login required"}), 401
            return redirect(url_for("login", next=request.path))
        return view_func(*args, **kwargs)
    return wrapped


# Store requests (raw timestamps, used for the 10s sliding window)
request_log = defaultdict(list)

# Per-IP time series for sparklines: list of (timestamp, request_count) samples
ip_history = defaultdict(list)

# Per-IP history of past window counts, used to compute a rolling baseline
# (mean/stddev) for the z-score / adaptive detection method.
ip_baseline = defaultdict(list)

# Store blocked IPs -> unblock timestamp
blocked_ips = {}

# Store attack history
attack_history = []

# IPs that are never blocked or flagged, regardless of traffic volume
whitelisted_ips = set()

# Settings
REQUEST_LIMIT = 20                              # fixed-threshold method
SUSPICIOUS_LIMIT = int(REQUEST_LIMIT * 0.6)     # 60% of block threshold
BLOCK_TIME = 30
SPARKLINE_MAX_POINTS = 30
BASELINE_MAX_SAMPLES = 50                       # how many past windows to remember per IP
Z_SCORE_THRESHOLD = 3.0                         # how many std devs above baseline counts as an attack

# The real website ShieldNet is protecting. Requests to /protected/... are
# checked against the detection engine BEFORE being forwarded here - if an
# IP is flagged, the demo site never sees the request at all.
DEMO_SITE_URL = os.environ.get("DEMO_SITE_URL", "http://127.0.0.1:6060")

# Create logs folder
os.makedirs("logs", exist_ok=True)


def send_alert(ip):
    sender_email = os.environ.get("SHIELDNET_EMAIL")
    app_password = os.environ.get("SHIELDNET_APP_PASSWORD")
    receiver_email = os.environ.get("SHIELDNET_RECEIVER_EMAIL", sender_email)

    if not sender_email or not app_password:
        print("⚠️  Email alert skipped: SHIELDNET_EMAIL / SHIELDNET_APP_PASSWORD not set in environment.")
        return

    subject = "ShieldNet DDoS Alert"

    body = f"""
DDoS Attack Detected

Attacker IP: {ip}

Time: {time.strftime('%H:%M:%S')}

Action Taken:
IP temporarily blocked by ShieldNet.
"""

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = receiver_email

    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(sender_email, app_password)
        server.sendmail(sender_email, receiver_email, msg.as_string())
        server.quit()
        print("📧 Alert Email Sent Successfully")
    except Exception as e:
        print("Email Error:", e)


def detect(ip, request_count):
    """
    Run both detection methods and return their results so they can be
    compared (used by the evaluation script) as well as combined for the
    actual blocking decision.

    fixed_flag:    simple static-threshold method (original approach)
    zscore_flag:   adaptive method - flags traffic that is an unusual spike
                   relative to that IP's own recent history, rather than a
                   single hardcoded number for everyone
    """
    history = ip_baseline[ip]

    fixed_flag = request_count > REQUEST_LIMIT

    if len(history) >= 3:
        baseline_mean = statistics.mean(history)
        baseline_std = statistics.pstdev(history)
        if baseline_std > 0:
            z_score = (request_count - baseline_mean) / baseline_std
            zscore_flag = z_score > Z_SCORE_THRESHOLD
        else:
            # No variance yet (e.g. flat baseline) - fall back to a
            # multiple-of-baseline check so a sudden jump still triggers.
            zscore_flag = baseline_mean > 0 and request_count > baseline_mean * 3
    else:
        # Not enough history yet to compute a meaningful baseline.
        zscore_flag = False

    # Record this sample for future baseline calculations.
    history.append(request_count)
    if len(history) > BASELINE_MAX_SAMPLES:
        ip_baseline[ip] = history[-BASELINE_MAX_SAMPLES:]

    combined_flag = fixed_flag or zscore_flag
    return fixed_flag, zscore_flag, combined_flag


def record_ip_sample(ip, count):
    """Track a time series of request counts per IP for sparklines."""
    ip_history[ip].append({"time": time.strftime("%H:%M:%S"), "count": count})
    if len(ip_history[ip]) > SPARKLINE_MAX_POINTS:
        ip_history[ip] = ip_history[ip][-SPARKLINE_MAX_POINTS:]


def get_client_ip():
    """
    Identify the client IP. Checks X-Forwarded-For first so tools like
    attack.py can simulate distinct attacker IPs locally (this mirrors how
    a real app behind a proxy/load balancer would read client IPs).
    """
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr


def get_severity(request_count, ip):
    if ip in blocked_ips:
        return "attack"
    if request_count > REQUEST_LIMIT:
        return "attack"
    if request_count > SUSPICIOUS_LIMIT:
        return "suspicious"
    return "secure"


# ==========================
# Authentication
# ==========================
@app.route('/login', methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        if username == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["logged_in"] = True
            session["username"] = username
            next_path = request.args.get("next") or url_for("dashboard")
            return redirect(next_path)
        else:
            error = "Invalid username or password."

    return render_template("login.html", error=error)


@app.route('/logout', methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ==========================
# Dashboard Page
# ==========================
@app.route('/')
@login_required
def dashboard():
    return render_template("index.html", username=session.get("username"))


def evaluate_request(ip):
    """
    Runs the full detection pipeline for a single request from `ip`:
    whitelist check, block check, sliding-window counting, and combined
    fixed+rolling-baseline detection. Used by both /track (the original
    synthetic traffic endpoint) and the /protected proxy (real requests
    being forwarded to the demo site).

    Returns a tuple: (allowed: bool, status_message: str)
    """
    current_time = time.time()

    if ip in whitelisted_ips:
        request_log[ip].append(current_time)
        request_log[ip] = [t for t in request_log[ip] if current_time - t < 10]
        return True, "whitelisted"

    if ip in blocked_ips:
        if current_time < blocked_ips[ip]:
            return False, "already_blocked"
        else:
            del blocked_ips[ip]

    request_log[ip].append(current_time)
    request_log[ip] = [t for t in request_log[ip] if current_time - t < 10]

    request_count = len(request_log[ip])
    record_ip_sample(ip, request_count)

    with open("logs/traffic.log", "a") as file:
        file.write(f"IP: {ip}, Requests: {request_count}\n")

    fixed_flag, zscore_flag, combined_flag = detect(ip, request_count)

    if combined_flag and ip not in blocked_ips:
        attack_history.append({
            "ip": ip,
            "time": time.strftime("%H:%M:%S"),
            "requests": request_count,
            "detected_by": {
                "fixed_threshold": fixed_flag,
                "rolling_baseline": zscore_flag
            }
        })

        print(f"\n🚨 ALERT: DDoS Attack Detected from {ip} "
              f"(fixed={fixed_flag}, zscore={zscore_flag})")
        print(f"🛑 Blocking IP: {ip}\n")
        send_alert(ip)

        blocked_ips[ip] = current_time + BLOCK_TIME
        return False, "newly_blocked"

    return True, "ok"


# ==========================
# Traffic Monitoring Route
# ==========================
@app.route('/track')
def track():
    ip = get_client_ip()
    allowed, status = evaluate_request(ip)

    if not allowed:
        if status == "already_blocked":
            return f"🚫 IP {ip} is temporarily blocked!"
        return f"🚫 DDoS Detected. IP {ip} blocked."

    if status == "whitelisted":
        return "ShieldNet Server Running (whitelisted)"

    return "ShieldNet Server Running"


# ==========================
# Protected Site Reverse Proxy
# ==========================
# Every request here is evaluated by ShieldNet's detection engine BEFORE
# being forwarded to the real site (DEMO_SITE_URL). If the requesting IP
# is blocked or newly flagged, the demo site never receives the request -
# ShieldNet returns a block page directly instead.

HOP_BY_HOP_HEADERS = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailers", "transfer-encoding", "upgrade", "content-length", "content-encoding"
}


@app.route('/protected/', defaults={'path': ''}, methods=["GET", "POST"])
@app.route('/protected/<path:path>', methods=["GET", "POST"])
def protected_proxy(path):
    ip = get_client_ip()
    allowed, status = evaluate_request(ip)

    if not allowed:
        message = (
            f"🚫 Your IP ({ip}) is temporarily blocked due to suspicious traffic."
            if status == "already_blocked" else
            f"🚫 DDoS activity detected from your IP ({ip}). Access blocked by ShieldNet."
        )
        return Response(
            f"<html><body style='font-family:sans-serif; text-align:center; padding:60px;'>"
            f"<h1>403 — Blocked by ShieldNet</h1><p>{message}</p></body></html>",
            status=403,
            mimetype="text/html"
        )

    # Request passed detection - forward it to the real (demo) site
    target_url = f"{DEMO_SITE_URL}/{path}"

    try:
        upstream = requests.request(
            method=request.method,
            url=target_url,
            headers={k: v for k, v in request.headers if k.lower() != "host"},
            data=request.get_data(),
            params=request.args,
            allow_redirects=False,
            timeout=5
        )
    except requests.exceptions.RequestException:
        return Response(
            "<h1>502 — Demo site unreachable</h1>"
            "<p>ShieldNet allowed this request through, but the protected site did not respond. "
            f"Make sure it's running at {DEMO_SITE_URL}.</p>",
            status=502,
            mimetype="text/html"
        )

    response_headers = [
        (k, v) for k, v in upstream.headers.items()
        if k.lower() not in HOP_BY_HOP_HEADERS
    ]
    return Response(upstream.content, status=upstream.status_code, headers=response_headers)


# ==========================
# Dashboard Statistics API
# ==========================
@app.route('/stats')
@login_required
def stats():
    active_users = len(request_log)
    total_requests = sum(len(reqs) for reqs in request_log.values())

    top_attacker = "None"
    max_requests = 0

    for ip, reqs in request_log.items():
        if len(reqs) > max_requests:
            max_requests = len(reqs)
            top_attacker = ip

    severity = get_severity(max_requests, top_attacker if top_attacker != "None" else "")

    network = psutil.net_io_counters()

    return jsonify({
        "active_users": active_users,
        "blocked_ips": len(blocked_ips),
        "total_requests": total_requests,
        "top_attacker": top_attacker,
        "max_requests": max_requests,
        "timestamp": time.strftime("%H:%M:%S"),
        "severity": severity,
        "suspicious_limit": SUSPICIOUS_LIMIT,
        "request_limit": REQUEST_LIMIT,
        "latest_alert": attack_history[-1] if attack_history else "No Alerts",
        "top_attacker_sparkline": ip_history.get(top_attacker, []) if top_attacker != "None" else [],
        "packets_sent": network.packets_sent,
        "packets_recv": network.packets_recv,
        "bytes_sent": network.bytes_sent,
        "bytes_recv": network.bytes_recv
    })


# ==========================
# Attack History API (filterable)
# ==========================
@app.route('/history')
@login_required
def history():
    ip_filter = request.args.get("ip")
    results = attack_history

    if ip_filter:
        results = [item for item in results if item["ip"] == ip_filter]

    return jsonify(results)


# ==========================
# Blocked IPs Management
# ==========================
@app.route('/blocked')
@login_required
def blocked():
    current_time = time.time()
    result = [
        {
            "ip": ip,
            "unblock_at": time.strftime("%H:%M:%S", time.localtime(unblock_time)),
            "seconds_remaining": max(0, int(unblock_time - current_time))
        }
        for ip, unblock_time in blocked_ips.items()
    ]
    return jsonify(result)


@app.route('/unblock/<ip>', methods=["POST"])
@login_required
def unblock(ip):
    if ip in blocked_ips:
        del blocked_ips[ip]
        return jsonify({"status": "ok", "message": f"{ip} unblocked"})
    return jsonify({"status": "not_found", "message": f"{ip} was not blocked"}), 404


# ==========================
# Whitelist Management
# ==========================
@app.route('/whitelist')
@login_required
def get_whitelist():
    return jsonify(sorted(whitelisted_ips))


@app.route('/whitelist/add/<ip>', methods=["POST"])
@login_required
def whitelist_add(ip):
    whitelisted_ips.add(ip)
    # A whitelisted IP shouldn't stay blocked
    if ip in blocked_ips:
        del blocked_ips[ip]
    return jsonify({"status": "ok", "message": f"{ip} added to whitelist"})


@app.route('/whitelist/remove/<ip>', methods=["POST"])
@login_required
def whitelist_remove(ip):
    whitelisted_ips.discard(ip)
    return jsonify({"status": "ok", "message": f"{ip} removed from whitelist"})


# ==========================
# Reset (for testing / evaluation runs only)
# ==========================
@app.route('/reset', methods=["POST"])
@login_required
def reset():
    """
    Clears all traffic state so a fresh test scenario (e.g. an evaluation
    preset) can be run without previous requests skewing the results.
    Does NOT clear the whitelist, since that's meant to be a persistent
    operator setting rather than test-run state.
    """
    request_log.clear()
    ip_history.clear()
    ip_baseline.clear()
    blocked_ips.clear()
    attack_history.clear()
    return jsonify({"status": "ok", "message": "State reset"})


# ==========================
# Run Flask
# ==========================
import os

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )