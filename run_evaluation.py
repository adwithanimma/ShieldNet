"""
ShieldNet Evaluation Script
----------------------------
Runs each built-in attack preset against a live ShieldNet server (with a
clean state each time via /reset), then reports how well the detector
performed: which IPs were correctly/incorrectly blocked, and how many
requests each IP sent before being blocked (if at all).

Ground truth definition used here (simple, for the report's methodology
section): an IP is a "true attacker" if its configured request count
exceeds REQUEST_LIMIT (20); otherwise it's "benign" traffic that should
NOT be blocked.

Usage:
    python run_evaluation.py
    python run_evaluation.py --presets heavy mixed
"""

import requests
import time
import random
import threading
import argparse
import csv
import os

TARGET_BASE = "http://127.0.0.1:5000"
TRACK_URL = f"{TARGET_BASE}/track"
RESET_URL = f"{TARGET_BASE}/reset"
BLOCKED_URL = f"{TARGET_BASE}/blocked"
HISTORY_URL = f"{TARGET_BASE}/history"
LOGIN_URL = f"{TARGET_BASE}/login"

# Credentials for endpoints protected by login_required (reset/blocked/history).
# Reads from the same .env used by app.py, or falls back to the printed
# default - override with SHIELDNET_ADMIN_USERNAME / SHIELDNET_ADMIN_PASSWORD.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

ADMIN_USERNAME = os.environ.get("SHIELDNET_ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("SHIELDNET_ADMIN_PASSWORD", "shieldnet")

# A single session is reused across all requests so the login cookie persists.
session = requests.Session()

REQUEST_LIMIT = 20  # must match app.py's REQUEST_LIMIT for ground-truth labeling

# Same preset shapes as attack.py, duplicated here to keep this script
# self-contained and independently runnable for grading purposes.
PRESETS = {
    "light": [
        {"requests": 5, "delay": 1.0},
        {"requests": 8, "delay": 0.8},
        {"requests": 6, "delay": 1.2},
    ],
    "suspicious": [
        {"requests": 15, "delay": 0.3},
        {"requests": 14, "delay": 0.35},
    ],
    "heavy": [
        {"requests": 40, "delay": 0.05},
        {"requests": 35, "delay": 0.05},
        {"requests": 45, "delay": 0.04},
    ],
    "mixed": [
        {"requests": 40, "delay": 0.05},
        {"requests": 35, "delay": 0.05},
        {"requests": 15, "delay": 0.3},
        {"requests": 5, "delay": 1.0},
    ],
}


def random_ip():
    return f"192.168.1.{random.randint(2, 250)}"


def run_attacker(ip, num_requests, delay):
    for _ in range(num_requests):
        try:
            requests.get(TRACK_URL, headers={"X-Forwarded-For": ip}, timeout=5)
        except requests.exceptions.RequestException:
            pass
        time.sleep(delay)


def login():
    try:
        resp = session.post(LOGIN_URL, data={"username": ADMIN_USERNAME, "password": ADMIN_PASSWORD}, timeout=5)
        if resp.status_code == 200 and "Invalid username" in resp.text:
            print("❌ Login failed - check SHIELDNET_ADMIN_USERNAME / SHIELDNET_ADMIN_PASSWORD in .env")
            return False
        return True
    except requests.exceptions.RequestException as e:
        print(f"❌ Could not reach server to log in: {e}")
        return False


def reset_server():
    try:
        session.post(RESET_URL, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"⚠️  Could not reset server state: {e}")


def get_blocked_ips():
    try:
        return {item["ip"] for item in session.get(BLOCKED_URL, timeout=5).json()}
    except (requests.exceptions.RequestException, ValueError):
        return set()


def get_history():
    try:
        return session.get(HISTORY_URL, timeout=5).json()
    except (requests.exceptions.RequestException, ValueError):
        return []


def run_preset(preset_name, entries):
    print(f"\n{'=' * 60}")
    print(f" Running preset: {preset_name}")
    print(f"{'=' * 60}")

    reset_server()
    time.sleep(0.5)

    # Assign a fixed IP to each configured attacker for this run
    configs = [{"ip": random_ip(), **entry} for entry in entries]

    threads = []
    for c in configs:
        t = threading.Thread(target=run_attacker, args=(c["ip"], c["requests"], c["delay"]))
        threads.append(t)
        t.start()
        time.sleep(0.2)

    for t in threads:
        t.join()

    time.sleep(0.5)  # let last requests settle

    blocked = get_blocked_ips()
    history = get_history()

    rows = []
    for c in configs:
        ip = c["ip"]
        is_true_attacker = c["requests"] > REQUEST_LIMIT
        was_blocked = ip in blocked or any(h["ip"] == ip for h in history)

        if is_true_attacker and was_blocked:
            outcome = "True Positive"
        elif is_true_attacker and not was_blocked:
            outcome = "False Negative"
        elif not is_true_attacker and was_blocked:
            outcome = "False Positive"
        else:
            outcome = "True Negative"

        detection_entry = next((h for h in history if h["ip"] == ip), None)
        requests_at_detection = detection_entry["requests"] if detection_entry else "-"
        detected_by = detection_entry.get("detected_by", {}) if detection_entry else {}

        rows.append({
            "preset": preset_name,
            "ip": ip,
            "requests_sent": c["requests"],
            "true_attacker": is_true_attacker,
            "blocked": was_blocked,
            "outcome": outcome,
            "requests_at_detection": requests_at_detection,
            "fixed_threshold_flag": detected_by.get("fixed_threshold", "-"),
            "rolling_baseline_flag": detected_by.get("rolling_baseline", "-"),
        })

    return rows


def print_table(all_rows):
    headers = ["Preset", "IP", "Sent", "True Attacker?", "Blocked?", "Outcome", "Detected@", "Fixed", "Z-Score"]
    col_widths = [10, 16, 6, 15, 9, 16, 10, 6, 8]

    def fmt_row(vals):
        return " | ".join(str(v).ljust(w) for v, w in zip(vals, col_widths))

    print("\n" + fmt_row(headers))
    print("-" * (sum(col_widths) + 3 * (len(col_widths) - 1)))

    for r in all_rows:
        print(fmt_row([
            r["preset"], r["ip"], r["requests_sent"], r["true_attacker"],
            r["blocked"], r["outcome"], r["requests_at_detection"],
            r["fixed_threshold_flag"], r["rolling_baseline_flag"]
        ]))


def print_summary(all_rows):
    outcomes = [r["outcome"] for r in all_rows]
    tp = outcomes.count("True Positive")
    tn = outcomes.count("True Negative")
    fp = outcomes.count("False Positive")
    fn = outcomes.count("False Negative")
    total = len(outcomes)

    accuracy = (tp + tn) / total * 100 if total else 0
    precision = tp / (tp + fp) * 100 if (tp + fp) else 0
    recall = tp / (tp + fn) * 100 if (tp + fn) else 0

    print(f"\n{'=' * 60}")
    print(" SUMMARY")
    print(f"{'=' * 60}")
    print(f"Total simulated IPs : {total}")
    print(f"True Positives      : {tp}")
    print(f"True Negatives      : {tn}")
    print(f"False Positives     : {fp}")
    print(f"False Negatives     : {fn}")
    print(f"Accuracy            : {accuracy:.1f}%")
    print(f"Precision           : {precision:.1f}%")
    print(f"Recall              : {recall:.1f}%")


def save_csv(all_rows, filename="logs/evaluation_results.csv"):
    if not all_rows:
        return
    with open(filename, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=all_rows[0].keys())
        writer.writeheader()
        writer.writerows(all_rows)
    print(f"\n📄 Results saved to {filename}")


def parse_args():
    parser = argparse.ArgumentParser(description="Evaluate ShieldNet detection accuracy across attack presets.")
    parser.add_argument(
        "--presets", nargs="+", choices=list(PRESETS.keys()), default=list(PRESETS.keys()),
        help="Which presets to evaluate (default: all)"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if not login():
        return

    all_rows = []

    for preset_name in args.presets:
        rows = run_preset(preset_name, PRESETS[preset_name])
        all_rows.extend(rows)

    print_table(all_rows)
    print_summary(all_rows)
    save_csv(all_rows)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nEvaluation stopped by user.")