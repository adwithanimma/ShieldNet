"""
ShieldNet Attack Simulator
---------------------------
Simulates DDoS-style traffic against your local ShieldNet server for testing.

Usage (interactive):
    python attack.py

Usage (non-interactive, with arguments):
    python attack.py --preset heavy
    python attack.py --ips 5 --requests 30 --delay 0.05
    python attack.py --target http://127.0.0.1:5000/track
"""

import requests
import time
import random
import threading
import argparse
import sys

DEFAULT_TARGET = "http://127.0.0.1:5000/track"

PRESETS = {
    "light": {
        "description": "A few IPs sending light, mostly-normal traffic",
        "attackers": [
            {"requests": 5, "delay": 1.0},
            {"requests": 8, "delay": 0.8},
            {"requests": 6, "delay": 1.2},
        ],
    },
    "suspicious": {
        "description": "Traffic that hovers near the threshold but stays unblocked",
        "attackers": [
            {"requests": 15, "delay": 0.3},
            {"requests": 14, "delay": 0.35},
        ],
    },
    "heavy": {
        "description": "Multiple IPs flooding hard enough to trigger blocks",
        "attackers": [
            {"requests": 40, "delay": 0.05},
            {"requests": 35, "delay": 0.05},
            {"requests": 45, "delay": 0.04},
        ],
    },
    "mixed": {
        "description": "A realistic mix: flooders, suspicious, and background traffic",
        "attackers": [
            {"requests": 40, "delay": 0.05},
            {"requests": 35, "delay": 0.05},
            {"requests": 15, "delay": 0.3},
            {"requests": 5, "delay": 1.0},
        ],
    },
}


def random_ip():
    return f"192.168.1.{random.randint(2, 250)}"


def run_attacker(target, ip, num_requests, delay, verbose=True):
    for i in range(num_requests):
        try:
            response = requests.get(target, headers={"X-Forwarded-For": ip}, timeout=5)
            if verbose:
                print(f"[{ip}] Request {i + 1}/{num_requests}: {response.text.strip()}")
        except requests.exceptions.RequestException as e:
            print(f"[{ip}] Request failed: {e}")
        time.sleep(delay)


def build_attackers_from_preset(preset_name):
    preset = PRESETS[preset_name]
    attackers = []
    for entry in preset["attackers"]:
        attackers.append({
            "ip": random_ip(),
            "requests": entry["requests"],
            "delay": entry["delay"],
        })
    return attackers


def build_attackers_custom(num_ips, num_requests, delay):
    return [
        {"ip": random_ip(), "requests": num_requests, "delay": delay}
        for _ in range(num_ips)
    ]


def prompt_interactive():
    print("=" * 60)
    print(" ShieldNet Attack Simulator")
    print("=" * 60)
    print("\nChoose a traffic pattern:\n")

    preset_names = list(PRESETS.keys())
    for idx, name in enumerate(preset_names, start=1):
        print(f"  {idx}. {name.capitalize():12} - {PRESETS[name]['description']}")
    print(f"  {len(preset_names) + 1}. custom       - Set your own number of IPs / requests / delay")

    choice = input(f"\nEnter a number (1-{len(preset_names) + 1}) [default: {len(preset_names) + 1}]: ").strip()

    if choice == "" or choice == str(len(preset_names) + 1):
        num_ips = input("How many attacker IPs? [default: 3]: ").strip()
        num_ips = int(num_ips) if num_ips else 3

        num_requests = input("Requests per IP? [default: 25]: ").strip()
        num_requests = int(num_requests) if num_requests else 25

        delay = input("Delay between requests in seconds? [default: 0.1]: ").strip()
        delay = float(delay) if delay else 0.1

        return build_attackers_custom(num_ips, num_requests, delay)

    try:
        selected = preset_names[int(choice) - 1]
        print(f"\nRunning preset: {selected}\n")
        return build_attackers_from_preset(selected)
    except (ValueError, IndexError):
        print("Invalid choice, defaulting to 'mixed' preset.\n")
        return build_attackers_from_preset("mixed")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Simulate DDoS-style traffic against a local ShieldNet server."
    )
    parser.add_argument(
        "--target", default=DEFAULT_TARGET,
        help=f"Server endpoint to hit (default: {DEFAULT_TARGET})"
    )
    parser.add_argument(
        "--preset", choices=list(PRESETS.keys()),
        help="Use a built-in traffic pattern instead of interactive prompts"
    )
    parser.add_argument("--ips", type=int, help="Number of attacker IPs (custom mode)")
    parser.add_argument("--requests", type=int, help="Requests per IP (custom mode)")
    parser.add_argument("--delay", type=float, help="Delay between requests in seconds (custom mode)")
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress per-request output, only print a summary"
    )
    return parser.parse_args()


def main():
    args = parse_args()

    if args.preset:
        attackers = build_attackers_from_preset(args.preset)
    elif args.ips and args.requests is not None and args.delay is not None:
        attackers = build_attackers_custom(args.ips, args.requests, args.delay)
    elif len(sys.argv) > 1:
        print("For custom mode, provide --ips, --requests, and --delay together.")
        print("Or use --preset light|suspicious|heavy|mixed")
        print("Falling back to interactive mode...\n")
        attackers = prompt_interactive()
    else:
        attackers = prompt_interactive()

    print(f"\nTarget: {args.target}")
    print(f"Simulating {len(attackers)} attacker IP(s):\n")
    for a in attackers:
        print(f"  - {a['ip']:16} {a['requests']:>3} requests, {a['delay']}s delay")
    print()

    threads = []
    for config in attackers:
        t = threading.Thread(
            target=run_attacker,
            args=(args.target, config["ip"], config["requests"], config["delay"], not args.quiet)
        )
        threads.append(t)
        t.start()
        time.sleep(0.2)

    for t in threads:
        t.join()

    print("\n✅ Simulation complete. Check the dashboard for results.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nSimulation stopped by user.")