# 🛡️ ShieldNet

ShieldNet is a lightweight Flask-based project for detecting and mitigating DDoS-like traffic. It tracks requests from different IP addresses and uses two detection methods: a fixed request threshold and a rolling-baseline z-score. When an IP is detected as abusive, it can be blocked and the event is recorded in the dashboard.

The project also includes a traffic simulator and an evaluation script to test how well the detection methods perform.

## Features

* **IP-based request tracking** through the `/track` endpoint using `X-Forwarded-For`
* **Two detection methods**

  * **Fixed threshold:** flags an IP after it crosses the configured request limit (default: 20)
  * **Rolling baseline (z-score):** checks whether traffic is significantly higher than the recent baseline
* **Automatic IP blocking** when traffic is detected as abusive
* **Detection history** showing the detector that triggered and the request count
* **Admin dashboard** protected by login credentials stored in environment variables
* **Traffic simulator** with `light`, `suspicious`, `heavy`, and `mixed` presets
* **Evaluation script** that calculates TP, TN, FP, FN, accuracy, precision, and recall
* **CSV log export** using `export_logs.py`
* **Docker support**
* **Demo site** for testing traffic through ShieldNet

## Project Structure

```text
ShieldNet/
├── app.py               # Flask server, detection, blocking, dashboard and API
├── attack.py            # Traffic simulator
├── run_evaluation.py    # Runs traffic presets and calculates metrics
├── export_logs.py       # Exports detection logs
├── demo_site/           # Demo site for testing
├── templates/           # Dashboard and login templates
├── Dockerfile
├── requirements.txt
└── .gitignore
```

## Getting Started

### Prerequisites

* Python 3.10+
* pip

### Installation

```bash
git clone https://github.com/adwithanimma/ShieldNet.git
cd ShieldNet
python -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### Configuration

Create a `.env` file in the project root:

```env
SHIELDNET_ADMIN_USERNAME=admin
SHIELDNET_ADMIN_PASSWORD=change-me
```

If these variables are not set, the evaluation script uses `admin` / `shieldnet` as the default credentials.

For anything beyond local testing, set your own username and password.

## Run the Server

```bash
python app.py
```

The server runs at:

```text
http://127.0.0.1:5000
```

For production-style serving with Gunicorn:

```bash
gunicorn app:app
```

## Run with Docker

Build the Docker image:

```bash
docker build -t shieldnet .
```

Run the container:

```bash
docker run -p 5000:5000 --env-file .env shieldnet
```

## Usage

### API Endpoints

| Endpoint   | Description                                                                       |
| ---------- | --------------------------------------------------------------------------------- |
| `/track`   | Records a request from an IP and runs the detection logic                         |
| `/login`   | Admin login                                                                       |
| `/blocked` | Shows currently blocked IPs (authentication required)                             |
| `/history` | Shows detection history and the detector that triggered (authentication required) |
| `/reset`   | Resets the current server state (authentication required)                         |

### Simulate Traffic

The simulator should only be used against a server that you own or have permission to test.

Run the interactive menu:

```bash
python attack.py
```

Run one of the built-in presets:

```bash
python attack.py --preset mixed
```

Available presets are:

```text
light
suspicious
heavy
mixed
```

You can also generate custom traffic:

```bash
python attack.py --ips 3 --requests 40 --delay 0.05
```

To test a hosted deployment:

```bash
python attack.py --target https://your-app.example.com/track --preset heavy --timeout 60
```

| Preset       | Behavior                                                                  |
| ------------ | ------------------------------------------------------------------------- |
| `light`      | A few IPs sending a small amount of mostly normal traffic                 |
| `suspicious` | Traffic stays close to the configured threshold without being blocked     |
| `heavy`      | Multiple IPs send enough traffic to trigger detection and blocking        |
| `mixed`      | Combines heavy traffic, suspicious traffic, and normal background traffic |

After starting the simulator, open the dashboard to view the detection events.

## Evaluate Detection Accuracy

Run all available presets:

```bash
python run_evaluation.py
```

Run selected presets:

```bash
python run_evaluation.py --presets heavy mixed
```

The evaluation script logs in, resets the server state, runs the selected traffic presets, and generates a per-IP result table.

An IP that sends more requests than the configured limit of 20 is treated as a true attacker for the evaluation.

The results include:

* True Positives (TP)
* True Negatives (TN)
* False Positives (FP)
* False Negatives (FN)
* Accuracy
* Precision
* Recall

The results are saved to:

```text
logs/evaluation_results.csv
```

## How It Works

1. A request reaches the `/track` endpoint.
2. ShieldNet identifies the client IP from the request.
3. The request count for that IP is updated.
4. The two detection methods check the traffic:

   * **Fixed threshold** checks whether the request count has crossed the configured limit.
   * **Rolling baseline** calculates a z-score using recent traffic and checks for unusual activity.
5. If an IP is flagged, ShieldNet blocks it and records the detection event.
6. The dashboard displays blocked IPs and detection history.

## Tech Stack

* Python
* Flask
* Gunicorn
* Requests
* psutil
* python-dotenv
* Docker

## Roadmap

* [ ] Add persistent storage for logs and the blocklist
* [ ] Make detection thresholds configurable through environment variables
* [ ] Add unblock and allowlist controls to the dashboard
* [ ] Add automated tests and CI

## Disclaimer

ShieldNet is an educational project for demonstrating DDoS detection and mitigation concepts. It is not intended to replace production DDoS protection.

Use the traffic simulator only on systems you own or have explicit permission to test.

