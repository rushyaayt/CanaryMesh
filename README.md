<div align="center">

```
   ____                            __  __          _     
  / ___|__ _ _ __   __ _ _ __ _   |  \/  | ___ ___| |__  
 | |   / _` | '_ \ / _` | '__| | | | |\/| |/ _ \ __| '_ \ 
 | |__| (_| | | | | (_| | |  | |_| | |  | |  __\__ \ | | |
  \____\__,_|_| |_|\__,_|_|   \__, |_|  |_|\___|___/_| |_|
                              |___/                        
```

# CanaryMesh — Honeytoken-as-a-Service (HaaS)
### Active Cyber Deception & Ephemeral Supply-Chain Intrusion Detection

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Deception](https://img.shields.io/badge/False%20Positives-0.0%25%20Guaranteed-00f5a0)](#threat-model--zero-false-positives)
[![Tests](https://img.shields.io/badge/Tests-17%20Passing-brightgreen)](#automated-testing)

*Deploy realistic, low-cost honeytokens across cloud infrastructure, developer environments, and CI/CD pipelines to catch credential misuse, lateral movement, and supply-chain attacks with instant high-fidelity alerts and forensic breadcrumbs.*

</div>

---

## 💡 The Problem & The Fresh Paradigm

Traditional honeypots are static, expensive to maintain, and easily avoided by modern adversaries. Attackers rarely stumble into isolated honeypot servers; instead, they **scrape source code, compromise CI/CD runner logs, poison supply-chain dependencies, or hijack developer workstations**.

**CanaryMesh (Honeytoken-as-a-Service)** shifts deception from monolithic static traps into **lightweight, distributed, ephemeral artifacts**:
- **Deception-as-Code**: Generate authentic-looking credentials (AWS IAM, GitHub PATs, OpenAI API keys, Stripe secrets, PostgreSQL URIs) directly into repos, `.env` files, and container images.
- **Ephemeral CI/CD Seeding**: Inject dynamic honeytokens on-the-fly during pipeline runs (GitHub Actions, GitLab CI) with tight TTLs (e.g. 60 minutes). If any rogue dependency, compromised runner, or pull request exfiltrates and tests the secret, you are alerted within milliseconds.
- **Zero False Positives**: Legitimate employees and services never use honeytokens. Any touch is a confirmed breach attempt.
- **Authentic Decoy Trapping**: When an attacker tests the token, the Decoy Gateway emulates real provider error codes (OpenAI quota limits, AWS STS auth errors, Stripe expiration), keeping the adversary probing in a deception sandbox while extracting forensic telemetry.

---

## 🏛️ Architecture & Deception Flow

```
                                      [ DECEPTION MESH ]
                                               │
               ┌───────────────────────────────┴──────────────────────────────┐
               │                                                              │
     [ 1. Seed & Deploy ]                                            [ 2. Adversary Touch ]
  • CI/CD Pipeline Runners                                        • Discovered in Build Log
  • Developer Workstations                                        • Scraped from Leaked Repo
  • AWS/K8s ConfigMaps                                            • Exfiltrated by Malicious Dep
               │                                                              │
               ▼                                                              ▼
     ┌──────────────────┐                                           ┌──────────────────┐
     │ Ephemeral Honey- │                                           │ Adversary Probes │
     │ token Generator  │                                           │  Decoy Gateway   │
     └──────────────────┘                                           └────────┬─────────┘
                                                                             │
               ┌─────────────────────────────────────────────────────────────┘
               ▼
   [ 3. High-Fidelity Forensic Capture ]
     ├── Client IP & True Proxy Resolution (CF / XFF)
     ├── Tool Fingerprinting (cURL, Python, SQLMap, AWS CLI, Postman)
     ├── Geolocation & Autonomous System Number (ASN)
     ├── Full Request Headers, HTTP Method, Body Payload
     └── Threat Severity & Post-TTL Context
               │
               ├─────────────────────────────────────────────┐
               ▼                                             ▼
   [ 4. Authentic Decoy Response ]              [ 5. Instant Alert Dispatch ]
     • OpenAI: 429 Insufficient Quota             • Slack Block Kit Cards
     • Stripe: 401 API Key Expired                • Discord Rich Embeds
     • AWS STS: 403 InvalidClientTokenId          • Generic SIEM / Splunk / Datadog
     • Microservice: 403 Missing IAM Scope        • Real-Time Cyber SOC Dashboard
```

---

## ✨ Core Features

| Feature | Capability |
| :--- | :--- |
| **Realistic Honeytokens** | Generates authentic key formats: `AKIA...` (AWS), `ghp_...` (GitHub), `sk-proj-...` (OpenAI), `sk_live_...` (Stripe), `postgresql://...` (Database), and custom CI JWTs. |
| **Ephemeral CI/CD Seeding** | 1-line integration for GitHub Actions & GitLab CI with auto-expiring TTLs (15 min to 24 hrs). |
| **Decoy Trap Gateway** | Realistic honeypot endpoints that trick adversaries into continuing reconnaissance while capturing forensic telemetry. |
| **Adversary Tool Fingerprinting** | Automatically detects attacker tool signatures (cURL, Python requests, Postman, SQLMap, Nikto, Nuclei, AWS CLI). |
| **Multi-Channel Alert Dispatcher** | Ships incident alerts to Slack (Block Kit), Discord (Cyber Red Embeds), SIEM webhooks, and local audit logs. |
| **Modern SOC Web Dashboard** | Cyberpunk dark-mode user interface with fleet inventory, real-time alert feed, forensic drawer, and 1-click attack simulator. |
| **CLI & Automation Ready** | Bundled `haas` CLI for developers and `seed-ci.sh` shell injector. |
| **Zero External Infrastructure** | Operates on Python 3.10+ and SQLite with WAL mode; zero mandatory cloud dependencies. |

---

## 🚀 Quickstart

### Option 1: Run with Docker Compose (Recommended)

```bash
git clone https://github.com/rushyaayt/canarymesh.git
cd canarymesh
docker compose up -d
```
The CanaryMesh server and SOC Dashboard will be live at **`http://localhost:8000/`**.

---

### Option 2: Run Locally with Python

```bash
# 1. Clone & enter repository
git clone https://github.com/rushyaayt/canarymesh.git
cd canarymesh

# 2. Initialize virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt
pip install -e .

# 4. Launch deception platform
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

---

## 💻 CLI Usage (`haas`)

CanaryMesh includes a standalone command-line tool `haas` for developers, SecOps, and pipeline scripts:

```bash
# Generate a new honeytoken
haas generate --type aws_iam --label "s3-backup-deployer" --ttl 120

# Seed an ephemeral honeytoken into a CI run
haas seed-ci --repo "my-org/payment-service" --workflow "release" --ttl 60 --export

# List active honeytokens in the mesh
haas list

# View breach alerts and forensic breadcrumbs
haas alerts --limit 10

# Simulate an adversary probe to verify detection
haas simulate --tool "curl/8.4.0" --ip "198.51.100.42"
```

---

## ⚡ CI/CD Integration Guide

### 1. GitHub Actions Integration

Add the following step to your `.github/workflows/ci.yml` before running untrusted steps or build tests:

```yaml
name: Production Build & Test
on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Code
        uses: actions/checkout@v4

      - name: Seed CanaryMesh Ephemeral Honeytoken
        run: |
          RESPONSE=$(curl -s -X POST "${{ secrets.CANARYMESH_URL }}/api/v1/seed/ci" \
            -H "Content-Type: application/json" \
            -d '{
              "repository": "${{ github.repository }}",
              "workflow": "${{ github.workflow }}",
              "run_id": "${{ github.run_id }}",
              "commit_sha": "${{ github.sha }}",
              "ttl_minutes": 60,
              "token_type": "ci_ephemeral"
            }')
          
          # Ingest honeytoken as decoy secret
          TOKEN_VAL=$(echo "$RESPONSE" | grep -o '"token_value":"[^"]*' | cut -d'"' -f4)
          echo "CANARY_CI_RELEASE_KEY=$TOKEN_VAL" >> "$GITHUB_ENV"
          echo "Armed ephemeral honeytoken for run ${{ github.run_id }}."

      - name: Run Pipeline Steps
        run: |
          npm test
          # If any dependency or PR attacker attempts to exfiltrate and use $CANARY_CI_RELEASE_KEY,
          # CanaryMesh immediately sounds the breach alarm with zero false positives!
```

---

### 2. Portable Shell Seeder (`scripts/seed-ci.sh`)

For any CI runner (GitLab CI, Jenkins, CircleCI):

```bash
CANARY_SERVER="http://canarymesh.internal:8000" \
CANARY_TTL_MINUTES=45 \
./scripts/seed-ci.sh
```

---

## 🎯 Attack Simulation & Verification

To verify your detection pipeline and witness real-time alerts without waiting for a real adversary:

```bash
# Run the automated verification script
python scripts/simulate_attack.py
```

Or test directly with `curl`:
```bash
# 1. Generate an OpenAI honeytoken
curl -s -X POST http://localhost:8000/api/v1/tokens \
  -H "Content-Type: application/json" \
  -d '{"token_type": "openai_key", "label": "test-openai", "ttl_minutes": 30}'

# 2. Simulate attacker querying OpenAI endpoint with the stolen key
curl -i -X POST http://localhost:8000/v1/chat/completions \
  -H "Authorization: Bearer sk-proj-a1b2c3d4e5f6..." \
  -H "User-Agent: curl/8.4.0" \
  -H "Content-Type: application/json" \
  -d '{"model": "gpt-4", "messages": [{"role": "user", "content": "hello"}]}'
```
**Attacker receives:**
```json
HTTP/1.1 429 Too Many Requests
openai-organization: org-prod-ai-workspace

{
  "error": {
    "message": "You exceeded your current quota, please check your plan and billing details.",
    "type": "insufficient_quota",
    "code": "insufficient_quota"
  }
}
```
**Security Team receives:**
Instant Slack/Discord webhook with the attacker's IP, country, ISP, user-agent, headers, and precise honeytoken label!

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/v1/tokens` | Generate a new honeytoken (AWS, GitHub, OpenAI, Stripe, CI, DB). |
| `GET` | `/api/v1/tokens` | List all honeytokens with status, trigger count, and TTL. |
| `GET` | `/api/v1/tokens/{id}` | Inspect a specific honeytoken. |
| `DELETE`| `/api/v1/tokens/{id}` | Revoke an active honeytoken. |
| `POST` | `/api/v1/seed/ci` | Dynamic 1-line ephemeral token provisioning for CI/CD runs. |
| `GET` | `/api/v1/seed/quick-script.sh` | Downloadable bash injector for CI/CD runners. |
| `GET` | `/api/v1/alerts` | List forensic breach incident logs. |
| `GET` | `/api/v1/alerts/{id}` | Full forensic breakdown (raw headers, payload, GeoIP, client tool). |
| `POST` | `/api/v1/alerts/simulate` | Fire a live breach simulation for testing and verification. |
| `ALL` | `/trap/{token_id}` | Universal decoy trap endpoint. |
| `POST` | `/v1/chat/completions` | Decoy OpenAI API gateway. |
| `ALL` | `/v1/charges` | Decoy Stripe charges gateway. |
| `ALL` | `/api/aws/sts` | Decoy AWS STS gateway. |
| `GET` | `/api/v1/stats` | High-level deception telemetry metrics. |
| `GET` | `/health` | Service health status. |

---

## 🛡️ Threat Model & Zero False Positives

| Attack Vector | How CanaryMesh Detects It |
| :--- | :--- |
| **Supply-Chain Dependency Attack** | A malicious npm/pip package scrapes environment variables during `npm install` or `pytest`. When the threat actor tries the key, CanaryMesh alerts on their infrastructure IP. |
| **Compromised CI/CD Runner / Logs** | An adversary accesses build logs or runner artifacts containing the ephemeral key. The moment they test it, an alert triggers with their client IP. |
| **Accidental Public Repo Leak** | An engineer commits a decoy `.env` file or AWS credentials. Automated GitHub scanner bots or threat actors immediately probe the credential, pinpointing the leak. |
| **Lateral Movement / Insider Recon** | An attacker scanning internal git repositories or Kubernetes secrets discovers a decoy database URI and probes it. |

---

## 🧪 Automated Testing

CanaryMesh includes a test suite covering realistic token generation, cryptographic HMAC hashing, decoy gateways, CI seeder TTLs, and alert dispatching:

```bash
# Run test suite
pytest -v tests/
```
```
======================= 17 passed in 1.19s =======================
```

---

## 📄 License

CanaryMesh is open-source software licensed under the [Apache License, Version 2.0](LICENSE).



