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
[![Deception](https://img.shields.io/badge/Deception-High--confidence%20signals-00f5a0)](#threat-model)
[![Tests](https://img.shields.io/badge/Tests-17%20Passing-brightgreen)](#automated-testing)

*Deploy realistic, low-cost honeytokens across cloud infrastructure, developer environments, and CI/CD pipelines to catch credential misuse, lateral movement, and supply-chain attacks with instant high-fidelity alerts and forensic breadcrumbs.*

</div>

---

## 💡 The Problem & The Fresh Paradigm

Traditional honeypots are static, expensive to maintain, and easily avoided by modern adversaries. Attackers rarely stumble into isolated honeypot servers; instead, they **scrape source code, compromise CI/CD runner logs, poison supply-chain dependencies, or hijack developer workstations**.

**CanaryMesh (Honeytoken-as-a-Service)** shifts deception from monolithic static traps into **lightweight, distributed, ephemeral artifacts**:
- **Deception-as-Code**: Generate authentic-looking credentials (AWS IAM, GitHub PATs, OpenAI API keys, Stripe secrets, PostgreSQL URIs) directly into repos, `.env` files, and container images.
- **Ephemeral CI/CD Seeding**: Inject dynamic honeytokens on-the-fly during pipeline runs (GitHub Actions, GitLab CI) with tight TTLs (e.g. 60 minutes). If any rogue dependency, compromised runner, or pull request exfiltrates and tests the secret, you are alerted within milliseconds.
- **High-Confidence Signals**: Honeytoken use is suspicious, but scanners, tests, deployment mistakes, and misconfiguration still need investigation.
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
Before starting it, add a randomly generated `CANARY_ADMIN_API_KEY` (at least
32 characters) to your local `.env` file. The dashboard's **Admin Key** button
uses this value; do not commit `.env`.

---

### Option 2: Run Locally with Python

```bash
# 1. Clone & enter repository
git clone https://github.com/rushyaayt/canarymesh.git
cd canarymesh

# 2. Initialize virtual environment
python -m venv .venv
# Windows (PowerShell)
.\.venv\Scripts\Activate.ps1

# Linux / macOS
source .venv/bin/activate

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
        env:
          CANARY_ADMIN_API_KEY: ${{ secrets.CANARY_ADMIN_API_KEY }}
        run: |
          RESPONSE=$(curl -s -X POST "${{ secrets.CANARYMESH_URL }}/api/v1/seed/ci" \
            -H "Content-Type: application/json" \
            -H "Authorization: Bearer $CANARY_ADMIN_API_KEY" \
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
          # CanaryMesh alerts when the honeytoken is used; investigate the context of every signal.
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
  -H "Authorization: Bearer $CANARY_ADMIN_API_KEY" \
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
| `POST` | `/api/v1/tokens` | Generate a new honeytoken (admin key required). |
| `GET` | `/api/v1/tokens` | List honeytokens (read-only or admin key required). |
| `GET` | `/api/v1/tokens/{id}` | Inspect a honeytoken (read-only or admin key required). |
| `DELETE`| `/api/v1/tokens/{id}` | Revoke an active honeytoken (admin key required). |
| `POST` | `/api/v1/seed/ci` | Provision an ephemeral CI/CD token (admin key required). |
| `GET` | `/api/v1/seed/quick-script.sh` | Downloadable bash injector for CI/CD runners. |
| `GET` | `/api/v1/alerts` | List forensic alerts (read-only or admin key required). |
| `GET` | `/api/v1/alerts/{id}` | Full forensic breakdown (read-only or admin key required). |
| `GET` | `/api/v1/breaches` | List persisted decoy and cloud webhook events (read-only or admin key required). |
| `GET` | `/api/v1/events` | Search incident history (read-only or admin key required). |
| `GET` | `/api/v1/events/export` | Export filtered incident events as CSV (read-only or admin key required). |
| `GET` | `/api/v1/notifications` | Inspect webhook delivery attempts (read-only or admin key required). |
| `POST` | `/api/v1/notifications/{id}/retry` | Retry a failed webhook delivery (admin key required). |
| `POST` | `/api/v1/alerts/simulate` | Fire a live breach simulation for testing (admin key required). |
| `POST` | `/api/v1/webhooks/aws` | Authenticated AWS CloudTrail/EventBridge webhook receiver. |
| `WS` | `/api/v1/ws/alerts` | Stream token-trigger and standalone breach events to connected dashboards. |
| `ALL` | `/trap/{token_id}` | Universal decoy trap endpoint. |
| `GET` | `/.env`, `/config.json` | Fake configuration-file traps; access is persisted as a breach event. |
| `POST` | `/v1/chat/completions` | Decoy OpenAI API gateway. |
| `ALL` | `/v1/charges` | Decoy Stripe charges gateway. |
| `ALL` | `/api/aws/sts` | Decoy AWS STS gateway. |
| `GET` | `/api/v1/stats` | High-level deception telemetry metrics. |
| `GET` | `/health` | Service health status. |

Set a high-entropy `CANARY_ADMIN_API_KEY` (at least 32 characters) for
management operations: token creation/revocation, CI seeding, alert simulation,
and notification retries. Optionally set a separate high-entropy
`CANARY_READONLY_API_KEY` for read-only access. Send HTTP credentials as
`Authorization: Bearer <key>`. Administrative changes are written to the audit
log with a hashed key identifier, action, target, and client IP. For browser
WebSockets, offer subprotocols `canarymesh` and `canarymesh-auth.<key>`; use
TLS and configure proxies not to log WebSocket subprotocol values. Protected
endpoints return `503` until at least one API key is configured.

To rotate the admin key without interrupting clients, configure the new
`CANARY_ADMIN_API_KEY` and temporarily set `CANARY_PREVIOUS_ADMIN_API_KEY` to
the old value, restart, roll clients to the new key, then remove the previous
key and restart again. The previous key has full admin privileges during the
overlap; store both values in a secret manager and keep the overlap short.

Standalone trap and AWS webhook events are stored in SQLite and broadcast to
authorized WebSocket clients. `/api/v1/events` provides a unified view of
token-trigger alerts and standalone trap/cloud events. Webhook deliveries are
persisted, retried up to three times, recovered after a process restart, and
can be inspected or manually retried. Database leases coordinate concurrent
workers and retries use bounded backoff. Delivery is at-least-once; use the event
ID in notifications to deduplicate in downstream systems. The global webhook URL remains in runtime
configuration rather than notification records; existing per-token webhook
destinations remain part of the token registry. On startup, a one-time database
migration redacts common credential fields from existing captured headers,
query parameters, and JSON request bodies. New non-JSON request bodies are
stored only as redacted length metadata.

All configured outbound webhook URLs must use HTTPS on port 443 and resolve
only to public IP addresses. `CANARY_WEBHOOK_ALLOWED_HOSTS` is an explicit
comma-separated exact-host allowlist for deployments that intentionally deliver
to private destinations; allowlisting a host trusts every address it resolves
to. DNS is revalidated at delivery time and redirects are disabled.

For multiple app instances, set `CANARY_REDIS_URL` to enable Redis Pub/Sub for
cross-instance WebSocket fan-out. If Redis is unavailable at startup, the app
logs the condition and uses a process-local feed. Set `CANARY_RETENTION_DAYS`
to a positive number to purge older event/audit records on startup and daily.
Set `CANARY_WEBHOOK_RATE_LIMIT`, `CANARY_WEBHOOK_RATE_WINDOW_SECONDS`, and
`CANARY_WEBHOOK_MAX_BODY_BYTES` to tune inbound AWS webhook limits.

Run database integrity and backup checks from an administrative shell:

```python
from app.database import Database

db = Database()
print(db.integrity_check())
print(db.backup_to("canarymesh-backup.db"))
```

Keep backups outside the application database directory, restrict access to
them, and test restoration on a separate copy before relying on a backup.
Restore only while the service is stopped, then run `integrity_check()` before
restarting.

To accept AWS EventBridge events, set `CANARY_AWS_WEBHOOK_SECRET`,
`CANARY_AWS_ACCOUNT_ID`, and the exact `CANARY_AWS_PRINCIPAL_ARN`. Configure
an EventBridge rule to invoke a small Lambda forwarder. The forwarder must send
the raw EventBridge JSON body with `x-canary-timestamp` (Unix seconds) and
`x-canary-signature: sha256=<hex HMAC-SHA256>` headers. Sign the exact bytes as
`HMAC-SHA256(secret, timestamp + "." + raw_body)`; retrieve the signing secret
from AWS Secrets Manager. The receiver enforces a five-minute signature window,
replay protection, rate/body-size limits, account and principal checks, a
24-hour CloudTrail event age limit, and event-ID deduplication. Rotate the
signing secret by updating both Secrets Manager and CanaryMesh. Leave any
required AWS setting unset to keep the receiver disabled.
`CANARY_DEFAULT_WEBHOOK_URL` receives standalone breach alerts through Slack,
Discord, or a generic webhook.
The decoy configuration response uses an `.invalid` host and an explicitly
non-credential password to avoid resembling usable secrets.

For the AWS canary, create a dedicated IAM user with no attached permissions
and create an access key for that user. Plant that AWS-issued access key as the
canary secret; a synthetic key that does not correspond to an AWS principal
cannot produce a CloudTrail event identifying the configured ARN. Do not grant
the user permissions. Enable CloudTrail management events, then create an
EventBridge rule matching the target account, `AWS API Call via CloudTrail`
detail type, and `detail.userIdentity.arn` for that dedicated user. Configure
the rule's Lambda target with least-privilege permission to read the signing
secret and invoke this service. Rotate or revoke the canary access key as part
of retirement.

The application uses SQLite WAL mode. Back up the configured database file
with a SQLite-consistent backup (for example, SQLite's backup API); do not copy
only the live database file while ignoring its WAL journal.
Proxy-supplied client IP headers are ignored by default. Set
`CANARY_TRUST_PROXY_HEADERS=true` only when the service is behind a trusted
proxy configured to remove caller-supplied forwarding headers and set its own.

---

## 🛡️ Threat Model

| Attack Vector | How CanaryMesh Detects It |
| :--- | :--- |
| **Supply-Chain Dependency Attack** | A malicious npm/pip package scrapes environment variables during `npm install` or `pytest`. If the token is used, CanaryMesh records an alert with available request context. |
| **Compromised CI/CD Runner / Logs** | An adversary accesses build logs or runner artifacts containing the ephemeral key. If they test it, an alert records the client IP and other available context. |
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
