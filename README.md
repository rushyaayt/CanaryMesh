# CanaryMesh

CanaryMesh is a self-hosted deception and honeytoken service. It creates
synthetic credentials and decoy endpoints that can be planted in controlled
repositories, test environments, and CI/CD jobs. When a decoy is accessed,
CanaryMesh records the event and can notify a security team.

It is intended for authorized defensive monitoring and security testing. Canary
values are not real credentials and do not grant access to third-party services.
Treat every alert as a high-confidence signal to investigate, not automatic
proof of malicious activity: scanners, tests, and configuration mistakes can
also touch a decoy.

## What it does

- Generates synthetic AWS IAM, GitHub PAT, OpenAI, Stripe, database URL, and
  CI-style honeytokens.
- Provides token-specific traps and decoy endpoints, including `/.env`,
  `/config.json`, `/v1/chat/completions`, `/v1/charges`, and `/api/aws/sts`.
- Records token hits and standalone trap hits in SQLite, with request context
  and optional token expiration.
- Streams live events to authenticated dashboard WebSocket clients.
- Sends alerts to Slack, Discord, or compatible JSON webhooks.
- Accepts authenticated AWS CloudTrail events through a timestamped,
  HMAC-signed webhook.
- Offers admin and read-only API keys, administrative audit records, webhook
  delivery retries, optional Redis fan-out, retention, and SQLite backup checks.

The dashboard is served by the FastAPI application at `/`. API documentation is
available at `/docs` while the server is running.

## Requirements

- Python 3.10 or later for a local installation.
- Docker Engine and the Docker Compose plugin for the container option.
- A random API key of at least 32 characters. Admin-protected operations do
  not work until `CANARY_ADMIN_API_KEY` is configured.
- Redis is optional. It is only needed for WebSocket event fan-out across
  multiple application instances.

## Install and run locally

Clone the repository and create an isolated Python environment.

**Windows PowerShell**

```powershell
git clone https://github.com/rushyaayt/CanaryMesh.git
Set-Location CanaryMesh
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

**Linux or macOS**

```bash
git clone https://github.com/rushyaayt/CanaryMesh.git
cd CanaryMesh
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Set a high-entropy admin key before starting the application. The following
prints a suitable random value; store it in a password manager or secret
manager and do not commit it.

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Set the generated key and run the development server:

**Windows PowerShell**

```powershell
$env:CANARY_ADMIN_API_KEY = "<paste-generated-key>"
$env:CANARY_SECRET_KEY = "<set-a-separate-random-secret>"
$env:CANARY_DATABASE_PATH = "canarymesh.db"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

**Linux or macOS**

```bash
export CANARY_ADMIN_API_KEY="<paste-generated-key>"
export CANARY_SECRET_KEY="<set-a-separate-random-secret>"
export CANARY_DATABASE_PATH="canarymesh.db"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000 --reload
```

`--reload` is for local development. For a deployment, omit it, bind Uvicorn
to the intended interface, set `CANARY_PUBLIC_URL` appropriately, use HTTPS through a trusted
reverse proxy, and store secrets outside the repository. CanaryMesh reads
configuration from environment variables; the local Python process does not
automatically load `.env`.

Open these URLs after the server starts:

- Dashboard: <http://localhost:8000/>
- Health check: <http://localhost:8000/health>
- Interactive API docs: <http://localhost:8000/docs>

In the dashboard, choose **Admin Key** and enter the configured admin key.
Protected routes return `503` if no API key is configured, `401` for a missing
or invalid key, and `403` if a read-only key attempts an admin action.

## Run with Docker Compose

Copy `.env.example` to `.env`, then set at least `CANARY_ADMIN_API_KEY` and
`CANARY_SECRET_KEY` to separate, randomly generated values. Compose loads the
root `.env` file; keep it private and out of version control. The Compose
configuration requires `CANARY_SECRET_KEY` to be provided.

```bash
docker compose up --build -d
docker compose logs -f canarymesh
```

The dashboard is at <http://localhost:8000/>. Shut the service down with:

```bash
docker compose down
```

Compose stores the SQLite database in the persistent `canary_data` volume.
`docker compose down -v` removes that volume and the persisted application
data; only use it when you intentionally want to delete that data.

For a remote deployment, set `CANARY_PUBLIC_URL` to the externally reachable
HTTPS address and configure TLS at a trusted proxy. Do not expose the
development server directly to the public internet.

## First detection walkthrough

Once the server is running and `CANARY_ADMIN_API_KEY` is set, the `haas` CLI
can create and manage tokens. The editable install adds it to the environment.
If your shell cannot find it, use `python -m cli.haas` instead.

```bash
# Supply the same key configured on the server.
export CANARY_ADMIN_API_KEY="<your-admin-key>"

# Create a decoy and note its token ID.
haas generate --type ci_ephemeral --label "local-demo" --ttl 60

# List tokens to see their IDs and status.
haas list

# Simulate a hit against the most recently created active token.
haas simulate --tool "curl/8.4.0" --ip "198.51.100.42"

# Review token-trigger alerts.
haas alerts --limit 10
```

On PowerShell, set the environment key with:

```powershell
$env:CANARY_ADMIN_API_KEY = "<your-admin-key>"
```

You can also test the configuration-file trap without authentication:

```bash
curl -i http://localhost:8000/.env
```

The trap returns deliberately fake values and records a standalone breach. The
returned decoy data is not a usable configuration file or credential.

## API authentication and access roles

Send API credentials in the header `Authorization: Bearer <key>`.

- `CANARY_ADMIN_API_KEY` grants read and management access.
- `CANARY_READONLY_API_KEY` optionally grants read-only access.
- `CANARY_PREVIOUS_ADMIN_API_KEY` optionally allows an old admin key during a
  short, staged rotation window. It retains full admin privileges until removed.

All configured API keys must be at least 32 characters and must be different.
Administrative actions such as token creation/revocation, CI seeding, alert
simulation, and notification retries are recorded in `/api/v1/audit`. The audit
record contains a hashed key identifier, action, target, and client IP; it
does not store the API key.

| Capability | Required role |
| --- | --- |
| List and inspect tokens, alerts, breaches, events, stats, notifications, and audit records | Read-only or admin |
| Create/revoke tokens, seed CI, simulate an alert, retry a notification | Admin |
| Connect to the live WebSocket feed | Read-only or admin |

For staged admin-key rotation, configure the new key as
`CANARY_ADMIN_API_KEY` and the old key as `CANARY_PREVIOUS_ADMIN_API_KEY`.
Restart, move clients to the new key, then remove the previous key and restart
again. Keep the overlap short.

## API reference

All API routes are under `/api/v1` unless noted.

| Method | Endpoint | Purpose |
| --- | --- | --- |
| `POST` | `/tokens` | Create a honeytoken. Admin only. |
| `GET` | `/tokens`, `/tokens/{id}` | List or inspect tokens. Read-only or admin. |
| `DELETE` | `/tokens/{id}` | Revoke a token. Admin only. |
| `GET` | `/stats` | Read summary metrics. Read-only or admin. |
| `POST` | `/seed/ci` | Create a time-limited CI token. Admin only. |
| `GET` | `/seed/quick-script.sh` | Download the CI helper script. |
| `GET` | `/alerts`, `/alerts/{id}` | Read token-trigger alerts. Read-only or admin. |
| `POST` | `/alerts/simulate` | Simulate a token hit. Admin only. |
| `GET` | `/breaches` | Read standalone trap and cloud webhook events. Read-only or admin. |
| `GET` | `/events`, `/events/export` | Search or export unified event history. Read-only or admin. |
| `GET` | `/notifications` | Inspect webhook delivery state. Read-only or admin. |
| `POST` | `/notifications/{id}/retry` | Retry a failed delivery. Admin only. |
| `GET` | `/audit` | Read administrative audit entries. Read-only or admin. |
| `POST` | `/webhooks/aws` | Ingest a signed AWS EventBridge event. |
| `WS` | `/ws/alerts` | Stream live events to authenticated clients. |

Public trap routes include `/.env`, `/config.json`, `/trap/{token_id}`,
`/v1/chat/completions`, `/v1/charges`, and `/api/aws/sts`.

Example authenticated token creation:

```bash
curl -X POST http://localhost:8000/api/v1/tokens \
  -H "Authorization: Bearer $CANARY_ADMIN_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"token_type":"ci_ephemeral","label":"demo-token","ttl_minutes":60}'
```

## CI/CD seeding

The CI seeding endpoint requires an admin key. Store the key in the CI
platform's protected secret store; do not print it or place it in source code.
Example GitHub Actions step:

```yaml
- name: Seed a CanaryMesh token
  env:
    CANARYMESH_URL: ${{ secrets.CANARYMESH_URL }}
    CANARY_ADMIN_API_KEY: ${{ secrets.CANARY_ADMIN_API_KEY }}
  run: |
    response=$(curl --fail-with-body -sS -X POST "$CANARYMESH_URL/api/v1/seed/ci" \
      -H "Authorization: Bearer $CANARY_ADMIN_API_KEY" \
      -H "Content-Type: application/json" \
      -d "{\"repository\":\"${GITHUB_REPOSITORY}\",\"workflow\":\"${GITHUB_WORKFLOW}\",\"run_id\":\"${GITHUB_RUN_ID}\",\"commit_sha\":\"${GITHUB_SHA}\",\"ttl_minutes\":60,\"token_type\":\"ci_ephemeral\"}")
    token=$(printf '%s' "$response" | python -c "import json,sys; print(json.load(sys.stdin)['token_value'])")
    echo "CANARY_CI_RELEASE_KEY=$token" >> "$GITHUB_ENV"
```

Only pass the synthetic value to steps where you intend to monitor for misuse.
Avoid printing the response or token in job logs. The endpoint's response
contains the raw synthetic value once; protect it as you would any secret.

## Alert delivery and AWS CloudTrail

Set `CANARY_DEFAULT_WEBHOOK_URL` to send standalone breach alerts to Slack,
Discord, or a compatible JSON endpoint. Per-token webhook URLs can override the
default. Outbound webhooks must use HTTPS on port 443. CanaryMesh resolves the
hostname again when sending, blocks non-public and cloud metadata addresses,
and does not follow redirects. `CANARY_WEBHOOK_ALLOWED_HOSTS` is a
comma-separated list of exact hostnames for intentionally trusted private
destinations. Allowlisting bypasses the public-address restriction for that
hostname; only allow hosts you control.

To receive AWS CloudTrail events, configure:

- `CANARY_AWS_WEBHOOK_SECRET`: random signing secret of at least 32 characters.
- `CANARY_AWS_ACCOUNT_ID`: the expected AWS account ID.
- `CANARY_AWS_PRINCIPAL_ARN`: the exact ARN of the dedicated honeytoken user.

The receiver expects a trusted forwarder, such as a least-privilege Lambda
invoked by EventBridge, to send the raw EventBridge request body and:

- `x-canary-timestamp`: Unix timestamp in seconds, within five minutes of
  server time.
- `x-canary-signature`: `sha256=<hex HMAC-SHA256>`, calculated as
  `HMAC-SHA256(secret, timestamp + "." + raw_request_body)`.

The receiver checks the signature, replay window, payload size and rate,
account, principal, event source, event time, and event ID. Store the signing
secret in a secret manager, rotate it carefully, and never use an AWS IAM user
with permissions for a canary. Create a dedicated principal with no attached
permissions; revoke its key when retiring the canary.

## Configuration

Configuration is read from environment variables. `.env.example` lists the
available settings; Docker Compose loads `.env`, but a local Python process
requires you to export the variables in its environment.

| Variable | Default | Description |
| --- | --- | --- |
| `CANARY_PUBLIC_URL` | `http://localhost:8000` | Public base URL used in generated trap URLs. |
| `CANARY_SECRET_KEY` | Development placeholder | Application cryptographic secret; set a unique random value. |
| `CANARY_DATABASE_PATH` | `canarymesh.db` | SQLite database file location. |
| `CANARY_ADMIN_API_KEY` | Unset | Required admin credential. |
| `CANARY_PREVIOUS_ADMIN_API_KEY` | Unset | Temporary prior admin key during rotation. |
| `CANARY_READONLY_API_KEY` | Unset | Optional read-only credential. |
| `CANARY_DEFAULT_WEBHOOK_URL` | Unset | Optional default outbound alert destination. |
| `CANARY_WEBHOOK_ALLOWED_HOSTS` | Empty | Exact hostnames permitted to resolve to private addresses. |
| `CANARY_AWS_WEBHOOK_SECRET` | Unset | AWS webhook signing secret. |
| `CANARY_AWS_ACCOUNT_ID` | Unset | Expected AWS account ID. |
| `CANARY_AWS_PRINCIPAL_ARN` | Unset | Expected AWS honeytoken principal ARN. |
| `CANARY_WEBHOOK_RATE_LIMIT` | `60` | Requests allowed per client per time window on AWS webhook. |
| `CANARY_WEBHOOK_RATE_WINDOW_SECONDS` | `60` | AWS webhook rate-limit window. |
| `CANARY_WEBHOOK_MAX_BODY_BYTES` | `65536` | Maximum AWS webhook request size. |
| `CANARY_REDIS_URL` | Unset | Optional Redis URL for multi-instance live-feed fan-out. |
| `CANARY_RETENTION_DAYS` | `0` | Set to a positive value to purge older event/audit records daily. |
| `CANARY_GEOIP_ENABLED` | `true` | Enable optional IP geolocation enrichment. |
| `CANARY_TRUST_PROXY_HEADERS` | `false` | Trust forwarded client-IP headers only behind a trusted proxy. |
| `CANARY_DECOY_DELAY_MS` | `80` | Delay before a decoy route responds. |

The `CANARY_ADMIN_API_KEY` and `CANARY_SECRET_KEY` values must be independently
generated. Do not use the sample placeholders in production. To use the CLI
server instead of the Uvicorn command above, run
`haas server --host 127.0.0.1 --port 8000` and adjust those command-line
arguments for your deployment.

## Database backup and retention

CanaryMesh uses SQLite in WAL mode. Set `CANARY_RETENTION_DAYS` to a positive
number to remove older breach, alert, notification, and audit records at startup
and then daily. A value of `0` disables automatic retention.

Use SQLite's backup API rather than copying only the live database file while
the service is running:

```python
from app.database import Database

db = Database()
print(db.integrity_check())
print(db.backup_to("canarymesh-backup.db"))
```

Keep backups access-controlled and test restoration on a separate copy.
`backup_to` verifies the backup with SQLite's integrity check. Restore only
while the application is stopped, then verify the restored database before
restarting.

## Multi-instance deployments

SQLite is suitable for local and modest single-service deployments. Configure
`CANARY_REDIS_URL` to broadcast live WebSocket events across application
instances. Redis is optional; without it, live events reach only clients
connected to the same process. Redis Pub/Sub is a live-feed transport and does
not replace the persisted SQLite event history.

## Development and tests

Install the project with its development dependencies using
`python -m pip install -e ".[dev]"`, then run:

```bash
python -m pytest -q
python -m compileall -q app cli tests
```

The tests exercise token handling, traps, authorization, signed webhooks,
outbound destination validation, notification leases, retention, and database
backup behavior.
