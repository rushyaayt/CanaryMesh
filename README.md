# CanaryMesh

**A self-hosted honeytoken and deception service for detecting exposed credentials and observing suspicious use.**

CanaryMesh issues synthetic credentials and routes attempts to use them to decoy endpoints. When a token is tripped, the service records an alert with request and client context, updates token telemetry, and can send a notification to a configured webhook. The project is intended for controlled security testing and defensive monitoring.

> **Security notice:** The current `main` branch is an early-stage, self-hosted application. Its token-management, alert, statistics, and CI-seeding APIs do not require authentication. Do not expose it to the public internet or an untrusted network. Run it locally or behind strict network access controls while evaluating it. Do not use real credentials as honeytokens.

## What it does

- Generates synthetic honeytokens in formats intended to resemble AWS IAM keys, GitHub personal access tokens, OpenAI keys, Stripe secrets, database URLs, bearer tokens, and CI credentials. These are decoys, not working provider credentials.
- Provides decoy endpoints for token-specific traps and common API paths, including OpenAI-style chat completions, Stripe-style charges and balance, and an AWS STS-style endpoint.
- Supports short-lived tokens for CI workflows and records their repository, workflow, and run metadata.
- Stores tokens and breach alerts in a local SQLite database.
- Captures request details such as source IP, user agent, method, path, headers, and payload, and derives basic threat context.
- Displays the service dashboard and exposes an API for token and alert management.
- Can deliver alerts to a configured default or per-token webhook.

## Requirements

- Python 3.10 or later
- Git
- Docker Engine with the Docker Compose plugin (optional, for container-based local testing)

## Install and run locally

### 1. Get the source

```bash
git clone https://github.com/rushyaayt/CanaryMesh.git
cd CanaryMesh
```

### 2. Create a virtual environment and install dependencies

**macOS / Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

**Windows PowerShell**

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 3. Configure and start the service

Set a unique secret key for the local instance and bind to loopback for local use. The application otherwise defaults to listening on all interfaces and includes a development fallback key; do not use that fallback beyond an isolated local test.

**macOS / Linux**

```bash
export CANARY_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_urlsafe(48))')"
export CANARY_HOST=127.0.0.1
python -m uvicorn app.main:app --host "$CANARY_HOST" --port 8000
```

**Windows PowerShell**

```powershell
$env:CANARY_SECRET_KEY = python -c "import secrets; print(secrets.token_urlsafe(48))"
$env:CANARY_HOST = "127.0.0.1"
python -m uvicorn app.main:app --host $env:CANARY_HOST --port 8000
```

The service is available at `http://127.0.0.1:8000`. The SQLite database is created at `canarymesh.db` in the application working directory by default.

## Verify the installation

Open the dashboard at [http://127.0.0.1:8000/](http://127.0.0.1:8000/). Check the health endpoint and interactive API reference:

- Health: `GET http://127.0.0.1:8000/health`
- OpenAPI UI: `http://127.0.0.1:8000/docs`
- OpenAPI schema: `http://127.0.0.1:8000/openapi.json`

Generate a short-lived CI-style token:

```bash
curl -sS -X POST http://127.0.0.1:8000/api/v1/seed/ci \
  -H "Content-Type: application/json" \
  -d '{"repository":"example/demo","workflow":"local-smoke-test","ttl_minutes":60}'
```

The response includes a `token_id`, a `trap_endpoint`, and the synthetic `token_value`. The raw value is returned at creation time; handle it as sensitive test data. To generate an alert, send a request to the returned trap endpoint, replacing `<trap_endpoint>` with its value:

```bash
curl -i -X POST "<trap_endpoint>" \
  -H "Authorization: Bearer <token_value>" \
  -H "Content-Type: application/json" \
  -d '{"probe":"CanaryMesh local verification"}'
```

Review the recorded alerts at `http://127.0.0.1:8000/api/v1/alerts`. You can also run the included local simulation script after starting the service:

```bash
python scripts/simulate_attack.py
```

## API overview

All paths below are relative to the service origin. See `/docs` for request and response schemas.

| Method | Path | Purpose |
| --- | --- | --- |
| `POST` | `/api/v1/tokens` | Create a honeytoken |
| `GET` | `/api/v1/tokens` | List tokens |
| `GET` | `/api/v1/tokens/{token_id}` | Retrieve token details |
| `DELETE` | `/api/v1/tokens/{token_id}` | Revoke a token |
| `GET` | `/api/v1/stats` | Retrieve summary counts |
| `POST` | `/api/v1/seed/ci` | Create a time-limited CI honeytoken |
| `GET` | `/api/v1/alerts` | List breach alerts |
| `GET` | `/api/v1/alerts/{alert_id}` | Retrieve alert details |
| `POST` | `/api/v1/alerts/simulate` | Create a test alert for an existing token |
| `GET` | `/trap/{token_id}` | Exercise a token-specific decoy endpoint |

## Configuration

Configure the service through environment variables before starting it.

| Variable | Purpose | Default |
| --- | --- | --- |
| `CANARY_HOST` | Uvicorn listen address | `0.0.0.0` |
| `CANARY_PORT` | Service port | `8000` |
| `CANARY_PUBLIC_URL` | Public base URL used when generating trap links | `http://localhost:8000` |
| `CANARY_SECRET_KEY` | Secret used for honeytoken signatures | Development fallback; set a unique value |
| `CANARY_DATABASE_PATH` | SQLite database file path | `canarymesh.db` |
| `CANARY_DEFAULT_WEBHOOK_URL` | Default alert destination | Unset |
| `CANARY_GEOIP_ENABLED` | Enable IP geolocation lookups | `true` |
| `CANARY_TRUST_PROXY_HEADERS` | Use forwarded headers when determining client IP | `true` |
| `CANARY_DECOY_DELAY_MS` | Simulated decoy response delay | `80` |
| `CANARY_DEBUG` | Enable debug mode | `false` |

Only enable forwarded-header trust when requests arrive through a trusted proxy configured to overwrite those headers. Treat webhook destinations and captured alert data as sensitive, and restrict outbound network access appropriately.

## Run with Docker Compose

The repository includes a Compose configuration for local evaluation:

```bash
docker compose up --build
```

This configuration publishes port `8000` and contains a placeholder secret. Use it only for isolated local testing; do not expose the service or rely on the placeholder secret in a shared or production environment. Use `docker compose down` to stop the service. Review the Compose file and set deployment-specific secrets, network restrictions, and persistent storage before adapting it for any non-local environment.

## Data and operational notes

- SQLite data persists in the configured database file. Back it up using an application-consistent procedure and protect the file as incident data.
- Alert records may contain request headers and payloads. Restrict access and retention according to your organization's policies.
- Token creation responses include the raw synthetic value once. Store it only where it can be safely monitored, and revoke it when no longer needed.
- IP geolocation depends on the configured lookup behavior and may not be available for every address. Treat location and source-IP data as investigative context, not definitive attribution.
- This branch does not provide authenticated administration, signed cloud-provider webhooks, or a shared multi-instance event feed. Review the implementation and deployment risks before using it beyond a local, controlled evaluation.

## License

See the repository's license files for the applicable terms.