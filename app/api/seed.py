"""CanaryMesh Ephemeral CI/CD Seeding API"""

from datetime import datetime, timedelta, timezone
from fastapi import APIRouter, Response, status
from app.config import get_settings
from app.core.generators import compute_token_hash, generate_honeytoken
from app.database import get_db
from app.models import CISeedRequest, CISeedResponse, TokenType

router = APIRouter(prefix="/api/v1/seed", tags=["CI/CD Seeding"])


@router.post(
    "/ci",
    response_model=CISeedResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Seed ephemeral honeytoken into a CI/CD pipeline",
)
def seed_ci_honeytoken(req: CISeedRequest):
    settings = get_settings()
    db = get_db()

    label = f"ci-{req.repository.replace('/', '-')}-{req.workflow}"
    token_id, raw_token, secret_comp, display_token, _ = generate_honeytoken(req.token_type, label)
    token_hash = compute_token_hash(raw_token)

    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=req.ttl_minutes)

    trap_endpoint = f"{settings.public_url}/trap/{token_id}"

    # Determine standard environment variable name based on type
    if req.token_type == TokenType.AWS_IAM:
        env_var = "AWS_ACCESS_KEY_ID"
    elif req.token_type == TokenType.GITHUB_PAT:
        env_var = "GH_PACKAGE_DEPLOY_TOKEN"
    elif req.token_type == TokenType.OPENAI_KEY:
        env_var = "OPENAI_API_KEY"
    elif req.token_type == TokenType.STRIPE_SECRET:
        env_var = "STRIPE_SECRET_KEY"
    elif req.token_type == TokenType.DATABASE_URL:
        env_var = "DATABASE_URL"
    else:
        env_var = "CANARY_CI_RELEASE_KEY"

    # Shell export snippet for GitHub Actions / GitLab CI / Jenkins
    ci_snippet = (
        f'echo "{env_var}={raw_token}" >> "$GITHUB_ENV"\n'
        f'echo "CANARY_TRAP_ENDPOINT={trap_endpoint}" >> "$GITHUB_ENV"'
    )

    metadata = {
        "ci_seeding": True,
        "repository": req.repository,
        "workflow": req.workflow,
        "run_id": req.run_id,
        "commit_sha": req.commit_sha,
        "ttl_minutes": req.ttl_minutes,
        "env_variable": env_var,
        "trap_url": trap_endpoint,
    }

    db.save_token(
        token_id=token_id,
        token_value_hash=token_hash,
        display_token=display_token,
        token_type=req.token_type.value,
        label=label,
        environment=f"ci:{req.repository}",
        creator="ci-seeder",
        expires_at=expires_at,
        webhook_url=req.webhook_url,
        metadata=metadata,
    )

    return CISeedResponse(
        token_id=token_id,
        token_type=req.token_type.value,
        env_variable_name=env_var,
        token_value=raw_token,
        secret_component=secret_comp,
        trap_endpoint=trap_endpoint,
        expires_at=expires_at.isoformat(),
        ci_export_snippet=ci_snippet,
    )


@router.get(
    "/quick-script.sh",
    summary="Downloadable Bash one-liner for CI runners",
)
def get_quick_script():
    """Returns a bash helper script that CI runs can execute to dynamically register a canary key."""
    settings = get_settings()
    script = f"""#!/usr/bin/env bash
# CanaryMesh CI Seeder Auto-Injector
set -euo pipefail

CANARY_SERVER="${{CANARY_SERVER:-{settings.public_url}}}"
REPO_NAME="${{GITHUB_REPOSITORY:-local/dev}}"
WORKFLOW_NAME="${{GITHUB_WORKFLOW:-ci-test}}"
RUN_ID="${{GITHUB_RUN_ID:-001}}"
COMMIT="${{GITHUB_SHA:-HEAD}}"

echo "[CanaryMesh] Requesting ephemeral honeytoken for $REPO_NAME ($WORKFLOW_NAME)..."

RESPONSE=$(curl -s -X POST "$CANARY_SERVER/api/v1/seed/ci" \\
  -H "Content-Type: application/json" \\
  -d '{{"repository": "'"$REPO_NAME"'", "workflow": "'"$WORKFLOW_NAME"'", "run_id": "'"$RUN_ID"'", "commit_sha": "'"$COMMIT"'", "ttl_minutes": 60}}')

TOKEN_VAL=$(echo "$RESPONSE" | grep -o '"token_value":"[^"]*' | cut -d'"' -f4)
ENV_NAME=$(echo "$RESPONSE" | grep -o '"env_variable_name":"[^"]*' | cut -d'"' -f4)
TRAP_URL=$(echo "$RESPONSE" | grep -o '"trap_endpoint":"[^"]*' | cut -d'"' -f4)

if [ -n "$TOKEN_VAL" ]; then
  if [ -n "${{GITHUB_ENV:-}}" ]; then
    echo "$ENV_NAME=$TOKEN_VAL" >> "$GITHUB_ENV"
    echo "CANARY_TRAP_ENDPOINT=$TRAP_URL" >> "$GITHUB_ENV"
  fi
  echo "export $ENV_NAME=$TOKEN_VAL"
  echo "[CanaryMesh] Successfully seeded ephemeral honeytoken into CI environment."
else
  echo "[CanaryMesh] Warning: Could not register canary key; continuing build safely."
fi
"""
    return Response(content=script, media_type="text/x-shellscript")
