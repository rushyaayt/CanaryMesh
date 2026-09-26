#!/usr/bin/env bash
# ==============================================================================
# CanaryMesh Ephemeral Honeytoken Seeder for CI/CD Environments
# Compatible with GitHub Actions, GitLab CI, Jenkins, CircleCI, Bitbucket
# ==============================================================================
set -euo pipefail

CANARY_SERVER="${CANARY_SERVER:-http://localhost:8000}"
REPOSITORY="${GITHUB_REPOSITORY:-${CI_PROJECT_PATH:-my-org/my-service}}"
WORKFLOW="${GITHUB_WORKFLOW:-${CI_JOB_NAME:-default-build}}"
RUN_ID="${GITHUB_RUN_ID:-${CI_JOB_ID:-manual-$(date +%s)}}"
COMMIT="${GITHUB_SHA:-${CI_COMMIT_SHA:-HEAD}}"
TTL_MINUTES="${CANARY_TTL_MINUTES:-60}"
TOKEN_TYPE="${CANARY_TOKEN_TYPE:-ci_ephemeral}"

echo "[CanaryMesh] Requesting ephemeral honeytoken from Deception Mesh: $CANARY_SERVER"
echo "[CanaryMesh] Context: Repo=$REPOSITORY | Workflow=$WORKFLOW | RunID=$RUN_ID | TTL=${TTL_MINUTES}m"

SEED_PAYLOAD=$(cat <<EOF
{
  "repository": "$REPOSITORY",
  "workflow": "$WORKFLOW",
  "run_id": "$RUN_ID",
  "commit_sha": "$COMMIT",
  "ttl_minutes": $TTL_MINUTES,
  "token_type": "$TOKEN_TYPE"
}
EOF
)

RESPONSE=$(curl -s -f -X POST "$CANARY_SERVER/api/v1/seed/ci" \
  -H "Content-Type: application/json" \
  -d "$SEED_PAYLOAD" || true)

if [ -z "$RESPONSE" ]; then
  echo "[CanaryMesh] Warning: Could not reach CanaryMesh server ($CANARY_SERVER). Skipping canary injection."
  exit 0
fi

TOKEN_VAL=$(echo "$RESPONSE" | grep -o '"token_value":"[^"]*' | cut -d'"' -f4 || true)
ENV_VAR_NAME=$(echo "$RESPONSE" | grep -o '"env_variable_name":"[^"]*' | cut -d'"' -f4 || true)
TRAP_ENDPOINT=$(echo "$RESPONSE" | grep -o '"trap_endpoint":"[^"]*' | cut -d'"' -f4 || true)
EXPIRES_AT=$(echo "$RESPONSE" | grep -o '"expires_at":"[^"]*' | cut -d'"' -f4 || true)

if [ -n "$TOKEN_VAL" ] && [ -n "$ENV_VAR_NAME" ]; then
  # Inject into GitHub Actions environment if present
  if [ -n "${GITHUB_ENV:-}" ]; then
    echo "$ENV_VAR_NAME=$TOKEN_VAL" >> "$GITHUB_ENV"
    echo "CANARY_TRAP_ENDPOINT=$TRAP_ENDPOINT" >> "$GITHUB_ENV"
    echo "[CanaryMesh] Exported to \$GITHUB_ENV: $ENV_VAR_NAME"
  fi

  # Inject into GitLab CI dotenv artifact if requested
  if [ -n "${GITLAB_ENV_FILE:-}" ]; then
    echo "$ENV_VAR_NAME=$TOKEN_VAL" >> "$GITLAB_ENV_FILE"
    echo "CANARY_TRAP_ENDPOINT=$TRAP_ENDPOINT" >> "$GITLAB_ENV_FILE"
  fi

  export "$ENV_VAR_NAME=$TOKEN_VAL"
  export CANARY_TRAP_ENDPOINT="$TRAP_ENDPOINT"

  echo "[CanaryMesh] ✓ Ephemeral honeytoken armed! Auto-expires at: $EXPIRES_AT"
  echo "[CanaryMesh] If any build script or attacker accesses this token, an alarm fires immediately."
else
  echo "[CanaryMesh] Warning: Invalid response from CanaryMesh. No honeytoken seeded."
fi
