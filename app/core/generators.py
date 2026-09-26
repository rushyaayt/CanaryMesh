"""CanaryMesh Realistic Honeytoken Generators and Cryptographic Utilities"""

import base64
import hashlib
import hmac
import os
import secrets
import string
import uuid
from typing import Optional, Tuple
from app.config import get_settings
from app.models import TokenType


def _generate_random_chars(length: int, alphabet: str) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def compute_token_hash(token_value: str) -> str:
    """Computes a keyed HMAC-SHA256 hash of the token value for safe database indexing."""
    settings = get_settings()
    return hmac.new(
        settings.secret_key.encode("utf-8"),
        token_value.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def generate_honeytoken(
    token_type: TokenType,
    custom_label: Optional[str] = None,
) -> Tuple[str, str, Optional[str], str, str]:
    """
    Generates a realistic honeytoken based on the chosen deception type.
    Returns:
        (token_id, raw_token, secret_component, display_token, instructions)
    """
    settings = get_settings()
    token_id = f"canary_{uuid.uuid4().hex[:12]}"
    b62 = string.ascii_letters + string.digits
    b36_upper = string.ascii_uppercase + string.digits

    secret_component: Optional[str] = None
    instructions: str = ""

    if token_type == TokenType.AWS_IAM:
        # AWS Access Key ID starts with AKIA, 20 characters total
        # e.g., AKIAIOSFODNN7EXAMPLE
        raw_token = f"AKIA{_generate_random_chars(16, b36_upper)}"
        # AWS Secret Access Key: 40 base64 chars
        secret_component = secrets.token_urlsafe(30)[:40]
        display_token = f"{raw_token[:6]}••••••••{raw_token[-4:]}"
        instructions = (
            "Deploy as AWS credentials in ~/.aws/credentials, CI/CD pipeline secrets (AWS_ACCESS_KEY_ID), "
            "or embedded in Terraform code. When an attacker queries AWS STS or CanaryMesh's decoy gateway, an alert triggers."
        )

    elif token_type == TokenType.GITHUB_PAT:
        # GitHub Personal Access Token: starts with ghp_, 40 chars total
        random_suffix = _generate_random_chars(36, b62)
        raw_token = f"ghp_{random_suffix}"
        display_token = f"ghp_••••••••••••{raw_token[-6:]}"
        instructions = (
            "Place in .env files, git commit history, CI runner configs (GITHUB_TOKEN), or docker image build args. "
            "Detects repo scanner bots, public repo leaks, and malicious supply-chain dependencies."
        )

    elif token_type == TokenType.OPENAI_KEY:
        # OpenAI API Key format: sk-proj- + 48 characters
        random_suffix = _generate_random_chars(48, b62)
        raw_token = f"sk-proj-{random_suffix}"
        display_token = f"sk-proj-••••••••••••{raw_token[-6:]}"
        instructions = (
            "Seed in developer workstations, shell history (~/.bash_history), or AI agent configuration files. "
            "Catches adversaries attempting to weaponize or drain LLM budgets."
        )

    elif token_type == TokenType.STRIPE_SECRET:
        # Stripe Live Secret Key: starts with sk_live_
        random_suffix = _generate_random_chars(24, b62)
        raw_token = f"sk_live_{random_suffix}"
        display_token = f"sk_live_••••••••••••{raw_token[-4:]}"
        instructions = (
            "Seed in checkout service microservices, e-commerce staging repos, or payment processor mocks. "
            "High-priority financial intrusion signal."
        )

    elif token_type == TokenType.DATABASE_URL:
        # Realistic Database connection string with embedded honeytoken password
        db_user = "svc_app_analytics"
        db_password = f"cnry_db_{_generate_random_chars(20, b62)}"
        raw_token = db_password
        secret_component = f"postgresql://{db_user}:{db_password}@db-replica-01.corp.internal:5432/primary_store?sslmode=require"
        display_token = f"postgresql://{db_user}:••••••••@db-replica-01.corp.internal..."
        instructions = (
            "Place inside DATABASE_URL environment variables, Kubernetes ConfigMaps, or database connection pools. "
            "If an attacker probes internal services or connects to the gateway, instant alert is fired."
        )

    elif token_type == TokenType.BEARER_TOKEN:
        # Realistic Bearer JWT format
        header = base64.urlsafe_b64encode(b'{"alg":"HS256","typ":"JWT"}').decode().rstrip("=")
        payload = base64.urlsafe_b64encode(
            f'{{"sub":"service-account-ci","role":"cluster-admin","aud":"internal-api","canary_id":"{token_id}"}}'.encode()
        ).decode().rstrip("=")
        signature = secrets.token_urlsafe(16)[:20]
        raw_token = f"ey{header[2:]}.{payload}.{signature}"
        display_token = f"eyJ••••••••.{payload[-8:]}.••••"
        instructions = (
            "Use in Authorization: Bearer headers, microservice mesh configuration, or mock OAuth secrets."
        )

    else:
        # Default: CI Ephemeral Deception Key
        # Format: canary_ci_<token_id>_<random>
        random_entropy = _generate_random_chars(24, b62)
        raw_token = f"canary_ci_{token_id}_{random_entropy}"
        display_token = f"canary_ci_{token_id[:8]}••••{raw_token[-4:]}"
        instructions = (
            "Injected dynamically during CI pipeline runs (e.g. GitHub Actions, GitLab CI). "
            "Expires automatically after the workflow completes. Any usage indicates compromised build logs, "
            "runner exfiltration, or malicious PR pull actions."
        )

    return token_id, raw_token, secret_component, display_token, instructions
