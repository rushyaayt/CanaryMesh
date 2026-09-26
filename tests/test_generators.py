"""Tests for CanaryMesh Realistic Token Generators & Cryptographic Hashes"""

import pytest
from app.core.generators import compute_token_hash, generate_honeytoken
from app.models import TokenType


def test_generate_aws_iam_token():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.AWS_IAM, "test-aws")
    assert raw.startswith("AKIA")
    assert len(raw) == 20
    assert secret is not None and len(secret) == 40
    assert "AKIA" in display
    assert "••••" in display
    assert "AWS" in instructions


def test_generate_github_pat_token():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.GITHUB_PAT, "test-gh")
    assert raw.startswith("ghp_")
    assert len(raw) == 40
    assert "ghp_" in display
    assert secret is None


def test_generate_openai_key():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.OPENAI_KEY, "test-openai")
    assert raw.startswith("sk-proj-")
    assert len(raw) == 56
    assert "sk-proj-" in display


def test_generate_stripe_key():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.STRIPE_SECRET, "test-stripe")
    assert raw.startswith("sk_live_")
    assert len(raw) == 32
    assert "sk_live_" in display


def test_generate_ci_ephemeral_token():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.CI_EPHEMERAL, "test-ci")
    assert raw.startswith("canary_ci_")
    assert tok_id in raw
    assert "canary_ci_" in display


def test_generate_database_url():
    tok_id, raw, secret, display, instructions = generate_honeytoken(TokenType.DATABASE_URL, "test-db")
    assert raw.startswith("cnry_db_")
    assert secret is not None
    assert "postgresql://" in secret
    assert "5432" in secret


def test_compute_token_hash():
    token = "ghp_1234567890abcdef1234567890abcdef1234"
    h1 = compute_token_hash(token)
    h2 = compute_token_hash(token)
    assert len(h1) == 64  # SHA256 hex
    assert h1 == h2  # Deterministic HMAC

    # Whitespace stripping
    h3 = compute_token_hash(f"  {token}  ")
    assert h1 == h3

    # Distinct tokens yield distinct hashes
    h4 = compute_token_hash("ghp_differenttokenvalue1234567890abcdef12")
    assert h1 != h4
