"""CanaryMesh Pydantic Data Models & Schemas"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TokenType(str, Enum):
    AWS_IAM = "aws_iam"
    GITHUB_PAT = "github_pat"
    OPENAI_KEY = "openai_key"
    STRIPE_SECRET = "stripe_secret"
    CI_EPHEMERAL = "ci_ephemeral"
    DATABASE_URL = "database_url"
    BEARER_TOKEN = "bearer_token"


class TokenCreateRequest(BaseModel):
    token_type: TokenType = Field(default=TokenType.CI_EPHEMERAL, description="Type of honeytoken format")
    label: str = Field(..., description="Human-readable descriptor, e.g. 'ci-deployer-github-actions'")
    environment: str = Field(default="ci-cd", description="Deployment context, e.g. 'github-actions', 'prod-db'")
    ttl_minutes: Optional[int] = Field(default=120, description="Auto-expiry in minutes (None for infinite)")
    webhook_url: Optional[str] = Field(default=None, description="Custom webhook URL override for this honeytoken")
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Custom metadata tags")


class TokenGeneratedResponse(BaseModel):
    id: str
    token_type: str
    label: str
    environment: str
    raw_token: str = Field(..., description="The actual honeytoken secret. Will NOT be shown again!")
    display_token: str = Field(..., description="Safe masked preview")
    secret_component: Optional[str] = Field(default=None, description="Associated secret (e.g. AWS Secret Access Key)")
    trap_url: str = Field(..., description="The decoy endpoint URL this token trips against")
    created_at: str
    expires_at: Optional[str] = None
    instructions: str = Field(..., description="How to plant and use this honeytoken")


class TokenItem(BaseModel):
    id: str
    display_token: str
    token_type: str
    label: str
    environment: str
    creator: str
    created_at: str
    expires_at: Optional[str] = None
    is_active: bool
    trigger_count: int
    last_triggered_at: Optional[str] = None
    webhook_url: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CISeedRequest(BaseModel):
    repository: str = Field(..., description="Repository name, e.g. 'org/backend-api'")
    workflow: str = Field(..., description="Workflow name, e.g. 'build-and-test'")
    run_id: Optional[str] = Field(default=None, description="CI execution run ID")
    commit_sha: Optional[str] = Field(default=None, description="Commit hash of the run")
    ttl_minutes: int = Field(default=60, ge=5, le=1440, description="Ephemeral lifetime of the honeytoken")
    webhook_url: Optional[str] = Field(default=None, description="Optional incident webhook")
    token_type: TokenType = Field(default=TokenType.CI_EPHEMERAL, description="Honeytoken type to plant")


class CISeedResponse(BaseModel):
    token_id: str
    token_type: str
    env_variable_name: str
    token_value: str
    secret_component: Optional[str] = None
    trap_endpoint: str
    expires_at: str
    ci_export_snippet: str


class AlertRecord(BaseModel):
    id: str
    token_id: str
    token_label: str
    token_type: str
    timestamp: str
    client_ip: str
    user_agent: str
    http_method: str
    request_path: str
    headers: Dict[str, str]
    payload: Optional[str] = None
    query_params: Dict[str, Any] = Field(default_factory=dict)
    geo_location: Dict[str, Any] = Field(default_factory=dict)
    decoy_response_code: int
    decoy_response_body: Optional[str] = None
    severity: str = "CRITICAL"
    notified: bool = False


class SimulationRequest(BaseModel):
    token_id: Optional[str] = Field(default=None, description="ID of active honeytoken to simulate")
    token_value: Optional[str] = Field(default=None, description="Or raw honeytoken string")
    simulated_tool: Optional[str] = Field(default="curl/8.4.0 (x86_64-pc-linux-gnu)", description="Simulated User-Agent")
    simulated_ip: Optional[str] = Field(default="198.51.100.42", description="Simulated adversary IP")
    payload: Optional[str] = Field(default="{\"query\":\"query { users { email, secret_key } }\"}")


class StatsResponse(BaseModel):
    active_tokens: int
    revoked_tokens: int
    tripped_tokens: int
    total_alerts: int
    token_type_distribution: Dict[str, int]
