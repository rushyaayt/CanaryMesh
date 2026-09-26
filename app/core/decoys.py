"""CanaryMesh Authentic Decoy Response Generator"""

import json
import uuid
from typing import Dict, Tuple


def get_decoy_response(token_type: str, request_path: str) -> Tuple[int, str, Dict[str, str]]:
    """
    Returns an authentic-looking decoy HTTP response (status_code, body, headers).
    Decoys are engineered to keep adversaries probing rather than realizing they hit a honeypot.
    """
    req_id = f"req_{uuid.uuid4().hex[:16]}"

    if token_type == "openai_key" or "openai" in request_path or "chat/completions" in request_path:
        body = json.dumps({
            "error": {
                "message": "You exceeded your current quota, please check your plan and billing details. Visit https://platform.openai.com/account/billing for details.",
                "type": "insufficient_quota",
                "param": None,
                "code": "insufficient_quota",
            }
        }, indent=2)
        return 429, body, {
            "Content-Type": "application/json",
            "openai-organization": "org-prod-ai-workspace",
            "openai-processing-ms": "142",
            "x-request-id": req_id,
        }

    if token_type == "stripe_secret" or "stripe" in request_path or "charges" in request_path:
        body = json.dumps({
            "error": {
                "code": "api_key_expired",
                "doc_url": "https://stripe.com/docs/error-codes/api-key-expired",
                "message": "The provided API key has expired. Please obtain an active secret key from your Stripe dashboard.",
                "type": "invalid_request_error",
            }
        }, indent=2)
        return 401, body, {
            "Content-Type": "application/json",
            "Stripe-Version": "2024-06-20",
            "Request-Id": req_id,
        }

    if token_type == "aws_iam" or "aws" in request_path or "sts" in request_path:
        body = f"""<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
    <Type>Sender</Type>
    <Code>InvalidClientTokenId</Code>
    <Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>{uuid.uuid4()}</RequestId>
</ErrorResponse>"""
        return 403, body, {
            "Content-Type": "text/xml;charset=UTF-8",
            "x-amzn-RequestId": str(uuid.uuid4()),
        }

    if token_type == "database_url":
        body = json.dumps({
            "status": "error",
            "code": "AUTH_FAILED_OR_REVOKED",
            "message": "PostgreSQL peer authentication failed for user 'svc_app_analytics': password authentication failed.",
            "node": "db-replica-01.us-east-1.aws.internal",
        }, indent=2)
        return 401, body, {"Content-Type": "application/json"}

    # Default: Realistic Internal Microservice / CI API Decoy
    body = json.dumps({
        "status": "error",
        "error_code": "FORBIDDEN_INSUFFICIENT_PERMISSIONS",
        "message": "Principal authenticated, but missing permission 'ci:deployments:write' on namespace 'production-services'.",
        "request_id": req_id,
        "tenant": "enterprise-platform-core",
    }, indent=2)

    return 403, body, {
        "Content-Type": "application/json",
        "X-Canary-Mesh": "verified",
        "X-Request-Id": req_id,
    }
