#!/usr/bin/env python3
"""
CanaryMesh CLI (`haas`) — Command-line interface for Honeytoken-as-a-Service
"""

import argparse
import json
import os
import sys
import httpx


def get_base_url() -> str:
    return os.getenv("CANARY_URL", "http://localhost:8000").rstrip("/")


def get_admin_headers() -> dict[str, str]:
    api_key = os.getenv("CANARY_ADMIN_API_KEY")
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def get_read_headers() -> dict[str, str]:
    api_key = os.getenv("CANARY_ADMIN_API_KEY") or os.getenv("CANARY_READONLY_API_KEY")
    return {"Authorization": f"Bearer {api_key}"} if api_key else {}


def cmd_generate(args):
    """Generates a new honeytoken."""
    url = f"{get_base_url()}/api/v1/tokens"
    payload = {
        "token_type": args.type,
        "label": args.label,
        "environment": args.env,
        "ttl_minutes": args.ttl if args.ttl > 0 else None,
        "webhook_url": args.webhook,
    }

    try:
        resp = httpx.post(url, json=payload, headers=get_admin_headers(), timeout=5.0)
        if resp.status_code == 201:
            data = resp.json()
            print("\n[+] HONEYTOKEN GENERATED & ARMED")
            print("-" * 55)
            print(f"ID:              {data['id']}")
            print(f"Type:            {data['token_type']}")
            print(f"Label:           {data['label']}")
            print(f"Raw Token:       {data['raw_token']}")
            if data.get("secret_component"):
                print(f"Secret Access:   {data['secret_component']}")
            print(f"Trap Endpoint:   {data['trap_url']}")
            print(f"Expires At:      {data['expires_at'] or 'Never'}")
            print("-" * 55)
            print(f"Instructions:\n{data['instructions']}\n")
        else:
            print(f"[!] Error ({resp.status_code}): {resp.text}")
    except Exception as exc:
        print(f"[!] Could not connect to CanaryMesh server at {url}: {exc}")


def cmd_seed_ci(args):
    """Seeds an ephemeral honeytoken into a CI/CD pipeline."""
    url = f"{get_base_url()}/api/v1/seed/ci"
    payload = {
        "repository": args.repo,
        "workflow": args.workflow,
        "run_id": args.run_id,
        "commit_sha": args.commit,
        "ttl_minutes": args.ttl,
        "token_type": args.type,
    }

    try:
        resp = httpx.post(url, json=payload, headers=get_admin_headers(), timeout=5.0)
        if resp.status_code == 201:
            data = resp.json()
            print("\n[+] [CanaryMesh] Seeded ephemeral honeytoken into CI run.")
            print(f"Token ID:  {data['token_id']}")
            print(f"Env Var:   {data['env_variable_name']}={data['token_value']}")
            print(f"Trap URL:  {data['trap_endpoint']}")
            print(f"Expires:   {data['expires_at']}\n")

            if args.export:
                print(data["ci_export_snippet"])
        else:
            print(f"[!] Error ({resp.status_code}): {resp.text}")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")


def cmd_list(args):
    """Lists deployed honeytokens."""
    url = f"{get_base_url()}/api/v1/tokens"
    try:
        resp = httpx.get(url, headers=get_read_headers(), timeout=5.0)
        if resp.status_code == 200:
            tokens = resp.json()
            print(f"\n{'ID':<18} {'TYPE':<14} {'LABEL':<24} {'TRIPS':<6} {'STATUS':<10} {'EXPIRES'}")
            print("-" * 85)
            for t in tokens:
                status = "TRIPPED" if t["trigger_count"] > 0 else ("ARMED" if t["is_active"] else "REVOKED")
                expires = t["expires_at"][:19].replace("T", " ") if t["expires_at"] else "Never"
                print(f"{t['id']:<18} {t['token_type']:<14} {t['label'][:22]:<24} {t['trigger_count']:<6} {status:<10} {expires}")
            print()
        else:
            print(f"[!] Error: {resp.text}")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")


def cmd_alerts(args):
    """Shows recorded intrusion alerts."""
    url = f"{get_base_url()}/api/v1/alerts?limit={args.limit}"
    try:
        resp = httpx.get(url, headers=get_read_headers(), timeout=5.0)
        if resp.status_code == 200:
            alerts = resp.json()
            if not alerts:
                print("\n[+] No intrusion alerts recorded. Zero breaches detected.\n")
                return
            print(f"\n{'SEVERITY':<10} {'TOKEN LABEL':<22} {'ADVERSARY IP':<18} {'METHOD/ROUTE':<24} {'TIMESTAMP'}")
            print("-" * 90)
            for a in alerts:
                route = f"{a['http_method']} {a['request_path']}"
                time_str = a["timestamp"][:19].replace("T", " ")
                print(f"{a['severity']:<10} {a['token_label'][:20]:<22} {a['client_ip']:<18} {route[:22]:<24} {time_str}")
            print()
        else:
            print(f"[!] Error: {resp.text}")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")


def cmd_simulate(args):
    """Simulates an adversary tripping a honeytoken."""
    url = f"{get_base_url()}/api/v1/alerts/simulate"
    payload = {
        "token_id": args.token_id,
        "simulated_tool": args.tool,
        "simulated_ip": args.ip,
    }

    try:
        resp = httpx.post(url, json=payload, headers=get_admin_headers(), timeout=5.0)
        if resp.status_code == 200:
            data = resp.json()
            print("\n[!] [SIMULATION SUCCESSFUL] Alert triggered and dispatched!")
            print(json.dumps(data, indent=2))
            print()
        else:
            print(f"[!] Error: {resp.text}")
    except Exception as exc:
        print(f"[!] Connection failed: {exc}")


def cmd_server(args):
    """Starts the CanaryMesh Deception Platform server."""
    import uvicorn
    print(f"[*] Launching CanaryMesh Server on {args.host}:{args.port}...")
    uvicorn.run("app.main:app", host=args.host, port=args.port, reload=args.reload)


def main():
    parser = argparse.ArgumentParser(
        prog="haas",
        description="CanaryMesh - Honeytoken-as-a-Service CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate
    p_gen = subparsers.add_parser("generate", help="Generate a new honeytoken")
    p_gen.add_argument("--type", choices=["ci_ephemeral", "aws_iam", "github_pat", "openai_key", "stripe_secret", "database_url"], default="ci_ephemeral")
    p_gen.add_argument("--label", default="cli-planted-honeytoken")
    p_gen.add_argument("--env", default="dev-laptop")
    p_gen.add_argument("--ttl", type=int, default=120, help="TTL in minutes (0 for infinite)")
    p_gen.add_argument("--webhook", default=None, help="Custom alert webhook URL")
    p_gen.set_defaults(func=cmd_generate)

    # Seed CI
    p_ci = subparsers.add_parser("seed-ci", help="Seed ephemeral honeytoken for a CI run")
    p_ci.add_argument("--repo", required=True, help="Repository name (e.g. acme/backend)")
    p_ci.add_argument("--workflow", default="ci-test")
    p_ci.add_argument("--run-id", default=None)
    p_ci.add_argument("--commit", default=None)
    p_ci.add_argument("--ttl", type=int, default=60, help="TTL in minutes")
    p_ci.add_argument("--type", default="ci_ephemeral")
    p_ci.add_argument("--export", action="store_true", help="Print shell export statements")
    p_ci.set_defaults(func=cmd_seed_ci)

    # List
    p_list = subparsers.add_parser("list", help="List active honeytokens")
    p_list.set_defaults(func=cmd_list)

    # Alerts
    p_alerts = subparsers.add_parser("alerts", help="View breach alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.set_defaults(func=cmd_alerts)

    # Simulate
    p_sim = subparsers.add_parser("simulate", help="Simulate an adversary accessing a honeytoken")
    p_sim.add_argument("--token-id", default=None, help="Token ID to trip (or default to latest)")
    p_sim.add_argument("--tool", default="curl/8.4.0", help="Simulated adversary User-Agent")
    p_sim.add_argument("--ip", default="198.51.100.42", help="Simulated adversary IP")
    p_sim.set_defaults(func=cmd_simulate)

    # Server
    p_srv = subparsers.add_parser("server", help="Run the CanaryMesh deception server")
    p_srv.add_argument("--host", default="0.0.0.0")
    p_srv.add_argument("--port", type=int, default=8000)
    p_srv.add_argument("--reload", action="store_true")
    p_srv.set_defaults(func=cmd_server)

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        sys.exit(1)

    args.func(args)


if __name__ == "__main__":
    main()
