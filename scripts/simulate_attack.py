#!/usr/bin/env python3
"""
CanaryMesh Attack Simulator
Demonstrates an adversary finding a leaked honeytoken and probing it against the decoy gateway.
"""

import json
import os
import sys
import time
import httpx

SERVER_URL = os.getenv("CANARY_URL", "http://localhost:8000").rstrip("/")

print("=" * 65)
print("[*] CanaryMesh Attack Simulation & Verification Script")
print("=" * 65)

# 1. Check server health
print(f"[*] Connecting to CanaryMesh server at {SERVER_URL}...")
try:
    health = httpx.get(f"{SERVER_URL}/health", timeout=3.0)
    if health.status_code != 200:
        print(f"[!] Server returned unhealthy status: {health.status_code}")
        sys.exit(1)
    print("[+] CanaryMesh Deception Platform is ONLINE.\n")
except Exception as e:
    print(f"[!] Cannot connect to server at {SERVER_URL}. Is it running?\n    Error: {e}")
    sys.exit(1)

# 2. Seed an ephemeral CI Honeytoken
print("[1] Seeding ephemeral CI honeytoken into simulated pipeline...")
seed_resp = httpx.post(
    f"{SERVER_URL}/api/v1/seed/ci",
    json={
        "repository": "acme-corp/core-auth-service",
        "workflow": "deploy-production-k8s",
        "run_id": "gh-run-994182",
        "commit_sha": "d41d8cd98f00b204e9800998ecf8427e",
        "ttl_minutes": 45,
        "token_type": "ci_ephemeral",
    },
    timeout=5.0,
)

if seed_resp.status_code != 201:
    print(f"[!] Failed to seed token: {seed_resp.text}")
    sys.exit(1)

seed_data = seed_resp.json()
token_id = seed_data["token_id"]
token_val = seed_data["token_value"]
trap_url = seed_data["trap_endpoint"]
print(f"    [+] Token ID:    {token_id}")
print(f"    [+] Env Variable: {seed_data['env_variable_name']}")
print(f"    [+] Raw Secret:  {token_val}")
print(f"    [+] Trap Route:  {trap_url}")
print(f"    [+] TTL Expiry:  {seed_data['expires_at']}\n")

# 3. Simulate an adversary finding and probing the honeytoken
print("[2] Adversary discovered the honeytoken in stolen build logs!")
print("    Simulating attacker querying the trap gateway with cURL / Postman...")

time.sleep(1.0)

adversary_headers = {
    "User-Agent": "curl/8.4.0 (x86_64-pc-linux-gnu) libcurl/8.4.0",
    "Authorization": f"Bearer {token_val}",
    "X-Forwarded-For": "198.51.100.77",
    "Accept": "application/json",
}

probe_payload = {"command": "dump_environment", "intent": "lateral_movement"}

trap_resp = httpx.post(
    trap_url,
    headers=adversary_headers,
    json=probe_payload,
    timeout=5.0,
)

print(f"    [<-] Adversary received HTTP status: {trap_resp.status_code}")
print(f"    [<-] Decoy response body returned to attacker:\n{trap_resp.text}\n")

# 4. Inspect Forensic Alert Log
print("[3] Inspecting CanaryMesh forensic intrusion feed...")
time.sleep(0.5)

alerts_resp = httpx.get(f"{SERVER_URL}/api/v1/alerts?token_id={token_id}", timeout=5.0)
if alerts_resp.status_code == 200:
    alerts = alerts_resp.json()
    if alerts:
        alert = alerts[0]
        print("[+] INTRUSION DETECTED & FORENSICS LOGGED WITH ZERO FALSE POSITIVES!")
        print("-" * 65)
        print(f"Alert ID:          {alert['id']}")
        print(f"Severity:          {alert['severity']}")
        print(f"Adversary IP:      {alert['client_ip']}")
        print(f"Location:          {alert['geo_location'].get('city', 'Local')}, {alert['geo_location'].get('country', 'Net')}")
        print(f"Client / Tool:     {alert['headers'].get('User-Agent')}")
        print(f"Decoy Status:      {alert['decoy_response_code']}")
        print(f"Timestamp:         {alert['timestamp']}")
        print("-" * 65)
    else:
        print("[!] Alert record not found yet.")
else:
    print(f"[!] Failed to fetch alerts: {alerts_resp.text}")

print("\n[+] Simulation complete! View full interactive dashboard at: http://localhost:8000/\n")
