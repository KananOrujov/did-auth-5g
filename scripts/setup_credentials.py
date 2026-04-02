#!/usr/bin/env python3
"""
DID-Auth-5G Credential Setup Script
Automates: connections + schema + cred def + issue + store for all 6 UEs
Usage: python3 scripts/setup_credentials.py [local|bcovrin]
"""
import sys
import requests
import time
import json
import re

MODE = sys.argv[1] if len(sys.argv) > 1 else "local"

ISSUER   = "http://localhost:8021"
HOLDER   = "http://localhost:8031"
VERIFIER = "http://localhost:8041"
SIDECAR  = "/home/kali/did-auth-5g/sidecar/sidecar.py"

# Ledger-specific config
CONFIG = {
    "local": {
        "issuer_did": "YbmLV9CGCk8Uq1NAJqvD77",
        "schema_id":  "YbmLV9CGCk8Uq1NAJqvD77:2:5g-subscriber:1.0",
        "cred_def_tag": "revocable-local",
    },
    "bcovrin": {
        "issuer_did": "QTbY98psM6bDviJj9A6JLU",
        "schema_id":  "QTbY98psM6bDviJj9A6JLU:2:5g-subscriber:1.0",
        "cred_def_tag": "revocable",
    }
}

cfg = CONFIG[MODE]

UES = [
    ("imsi-001010000000001", "001010000000001", "SST:1"),
    ("imsi-001010000000002", "001010000000002", "SST:1"),
    ("imsi-001010000000003", "001010000000003", "SST:1"),
    ("imsi-001010000000004", "001010000000004", "SST:1"),
    ("imsi-001010000000005", "001010000000005", "SST:1"),
    ("imsi-001010000000006", "001010000000006", "SST:2"),
]

def post(url, data=None):
    r = requests.post(url, json=data, timeout=30)
    try:
        return r.json()
    except:
        print(f"  ERROR {url}: {r.text[:200]}")
        return {}

def get(url):
    return requests.get(url, timeout=30).json()

def wait_for_agents():
    print("Waiting for agents to be ready...")
    for name, port in [("Issuer",8021),("Holder",8031),("Verifier",8041)]:
        for attempt in range(20):
            try:
                label = get(f"http://localhost:{port}/status").get("label","")
                if label:
                    print(f"  ✓ {name}: {label}")
                    break
            except:
                pass
            time.sleep(2)
        else:
            print(f"  ✗ {name} not responding — is it started?")
            sys.exit(1)

def make_connection(inviter_url, inviter_name, accepter_url, accepter_name):
    print(f"  Connecting {inviter_name} <-> {accepter_name}...")
    inv = post(f"{inviter_url}/connections/create-invitation", {})
    inviter_conn = inv["connection_id"]
    invitation   = inv["invitation"]

    if not invitation.get("serviceEndpoint"):
        print(f"  ERROR: invitation missing serviceEndpoint — restart agents with --endpoint flag")
        sys.exit(1)

    h = post(f"{accepter_url}/connections/receive-invitation", invitation)
    accepter_conn = h["connection_id"]

    time.sleep(2)
    post(f"{accepter_url}/connections/{accepter_conn}/accept-invitation")
    time.sleep(3)
    post(f"{inviter_url}/connections/{inviter_conn}/accept-request")
    time.sleep(3)
    post(f"{accepter_url}/connections/{accepter_conn}/send-ping", {"comment":"ping"})
    time.sleep(3)

    state = get(f"{inviter_url}/connections/{inviter_conn}")["state"]
    print(f"  ✓ {inviter_name}<->{accepter_name}: {state}")
    return inviter_conn, accepter_conn

def get_or_create_cred_def(schema_id, tag):
    # Check existing
    existing = get(f"{ISSUER}/credential-definitions/created")
    for cid in existing.get("credential_definition_ids", []):
        if tag in cid:
            print(f"  ✓ Using existing cred def: {cid}")
            return cid

    # Create new
    print(f"  Creating new cred def (tag={tag})...")
    result = post(f"{ISSUER}/credential-definitions", {
        "schema_id": schema_id,
        "tag": tag,
        "support_revocation": True,
        "revocation_registry_size": 100
    })
    cred_def_id = result.get("credential_definition_id", "")
    if not cred_def_id:
        print(f"  ERROR creating cred def: {result}")
        sys.exit(1)
    print(f"  ✓ Cred def created: {cred_def_id}")
    time.sleep(3)
    return cred_def_id

def issue_credentials(issuer_conn, cred_def_id):
    print("  Issuing credentials...")
    for supi, imsi, slc in UES:
        r = post(f"{ISSUER}/issue-credential/send", {
            "connection_id": issuer_conn,
            "cred_def_id": cred_def_id,
            "credential_proposal": {
                "@type": "issue-credential/1.0/credential-preview",
                "attributes": [
                    {"name":"supi",              "value":supi},
                    {"name":"imsi",              "value":imsi},
                    {"name":"network_slice",     "value":slc},
                    {"name":"subscription_type", "value":"5G-SA"},
                    {"name":"issued_by",         "value":"MNO-Open5GS"},
                ]
            },
            "auto_remove": False
        })
        ex_id = r.get("credential_exchange_id","ERROR")
        print(f"  ✓ Issued {supi} ({slc}): {ex_id[:8]}...")
        time.sleep(3)

def accept_and_store():
    print("  Accepting offers on holder...")
    time.sleep(5)
    records = get(f"{HOLDER}/issue-credential/records")["results"]
    for r in records:
        if r["state"] == "offer_received":
            post(f"{HOLDER}/issue-credential/records/{r['credential_exchange_id']}/send-request", {})
            time.sleep(3)

    print("  Storing credentials on holder...")
    time.sleep(8)
    records = get(f"{HOLDER}/issue-credential/records")["results"]
    for r in records:
        if r["state"] == "credential_received":
            post(f"{HOLDER}/issue-credential/records/{r['credential_exchange_id']}/store", {})
            time.sleep(2)

def get_cred_map(cred_def_id):
    time.sleep(3)
    creds = get(f"{HOLDER}/credentials")["results"]
    cred_map = {}
    for c in creds:
        supi = c["attrs"]["supi"]
        cred_map[supi] = {
            "cred_id":    c["referent"],
            "slice":      c["attrs"]["network_slice"],
            "cred_rev_id": c.get("cred_rev_id",""),
        }
    return cred_map

def update_sidecar(cred_def_id, verifier_conn, cred_map):
    print("  Updating sidecar.py with new values...")
    with open(SIDECAR) as f:
        content = f.read()

    # Update CRED_DEF_ID
    content = re.sub(
        r'CRED_DEF_ID\s*=\s*"[^"]*"',
        f'CRED_DEF_ID   = "{cred_def_id}"',
        content
    )

    # Update VERIFIER_CONN
    content = re.sub(
        r'VERIFIER_CONN\s*=\s*"[^"]*"',
        f'VERIFIER_CONN = "{verifier_conn}"',
        content
    )

    # Update SUPI_CRED_MAP
    new_map = "SUPI_CRED_MAP = {\n"
    for supi, imsi, slc in UES:
        info = cred_map.get(supi, {})
        cid  = info.get("cred_id","MISSING")
        rev  = info.get("cred_rev_id","?")
        note = f"SST:2 -> DENY" if slc == "SST:2" else f"rev_id={rev}"
        new_map += f'    "{supi}": "{cid}",  # {note}\n'
    new_map += "}"

    content = re.sub(
        r'SUPI_CRED_MAP\s*=\s*\{[^}]+\}',
        new_map,
        content
    )

    with open(SIDECAR, "w") as f:
        f.write(content)
    print("  ✓ sidecar.py updated")

# ── MAIN ───────────────────────────────────────────────────
print(f"\n{'='*55}")
print(f"  DID-Auth-5G Credential Setup  [{MODE.upper()} LEDGER]")
print(f"{'='*55}\n")

print("Step 1: Checking agents...")
wait_for_agents()

print("\nStep 2: Creating connections...")
issuer_conn, _    = make_connection(ISSUER, "Issuer", HOLDER, "Holder")
verifier_conn, _  = make_connection(VERIFIER, "Verifier", HOLDER, "Holder")

print("\nStep 3: Getting/creating credential definition...")
cred_def_id = get_or_create_cred_def(cfg["schema_id"], cfg["cred_def_tag"])

print("\nStep 4: Issuing credentials to all 6 UEs...")
issue_credentials(issuer_conn, cred_def_id)

print("\nStep 5: Holder accepts and stores...")
accept_and_store()

print("\nStep 6: Getting credential map...")
cred_map = get_cred_map(cred_def_id)
print(f"  ✓ {len(cred_map)} credentials in wallet")

print("\nStep 7: Updating sidecar.py...")
update_sidecar(cred_def_id, verifier_conn, cred_map)

print("\nStep 8: Final credential map:")
print(f"\n  CRED_DEF_ID   = \"{cred_def_id}\"")
print(f"  VERIFIER_CONN = \"{verifier_conn}\"")
print(f"\n  SUPI_CRED_MAP:")
for supi, info in cred_map.items():
    print(f"    {supi}: {info['cred_id'][:8]}... ({info['slice']} rev={info['cred_rev_id']})")

print(f"\n{'='*55}")
print(f"  Setup complete! Now restart the sidecar:")
print(f"  pkill -f sidecar.py && python3 sidecar/sidecar.py &")
print(f"  Then test:")
print(f"  curl -s -X POST http://localhost:5000/did-auth \\")
print(f"    -H 'Content-Type: application/json' \\")
print(f"    -d '{{\"supi\":\"imsi-001010000000002\"}}'")
print(f"{'='*55}\n")
