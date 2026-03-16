#!/usr/bin/env python3
"""
Revocation behavior evaluation:
1. Verify valid credential -> expect True
2. Revoke credential -> expect False
3. Re-issue credential -> expect True
Measures latency at each step.
"""
import requests, time, subprocess, sys

SIDECAR      = "http://localhost:5000"
ISSUER       = "http://localhost:8021"
HOLDER       = "http://localhost:8031"
SUPI         = "imsi-001010000000001"
CRED_DEF     = "QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable"
REV_REG      = "QTbY98psM6bDviJj9A6JLU:4:QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable:CL_ACCUM:55375973-1fdd-4349-aa7e-47983a4aa460"
CONN_I2H     = "49b62f5e-b9f2-4536-83cb-1c8f6560487f"
SIDECAR_SCRIPT = "/home/kali/did-auth/sidecar.py"
SIDECAR_LOG  = "/home/kali/did-auth/logs/sidecar.log"
RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"

def restart_sidecar(cred_ref):
    # Update sidecar CRED_REF
    content = open(SIDECAR_SCRIPT).read()
    import re
    content = re.sub(r'SUPI_CRED_MAP = \{[^}]+\}',
        f'''SUPI_CRED_MAP = {{
    "imsi-001010000000001": "{cred_ref}",
    "imsi-001010000000002": "{cred_ref}",
    "imsi-001010000000003": "{cred_ref}",
}}''', content, flags=re.DOTALL)
    open(SIDECAR_SCRIPT, "w").write(content)
    subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
    time.sleep(2)
    log = open(SIDECAR_LOG, "w")
    subprocess.Popen(["python3", "-u", SIDECAR_SCRIPT], stdout=log, stderr=log)
    time.sleep(4)

def verify(label):
    r = requests.post(f"{SIDECAR}/did-auth", json={"supi": SUPI}, timeout=60)
    d = r.json()
    print(f"  [{label}] verified={d['verified']} slice={d.get('slice')} latency={d['latency_ms']}ms")
    return d['verified'], d['latency_ms']

def get_latest_cred(min_rev_id=0):
    for attempt in range(10):
        creds = [c for c in requests.get(f"{HOLDER}/credentials", params={"count": 50}).json().get("results", [])
                 if c.get("rev_reg_id") and int(c.get("cred_rev_id",0)) > min_rev_id]
        if creds:
            creds.sort(key=lambda x: int(x.get("cred_rev_id", 0)))
            return creds[-1]["referent"], creds[-1]["cred_rev_id"]
        time.sleep(2)
    raise Exception(f"No credential found with cred_rev_id > {min_rev_id}")

def issue_cred():
    # Get current max cred_rev_id before issuing
    try:
        existing = [c for c in requests.get(f"{HOLDER}/credentials", params={"count": 50}).json().get("results",[])
                    if c.get("rev_reg_id")]
        max_rev_id = max(int(c.get("cred_rev_id",0)) for c in existing) if existing else 0
    except:
        max_rev_id = 0
    requests.post(f"{ISSUER}/issue-credential/send", json={
        "connection_id": CONN_I2H,
        "cred_def_id": CRED_DEF,
        "credential_proposal": {
            "@type": "issue-credential/1.0/credential-preview",
            "attributes": [
                {"name": "supi",              "value": "imsi-001010000000001"},
                {"name": "imsi",              "value": "001010000000001"},
                {"name": "network_slice",     "value": "SST:1"},
                {"name": "subscription_type", "value": "5G-SA"},
                {"name": "issued_by",         "value": "MNO-Open5GS"}
            ]
        },
        "auto_remove": False
    })
    time.sleep(4)
    recs = [r for r in requests.get(f"{HOLDER}/issue-credential/records").json().get("results", [])
            if r["state"] == "offer_received"]
    recs.sort(key=lambda x: x.get("created_at", ""))
    if not recs:
        print("ERROR: no offer_received"); return None, None
    cred_ex = recs[-1]["credential_exchange_id"]
    requests.post(f"{HOLDER}/issue-credential/records/{cred_ex}/send-request", json={})
    time.sleep(5)
    requests.post(f"{HOLDER}/issue-credential/records/{cred_ex}/store", json={})
    time.sleep(3)
    return get_latest_cred(min_rev_id=max_rev_id)

def revoke_cred(cred_rev_id):
    requests.post(f"{ISSUER}/revocation/revoke", json={
        "cred_rev_id": cred_rev_id,
        "rev_reg_id": REV_REG,
        "publish": True
    })

def delete_other_creds(keep_referent):
    creds = [c for c in requests.get(f"{HOLDER}/credentials", params={"count": 50}).json().get("results", [])
             if c.get("rev_reg_id") and c["referent"] != keep_referent]
    for c in creds:
        requests.delete(f"{HOLDER}/credential/{c['referent']}")
        print(f"    Deleted cred {c['referent']} (cred_rev_id={c['cred_rev_id']})")
    time.sleep(1)

print("=== Revocation Behavior Test ===")
results = {}

# Issue fresh credential
print("\n[1] Issuing fresh credential...")
ref, rev_id = issue_cred()
print(f"    referent={ref} cred_rev_id={rev_id}")
restart_sidecar(ref)

print("\n[2] Verify valid credential (expect: True)")
v, lat = verify("VALID")
results["valid"] = {"verified": v, "latency_ms": lat}
assert v == True, f"FAIL: expected True got {v}"
print("    PASS")

print("\n[3] Revoking credential...")
revoke_cred(rev_id)
delete_other_creds(ref)
print("    Waiting 30s for ledger propagation...")
time.sleep(30)
restart_sidecar(ref)

print("\n[4] Verify revoked credential (expect: False)")
v, lat = verify("REVOKED")
results["revoked"] = {"verified": v, "latency_ms": lat}
assert v == False, f"FAIL: expected False got {v}"
print("    PASS")

print("\n[5] Issuing replacement credential...")
ref2, rev_id2 = issue_cred()
print(f"    referent={ref2} cred_rev_id={rev_id2}")
# Delete the revoked credential too so holder only has the new one
requests.delete(f"{HOLDER}/credential/{ref}")
time.sleep(1)
restart_sidecar(ref2)

print("\n[6] Verify re-issued credential (expect: True)")
v, lat = verify("REISSUED")
results["reissued"] = {"verified": v, "latency_ms": lat}
assert v == True, f"FAIL: expected True got {v}"
print("    PASS")

print("\n=== Revocation Test COMPLETE ===")
print(f"Valid:    verified={results['valid']['verified']}  latency={results['valid']['latency_ms']}ms")
print(f"Revoked:  verified={results['revoked']['verified']}  latency={results['revoked']['latency_ms']}ms")
print(f"Reissued: verified={results['reissued']['verified']}  latency={results['reissued']['latency_ms']}ms")

with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Revocation Test - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    for k, v in results.items():
        f.write(f"{k}: verified={v['verified']} latency={v['latency_ms']}ms\n")

print(f"\nResults saved to {RESULTS_FILE}")
