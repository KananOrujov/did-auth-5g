import requests, time, threading, sys

SIDECAR = "http://localhost:5000"
ISSUER = "http://localhost:8021"
REV_REG = "QTbY98psM6bDviJj9A6JLU:4:QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable:CL_ACCUM:55375973-1fdd-4349-aa7e-47983a4aa460"
CRED_REV_ID = "32"

UES = [
    "imsi-001010000000001",
    "imsi-001010000000002",
    "imsi-001010000000003",
]

results = {}

def auth_ue(supi):
    r = requests.post(f"{SIDECAR}/did-auth", json={"supi": supi}, timeout=60)
    d = r.json()
    results[supi] = {"verified": d["verified"], "slice": d.get("slice"), "latency_ms": d["latency_ms"]}
    print(f"  {supi}: verified={d['verified']} slice={d.get('slice')} latency={d['latency_ms']}ms")

print("=== Revocation Under Load Test ===")
print("\n[1] Baseline - all UEs should verify=True")
for supi in UES:
    auth_ue(supi)

print("\n[2] Revoking imsi-001010000000001 (cred_rev_id=32)...")
r = requests.post(f"{ISSUER}/revocation/revoke", json={
    "cred_rev_id": CRED_REV_ID,
    "rev_reg_id": REV_REG,
    "publish": True
})
print(f"  Revocation status: {r.status_code} {r.json()}")
time.sleep(3)

print("\n[3] Clearing sidecar cache...")
import subprocess
subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
time.sleep(1)
subprocess.Popen(["python3", "/home/kali/did-auth-5g/sidecar/sidecar.py"],
                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(3)

print("\n[4] Concurrent auth while UE1 is revoked...")
threads = []
for supi in UES:
    t = threading.Thread(target=auth_ue, args=(supi,))
    threads.append(t)

for t in threads:
    t.start()
for t in threads:
    t.join(timeout=60)

print("\n[5] Summary:")
for supi, r in results.items():
    expected = "DENY" if supi == "imsi-001010000000001" else "ALLOW"
    actual = "DENY" if not r["verified"] else "ALLOW"
    status = "PASS" if expected == actual else "FAIL"
    print(f"  {supi}: expected={expected} actual={actual} [{status}]")

with open("/home/kali/did-auth-5g/thesis-results.txt", "a") as f:
    f.write("\n=== B5 Revocation Under Load - " + time.strftime("%Y-%m-%d %H:%M") + " ===\n")
    for supi, r in results.items():
        f.write(f"  {supi}: verified={r['verified']} slice={r.get('slice')} latency={r['latency_ms']}ms\n")
print("Results saved.")
