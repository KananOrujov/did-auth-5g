#!/usr/bin/env python3
"""
Latency evaluation: n runs of full DID proof verification (no cache).
"""
import subprocess, requests, time, json, sys, os

SIDECAR = "http://localhost:5000"
SUPI = "imsi-001010000000001"
SIDECAR_SCRIPT = "/home/kali/did-auth/sidecar.py"
SIDECAR_LOG = "/home/kali/did-auth/logs/sidecar.log"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 10
RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"

def restart_sidecar():
    subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
    time.sleep(2)
    log = open(SIDECAR_LOG, "w")
    subprocess.Popen(["python3", "-u", SIDECAR_SCRIPT], stdout=log, stderr=log)
    time.sleep(4)

results = []
print(f"=== Latency Test (n={N}) ===")
for i in range(1, N+1):
    restart_sidecar()
    r = requests.post(f"{SIDECAR}/did-auth",
                      json={"supi": SUPI}, timeout=60)
    d = r.json()
    lat = d["latency_ms"]
    verified = d["verified"]
    slice_val = d.get("slice")
    results.append(lat)
    print(f"Run {i:2d}: verified={verified} slice={slice_val} latency={lat}ms")

print(f"\n--- Summary ---")
print(f"N:   {len(results)}")
print(f"Min: {min(results)}ms")
print(f"Max: {max(results)}ms")
print(f"Avg: {sum(results)//len(results)}ms")
print(f"All: {results}")

# Append to thesis results
with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Latency Test (n={N}) - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    for i, lat in enumerate(results, 1):
        f.write(f"Run {i}: {lat}ms\n")
    f.write(f"Min: {min(results)}ms  Max: {max(results)}ms  Avg: {sum(results)//len(results)}ms\n")

print(f"\nResults saved to {RESULTS_FILE}")
