#!/usr/bin/env python3
"""
Multi-UE scalability test:
Simulates N UEs authenticating sequentially and concurrently.
Uses same credential but different SUPI identifiers.
"""
import requests, time, subprocess, asyncio, aiohttp, sys

SIDECAR      = "http://localhost:5000"
SIDECAR_SCRIPT = "/home/kali/did-auth/sidecar.py"
SIDECAR_LOG  = "/home/kali/did-auth/logs/sidecar.log"
RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"

# Simulated UEs — all share same credential for testbed
UES = [
    "imsi-001010000000001",
    "imsi-001010000000002",
    "imsi-001010000000003",
    "imsi-001010000000004",
    "imsi-001010000000005",
]

def restart_sidecar():
    subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
    time.sleep(2)
    log = open(SIDECAR_LOG, "w")
    subprocess.Popen(["python3", "-u", SIDECAR_SCRIPT], stdout=log, stderr=log)
    time.sleep(4)

# --- Sequential test ---
print("=== Multi-UE Test ===")
print(f"\n[1] Sequential authentication ({len(UES)} UEs)")
restart_sidecar()

seq_results = []
for supi in UES:
    t0 = time.time()
    r = requests.post(f"{SIDECAR}/did-auth", json={"supi": supi}, timeout=60)
    d = r.json()
    lat = d["latency_ms"]
    seq_results.append({"supi": supi, "verified": d["verified"],
                        "slice": d.get("slice"), "latency_ms": lat})
    print(f"  {supi}: verified={d['verified']} slice={d.get('slice')} latency={lat}ms")

print(f"\n  Sequential summary:")
print(f"  Total UEs: {len(seq_results)}")
lats = [r["latency_ms"] for r in seq_results]
print(f"  Min: {min(lats)}ms  Max: {max(lats)}ms  Avg: {sum(lats)//len(lats)}ms")

# --- Concurrent test ---
print(f"\n[2] Concurrent authentication ({len(UES)} UEs simultaneously)")

async def auth_ue(session, supi):
    t0 = time.time()
    async with session.post(f"{SIDECAR}/did-auth",
                            json={"supi": supi},
                            timeout=aiohttp.ClientTimeout(total=60)) as r:
        d = await r.json()
        wall = int((time.time() - t0) * 1000)
        return {"supi": supi, "verified": d["verified"],
                "slice": d.get("slice"), "latency_ms": d["latency_ms"], "wall_ms": wall}

async def run_concurrent():
    restart_sidecar()
    t_start = time.time()
    async with aiohttp.ClientSession() as session:
        tasks = [auth_ue(session, supi) for supi in UES]
        results = await asyncio.gather(*tasks, return_exceptions=True)
    total = time.time() - t_start
    return results, total

conc_results, total_time = asyncio.run(run_concurrent())

print(f"  Total wall time: {total_time:.2f}s")
for r in conc_results:
    if isinstance(r, Exception):
        print(f"  ERROR: {r}")
    else:
        print(f"  {r['supi']}: verified={r['verified']} slice={r.get('slice')} latency={r['latency_ms']}ms wall={r['wall_ms']}ms")

conc_lats = [r["latency_ms"] for r in conc_results if not isinstance(r, Exception)]
if conc_lats:
    print(f"\n  Concurrent summary:")
    print(f"  Total wall time: {total_time:.2f}s")
    print(f"  Min: {min(conc_lats)}ms  Max: {max(conc_lats)}ms  Avg: {sum(conc_lats)//len(conc_lats)}ms")

# Save results
with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Multi-UE Test - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    f.write(f"Sequential ({len(UES)} UEs):\n")
    for r in seq_results:
        f.write(f"  {r['supi']}: verified={r['verified']} latency={r['latency_ms']}ms\n")
    f.write(f"  Avg: {sum(lats)//len(lats)}ms\n")
    f.write(f"Concurrent ({len(UES)} UEs):\n")
    f.write(f"  Total wall time: {total_time:.2f}s\n")
    for r in conc_results:
        if not isinstance(r, Exception):
            f.write(f"  {r['supi']}: verified={r['verified']} latency={r['latency_ms']}ms\n")
    if conc_lats:
        f.write(f"  Avg: {sum(conc_lats)//len(conc_lats)}ms\n")

print(f"\nResults saved to {RESULTS_FILE}")
