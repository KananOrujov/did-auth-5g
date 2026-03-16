#!/usr/bin/env python3
"""
Throughput evaluation: sequential requests with cache warm,
measures requests/sec and avg latency under load.
"""
import requests, time, json, subprocess, sys

SIDECAR = "http://localhost:5000"
SUPI = "imsi-001010000000001"
SIDECAR_SCRIPT = "/home/kali/did-auth/sidecar.py"
SIDECAR_LOG = "/home/kali/did-auth/logs/sidecar.log"
RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"
N = int(sys.argv[1]) if len(sys.argv) > 1 else 20

def restart_sidecar():
    subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
    time.sleep(2)
    log = open(SIDECAR_LOG, "w")
    subprocess.Popen(["python3", "-u", SIDECAR_SCRIPT], stdout=log, stderr=log)
    time.sleep(4)

print(f"=== Throughput Test (n={N}) ===")

# First request warms the cache
restart_sidecar()
print("Warming cache...")
r = requests.post(f"{SIDECAR}/did-auth", json={"supi": SUPI}, timeout=60)
print(f"Cache warm: verified={r.json()['verified']} latency={r.json()['latency_ms']}ms")
time.sleep(1)

# Now measure throughput with cache hits
latencies = []
errors = 0
t_total_start = time.time()

print(f"\nRunning {N} sequential cache-hit requests...")
for i in range(1, N+1):
    t0 = time.time()
    try:
        r = requests.post(f"{SIDECAR}/did-auth", json={"supi": SUPI}, timeout=10)
        d = r.json()
        lat = d["latency_ms"]
        latencies.append(lat)
        print(f"  Req {i:2d}: verified={d['verified']} cache_age={d.get('cache_age_s','N/A')}s latency={lat}ms")
    except Exception as e:
        errors += 1
        print(f"  Req {i:2d}: ERROR {e}")

total_time = time.time() - t_total_start
rps = N / total_time

print(f"\n--- Throughput Summary ---")
print(f"Total requests: {N}")
print(f"Errors:         {errors}")
print(f"Total time:     {total_time:.2f}s")
print(f"Throughput:     {rps:.2f} req/s")
if latencies:
    print(f"Avg latency:    {sum(latencies)//len(latencies)}ms")
    print(f"Min latency:    {min(latencies)}ms")
    print(f"Max latency:    {max(latencies)}ms")

with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Throughput Test (n={N}) - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    f.write(f"Total time: {total_time:.2f}s\n")
    f.write(f"Throughput: {rps:.2f} req/s\n")
    if latencies:
        f.write(f"Avg latency: {sum(latencies)//len(latencies)}ms\n")
        f.write(f"Min: {min(latencies)}ms  Max: {max(latencies)}ms\n")

print(f"\nResults saved to {RESULTS_FILE}")
