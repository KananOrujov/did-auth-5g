#!/usr/bin/env python3
"""
Stage 2 Experiment Runner - v3.0 system
Runs all key experiments and saves structured CSV + JSON output.
"""
import requests, time, json, csv, subprocess, asyncio, aiohttp, os

SIDECAR = "http://localhost:5000"
ISSUER  = "http://localhost:8021"
OUTPUT_DIR = "/home/kali/did-auth-5g/evaluation/results"
os.makedirs(OUTPUT_DIR, exist_ok=True)

TIMESTAMP = time.strftime("%Y%m%d_%H%M%S")
ALL_RESULTS = []

def save_results(name, results):
    # JSON
    with open(f"{OUTPUT_DIR}/{name}_{TIMESTAMP}.json", "w") as f:
        json.dump(results, f, indent=2)
    # CSV
    if results:
        keys = results[0].keys()
        with open(f"{OUTPUT_DIR}/{name}_{TIMESTAMP}.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=keys)
            w.writeheader()
            w.writerows(results)
    print(f"  Saved: {name}_{TIMESTAMP}.json/csv")

def restart_sidecar():
    subprocess.run(["pkill", "-f", "sidecar.py"], capture_output=True)
    time.sleep(1)
    subprocess.Popen(
        ["python3", "/home/kali/did-auth-5g/sidecar/sidecar.py"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    time.sleep(4)

def auth_request(supi):
    t0 = time.time()
    try:
        r = requests.post(f"{SIDECAR}/did-auth", json={"supi": supi}, timeout=60)
        d = r.json()
        d["wall_ms"] = int((time.time() - t0) * 1000)
        d["http_status"] = r.status_code
        return d
    except Exception as e:
        return {"final_decision": False, "reason": str(e), "wall_ms": int((time.time()-t0)*1000)}

# ─────────────────────────────────────────
# EXP 1: Allow / Deny / Revocation cases
# ─────────────────────────────────────────
print("\n=== EXP 1: Allow / Deny / Revocation ===")
restart_sidecar()
results = []

# Allow case
r = auth_request("imsi-001010000000002")
r["experiment"] = "allow_case"
r["supi"] = "imsi-001010000000002"
results.append(r)
print(f"  Allow:      final={r['final_decision']} reason={r.get('reason')} latency={r.get('timings_ms',{}).get('total_ms')}ms")

time.sleep(2)

# Deny case (slice)
r = auth_request("imsi-001010000000006")
r["experiment"] = "slice_deny_case"
r["supi"] = "imsi-001010000000006"
results.append(r)
print(f"  Slice deny: final={r['final_decision']} reason={r.get('reason')} latency={r.get('timings_ms',{}).get('total_ms')}ms")

time.sleep(2)

# Revocation case (imsi-001010000000001 is revoked)
restart_sidecar()
r = auth_request("imsi-001010000000001")
r["experiment"] = "revocation_deny_case"
r["supi"] = "imsi-001010000000001"
results.append(r)
print(f"  Revoked:    final={r['final_decision']} reason={r.get('reason')} latency={r.get('timings_ms',{}).get('total_ms')}ms")

save_results("exp1_allow_deny_revocation", results)

# ─────────────────────────────────────────
# EXP 2: Cold vs Warm latency (n=5 each)
# ─────────────────────────────────────────
print("\n=== EXP 2: Cold vs Warm Latency (n=5) ===")
results = []

# Cold runs
for i in range(1, 6):
    restart_sidecar()
    r = auth_request("imsi-001010000000002")
    row = {
        "experiment": "cold_latency",
        "run": i,
        "supi": "imsi-001010000000002",
        "final_decision": r.get("final_decision"),
        "proof_request_ms": r.get("timings_ms", {}).get("proof_request_ms"),
        "holder_response_ms": r.get("timings_ms", {}).get("holder_response_ms"),
        "verification_ms": r.get("timings_ms", {}).get("verification_ms"),
        "total_ms": r.get("timings_ms", {}).get("total_ms"),
        "cache_hit": r.get("cache_hit", False)
    }
    results.append(row)
    print(f"  Cold run {i}: {row['total_ms']}ms")

# Warm runs (cache populated)
restart_sidecar()
auth_request("imsi-001010000000002")  # populate cache
time.sleep(1)
for i in range(1, 6):
    r = auth_request("imsi-001010000000002")
    row = {
        "experiment": "warm_latency",
        "run": i,
        "supi": "imsi-001010000000002",
        "final_decision": r.get("final_decision"),
        "proof_request_ms": r.get("timings_ms", {}).get("proof_request_ms"),
        "holder_response_ms": r.get("timings_ms", {}).get("holder_response_ms"),
        "verification_ms": r.get("timings_ms", {}).get("verification_ms"),
        "total_ms": r.get("timings_ms", {}).get("total_ms"),
        "cache_hit": r.get("cache_hit", False)
    }
    results.append(row)
    print(f"  Warm run {i}: {row['total_ms']}ms cache_hit={row['cache_hit']}")

cold = [r["total_ms"] for r in results if r["experiment"]=="cold_latency" and r["total_ms"]]
warm = [r["total_ms"] for r in results if r["experiment"]=="warm_latency" and r["total_ms"]]
print(f"  Cold avg: {sum(cold)//len(cold)}ms  Warm avg: {sum(warm)//len(warm)}ms")
save_results("exp2_cold_vs_warm_latency", results)

# ─────────────────────────────────────────
# EXP 3: Multi-UE sequential
# ─────────────────────────────────────────
print("\n=== EXP 3: Multi-UE Sequential (5 UEs) ===")
restart_sidecar()
results = []
UES = [
    "imsi-001010000000002",
    "imsi-001010000000003",
    "imsi-001010000000004",
    "imsi-001010000000005",
]
for supi in UES:
    r = auth_request(supi)
    row = {
        "experiment": "multi_ue_sequential",
        "supi": supi,
        "final_decision": r.get("final_decision"),
        "reason": r.get("reason"),
        "total_ms": r.get("timings_ms", {}).get("total_ms"),
        "proof_verified": r.get("proof_verified"),
        "policy_allowed": r.get("policy_allowed"),
        "slice": r.get("slice")
    }
    results.append(row)
    print(f"  {supi}: final={row['final_decision']} latency={row['total_ms']}ms")
save_results("exp3_multi_ue_sequential", results)

# ─────────────────────────────────────────
# EXP 4: Concurrent UEs
# ─────────────────────────────────────────
print("\n=== EXP 4: Concurrent UEs (4 UEs) ===")

async def async_auth(session, supi):
    t0 = time.time()
    async with session.post(f"{SIDECAR}/did-auth",
                            json={"supi": supi},
                            timeout=aiohttp.ClientTimeout(total=120)) as r:
        d = await r.json()
        d["wall_ms"] = int((time.time()-t0)*1000)
        return d

async def run_concurrent():
    restart_sidecar()
    t_start = time.time()
    async with aiohttp.ClientSession() as session:
        tasks = [async_auth(session, s) for s in UES]
        res = await asyncio.gather(*tasks, return_exceptions=True)
    return res, int((time.time()-t_start)*1000)

conc_res, wall = asyncio.run(run_concurrent())
results = []
for supi, r in zip(UES, conc_res):
    if isinstance(r, Exception):
        row = {"experiment": "concurrent", "supi": supi, "final_decision": False, "reason": str(r)}
    else:
        row = {
            "experiment": "concurrent",
            "supi": supi,
            "final_decision": r.get("final_decision"),
            "reason": r.get("reason"),
            "total_ms": r.get("timings_ms", {}).get("total_ms"),
            "wall_ms": r.get("wall_ms"),
            "proof_verified": r.get("proof_verified"),
            "cache_hit": r.get("cache_hit")
        }
    results.append(row)
    print(f"  {supi}: final={row.get('final_decision')} latency={row.get('total_ms')}ms")
print(f"  Total wall time: {wall}ms")
save_results("exp4_concurrent_ues", results)

print(f"\n=== All experiments complete. Results in {OUTPUT_DIR}/ ===")
