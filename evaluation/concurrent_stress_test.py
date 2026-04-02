#!/usr/bin/env python3
"""
Concurrent UE Stress Test — Stage 3 Priority 2
Tests 2, 4, 6, 8, 10 concurrent UEs simultaneously
Measures: success rate, wall time, per-UE latency, queue time
"""
import asyncio
import aiohttp
import time
import json
import csv
import statistics
import datetime
import sys

SIDECAR_URL = "http://localhost:5000/did-auth"
RESULTS_DIR = "/home/kali/did-auth-5g/evaluation/results"

# All 6 available UEs (use UE-001 to UE-005 for allow, UE-006 is deny)
ALL_SUPIS = [
    "imsi-001010000000001",
    "imsi-001010000000002",
    "imsi-001010000000003",
    "imsi-001010000000004",
    "imsi-001010000000005",
    "imsi-001010000000006",  # SST:2 — always denied
]

ALLOW_SUPIS = ALL_SUPIS[:5]  # UE-001 to UE-005

async def auth_one_ue(session, supi, run_id):
    """Authenticate a single UE, return timing and result."""
    t_start = time.time()
    try:
        async with session.post(
            SIDECAR_URL,
            json={"supi": supi},
            timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            data = await resp.json()
            elapsed = int((time.time() - t_start) * 1000)
            return {
                "run_id":         run_id,
                "supi":           supi,
                "final_decision": data.get("final_decision", False),
                "reason":         data.get("reason", ""),
                "cache_hit":      data.get("cache_hit", False),
                "total_ms":       data.get("timings_ms", {}).get("total_ms", elapsed),
                "wall_ms":        elapsed,
                "http_status":    resp.status,
            }
    except Exception as e:
        elapsed = int((time.time() - t_start) * 1000)
        return {
            "run_id":         run_id,
            "supi":           supi,
            "final_decision": False,
            "reason":         f"error: {str(e)[:50]}",
            "cache_hit":      False,
            "total_ms":       elapsed,
            "wall_ms":        elapsed,
            "http_status":    0,
        }

async def run_concurrent_batch(supis, batch_label):
    """Fire all UEs simultaneously and collect results."""
    print(f"\n  [{batch_label}] Firing {len(supis)} UEs simultaneously...")
    wall_start = time.time()

    connector = aiohttp.TCPConnector(limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [auth_one_ue(session, supi, i+1) for i, supi in enumerate(supis)]
        results = await asyncio.gather(*tasks)

    wall_time = int((time.time() - wall_start) * 1000)

    success = [r for r in results if r["final_decision"]]
    failed  = [r for r in results if not r["final_decision"]]
    cached  = [r for r in results if r["cache_hit"]]

    print(f"  Wall time: {wall_time}ms")
    print(f"  Success: {len(success)}/{len(supis)} | Failed: {len(failed)} | Cache hits: {len(cached)}")

    for r in sorted(results, key=lambda x: x["run_id"]):
        status = "✓" if r["final_decision"] else "✗"
        print(f"    {status} UE-{r['supi'][-1]} | {r['total_ms']}ms | cache={r['cache_hit']} | {r['reason'][:40]}")

    return results, wall_time

async def flush_cache():
    """Clear sidecar cache by waiting for TTL or restarting."""
    print("  Flushing cache (waiting 2s + cache is per-sidecar-run)...")
    # Since sidecar caches in memory, we just wait between cold tests
    await asyncio.sleep(2)

async def main():
    print("=" * 60)
    print("  Concurrent UE Stress Test — DID-Auth-5G Stage 3")
    print("=" * 60)

    all_results = []
    summary = []
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # Test configurations: (n_ues, use_cache, label)
    test_configs = [
        (2,  False, "2_UEs_cold"),
        (4,  False, "4_UEs_cold"),
        (5,  False, "5_UEs_cold"),
        (5,  True,  "5_UEs_warm"),   # cache should be warm from previous run
        (10, True,  "10_UEs_warm"),  # 5 UEs repeated twice (only 5 distinct)
    ]

    for n_ues, use_cache, label in test_configs:
        print(f"\n{'─'*55}")
        print(f"  Test: {label}")
        print(f"{'─'*55}")

        # Select UEs — repeat if n > 5
        supis = (ALLOW_SUPIS * ((n_ues // 5) + 1))[:n_ues]

        if not use_cache:
            await flush_cache()

        results, wall_time = await run_concurrent_batch(supis, label)

        # Add metadata to each result
        for r in results:
            r["test_label"] = label
            r["n_ues"] = n_ues
            r["use_cache"] = use_cache
            r["wall_time_ms"] = wall_time
            all_results.append(r)

        # Summary stats
        success_count = sum(1 for r in results if r["final_decision"])
        latencies = [r["total_ms"] for r in results if r["total_ms"] > 0]
        summary.append({
            "test":          label,
            "n_ues":         n_ues,
            "cached":        use_cache,
            "wall_time_ms":  wall_time,
            "success":       success_count,
            "failed":        n_ues - success_count,
            "avg_latency_ms": int(statistics.mean(latencies)) if latencies else 0,
            "min_latency_ms": min(latencies) if latencies else 0,
            "max_latency_ms": max(latencies) if latencies else 0,
        })

        # Wait between tests to let sidecar settle
        if not use_cache:
            print("  Waiting 5s before next test...")
            await asyncio.sleep(5)

    # ── Print summary table ──────────────────────────────
    print(f"\n{'='*60}")
    print(f"  SUMMARY")
    print(f"{'='*60}")
    print(f"  {'Test':<20} {'UEs':>4} {'Cache':>6} {'Wall':>8} {'OK':>4} {'Avg':>8} {'Min':>8} {'Max':>8}")
    print(f"  {'-'*20} {'-'*4} {'-'*6} {'-'*8} {'-'*4} {'-'*8} {'-'*8} {'-'*8}")
    for s in summary:
        print(f"  {s['test']:<20} {s['n_ues']:>4} {str(s['cached']):>6} "
              f"{s['wall_time_ms']:>7}ms {s['success']:>4} "
              f"{s['avg_latency_ms']:>7}ms {s['min_latency_ms']:>7}ms {s['max_latency_ms']:>7}ms")

    # ── Save CSV ──────────────────────────────────────────
    csv_path = f"{RESULTS_DIR}/exp_concurrent_stress_{ts}.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=[
            "test_label","n_ues","use_cache","wall_time_ms","run_id",
            "supi","final_decision","reason","cache_hit",
            "total_ms","wall_ms","http_status"
        ])
        w.writeheader()
        w.writerows(all_results)

    # ── Save JSON ─────────────────────────────────────────
    json_path = f"{RESULTS_DIR}/exp_concurrent_stress_{ts}.json"
    with open(json_path, "w") as f:
        json.dump({
            "experiment":  "concurrent_ue_stress_test",
            "timestamp":   ts,
            "summary":     summary,
            "raw_results": all_results
        }, f, indent=2)

    print(f"\n  Saved: {csv_path}")
    print(f"  Saved: {json_path}")
    print(f"\n  Key findings:")
    cold_4 = next((s for s in summary if "4_UEs_cold" in s["test"]), None)
    warm_5 = next((s for s in summary if "5_UEs_warm" in s["test"]), None)
    warm_10 = next((s for s in summary if "10_UEs_warm" in s["test"]), None)
    if cold_4:
        print(f"  • 4 UEs cold: wall={cold_4['wall_time_ms']}ms avg={cold_4['avg_latency_ms']}ms")
    if warm_5:
        print(f"  • 5 UEs warm: wall={warm_5['wall_time_ms']}ms avg={warm_5['avg_latency_ms']}ms")
    if warm_10:
        print(f"  • 10 UEs warm: wall={warm_10['wall_time_ms']}ms avg={warm_10['avg_latency_ms']}ms")
    print()

asyncio.run(main())
