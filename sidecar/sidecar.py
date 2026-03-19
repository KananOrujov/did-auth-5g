#!/usr/bin/env python3
"""
DID Authentication Sidecar v3.0
- Separated decision logic (proof_verified, revocation_ok, policy_allowed)
- Fail-close by default
- Structured JSON logging
- Latency breakdown per component
"""
import asyncio
import time
import logging
import json
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', force=True)
log = logging.getLogger(__name__)

VERIFIER_URL  = "http://localhost:8041"
HOLDER_URL    = "http://localhost:8031"
CRED_DEF_ID   = "QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable"
VERIFIER_CONN = "4a229530-2c7c-4202-a762-f3c84bcfa45e"
CACHE_TTL     = 300
FAIL_OPEN     = False  # Stage 1: fail-close by default

_global_proof_semaphore = None

def get_semaphore():
    global _global_proof_semaphore
    if _global_proof_semaphore is None:
        _global_proof_semaphore = asyncio.Semaphore(1)
    return _global_proof_semaphore

SLICE_POLICY = {
    "imsi-001010000000001": "SST:1",
    "imsi-001010000000002": "SST:1",
    "imsi-001010000000003": "SST:1",
    "imsi-001010000000004": "SST:1",
    "imsi-001010000000005": "SST:1",
    "imsi-001010000000006": "SST:1",
}

SUPI_CRED_MAP = {
    "imsi-001010000000001": "ce8e519e-2022-482a-919f-02646493f73c",
    "imsi-001010000000002": "40dd6224-bb79-4350-8953-8e257d63db31",
    "imsi-001010000000003": "30a67241-eba2-47d9-838e-8252b351a66d",
    "imsi-001010000000004": "1ab7dcfc-4eb6-4318-a8b7-311b3bc47723",
    "imsi-001010000000005": "ee84735e-5282-4f46-9353-64aac032072f",
    "imsi-001010000000006": "95d3fb40-e671-4347-a2d4-973d2a89fef4",
}

did_cache = {}

def structured_log(supi, decision, reason, proof_verified, revocation_ok,
                   policy_allowed, slice_value, cache_hit, timings):
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "supi": supi,
        "final_decision": decision,
        "reason": reason,
        "proof_verified": proof_verified,
        "revocation_ok": revocation_ok,
        "policy_allowed": policy_allowed,
        "slice": slice_value,
        "cache_hit": cache_hit,
        "timings_ms": timings
    }
    log.info(f"[AUTH] {json.dumps(entry)}")
    return entry

async def run_did_verification(supi):
    async with get_semaphore():
        await _run_did_verification_inner(supi)

async def _run_did_verification_inner(supi):
    t_total_start = time.time()
    timings = {}

    cred_ref = SUPI_CRED_MAP.get(supi)
    required_slice = SLICE_POLICY.get(supi, "SST:1")

    # Decision components
    proof_verified = False
    revocation_ok  = False
    policy_allowed = False
    slice_value    = None
    reason         = "unknown_error"

    if not cred_ref:
        reason = "no_credential_mapped"
        _store_cache(supi, False, proof_verified, revocation_ok, policy_allowed,
                     slice_value, reason, timings, t_total_start)
        return

    timeout = ClientTimeout(total=30)
    try:
        async with ClientSession(timeout=timeout) as session:

            # --- Step 1: Send proof request ---
            t0 = time.time()
            payload = {
                "connection_id": VERIFIER_CONN,
                "proof_request": {
                    "name": "5G-DID-Auth",
                    "version": "1.0",
                    "requested_attributes": {
                        "supi_attr":  {"name": "supi",
                            "restrictions": [{"cred_def_id": CRED_DEF_ID}]},
                        "imsi_attr":  {"name": "imsi",
                            "restrictions": [{"cred_def_id": CRED_DEF_ID}]},
                        "slice_attr": {"name": "network_slice",
                            "restrictions": [{"cred_def_id": CRED_DEF_ID}]}
                    },
                    "requested_predicates": {},
                    "non_revoked": {"from": 0, "to": 9999999999}
                }
            }
            async with session.post(f"{VERIFIER_URL}/present-proof/send-request",
                                    json=payload) as resp:
                data = await resp.json()
                pex_id = data["presentation_exchange_id"]
            timings["proof_request_ms"] = int((time.time() - t0) * 1000)

            # --- Step 2: Holder responds ---
            t0 = time.time()
            for _ in range(15):
                async with session.get(f"{HOLDER_URL}/present-proof/records") as r:
                    records = (await r.json()).get("results", [])
                    pending = [x for x in records if x["state"] == "request_received"]
                    if pending:
                        matched = [x for x in pending if x.get("thread_id") == pex_id]
                        pex_h = (matched[0] if matched else pending[0])["presentation_exchange_id"]
                        async with session.get(
                            f"{HOLDER_URL}/present-proof/records/{pex_h}/credentials"
                        ) as cr:
                            cred_list = await cr.json()

                        req_attrs = {}
                        for item in cred_list:
                            for ref in item.get("presentation_referents", []):
                                if ref not in req_attrs:
                                    req_attrs[ref] = {
                                        "cred_id": item["cred_info"]["referent"],
                                        "revealed": True
                                    }
                        for ref in list(req_attrs.keys()):
                            req_attrs[ref]["cred_id"] = cred_ref

                        await session.post(
                            f"{HOLDER_URL}/present-proof/records/{pex_h}/send-presentation",
                            json={
                                "requested_attributes": req_attrs,
                                "requested_predicates": {},
                                "non_revoked": {"from": 0, "to": 9999999999},
                                "self_attested_attributes": {}
                            })
                        break
                await asyncio.sleep(1)
            timings["holder_response_ms"] = int((time.time() - t0) * 1000)

            # --- Step 3: Verify presentation ---
            t0 = time.time()
            deadline = time.time() + 25
            while time.time() < deadline:
                async with session.get(f"{VERIFIER_URL}/present-proof/records") as r:
                    records = (await r.json()).get("results", [])
                    pending = [x for x in records
                               if x["state"] == "presentation_received"
                               and x["presentation_exchange_id"] == pex_id]
                    if not pending:
                        pending = [x for x in records if x["state"] == "presentation_received"]
                    if pending:
                        vid = pending[-1]["presentation_exchange_id"]
                        async with session.post(
                            f"{VERIFIER_URL}/present-proof/records/{vid}/verify-presentation"
                        ) as vr:
                            vd = await vr.json()
                            # proof_verified: cryptographic signature check
                            proof_verified = vd.get("verified") == True or vd.get("verified") == "true"
                            # revocation_ok: if proof verified with non_revoked interval, revocation passed
                            revocation_ok = proof_verified
                            try:
                                revealed = vd["presentation"]["requested_proof"]["revealed_attrs"]
                                slice_value = revealed["slice_attr"]["raw"]
                            except Exception:
                                slice_value = None
                            # policy_allowed: slice policy check
                            policy_allowed = (slice_value == required_slice)
                        break
                await asyncio.sleep(1)
            timings["verification_ms"] = int((time.time() - t0) * 1000)

            # --- Final decision ---
            if not proof_verified:
                reason = "proof_verification_failed"
            elif not revocation_ok:
                reason = "credential_revoked"
            elif not policy_allowed:
                reason = f"slice_policy_denied: got={slice_value} required={required_slice}"
            else:
                reason = "all_checks_passed"

            final_decision = proof_verified and revocation_ok and policy_allowed
            timings["total_ms"] = int((time.time() - t_total_start) * 1000)

            _store_cache(supi, final_decision, proof_verified, revocation_ok,
                        policy_allowed, slice_value, reason, timings, t_total_start)

    except Exception as e:
        reason = f"sidecar_error: {str(e)}"
        log.error(f"[ERROR] {supi}: {reason}")
        timings["total_ms"] = int((time.time() - t_total_start) * 1000)
        # Fail-close: on any error, deny
        _store_cache(supi, FAIL_OPEN, False, False, False, None, reason, timings, t_total_start)

def _store_cache(supi, final_decision, proof_verified, revocation_ok,
                 policy_allowed, slice_value, reason, timings, t_start):
    did_cache[supi] = {
        "final_decision": final_decision,
        "proof_verified": proof_verified,
        "revocation_ok": revocation_ok,
        "policy_allowed": policy_allowed,
        "slice": slice_value,
        "reason": reason,
        "timings_ms": timings,
        "timestamp": time.time(),
        "latency_ms": timings.get("total_ms", int((time.time() - t_start) * 1000))
    }
    structured_log(supi, final_decision, reason, proof_verified, revocation_ok,
                   policy_allowed, slice_value, False, timings)

async def handle_did_auth(request):
    t_start = time.time()
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"final_decision": False, "reason": "invalid_json"}, status=400)

    supi = body.get("supi", "")
    if not supi:
        return web.json_response({"final_decision": False, "reason": "missing_supi"}, status=400)

    log.info(f"[AUSF] Auth request for SUPI: {supi}")

    cached = did_cache.get(supi)
    cache_age = time.time() - cached["timestamp"] if cached else 999

    if cached and cache_age < CACHE_TTL:
        # Background refresh if cache is getting stale
        if cache_age > CACHE_TTL / 2:
            asyncio.create_task(run_did_verification(supi))

        latency = int((time.time() - t_start) * 1000)
        structured_log(supi, cached["final_decision"], cached["reason"],
                       cached["proof_verified"], cached["revocation_ok"],
                       cached["policy_allowed"], cached.get("slice"),
                       True, {"total_ms": latency})

        status_code = 200 if cached["final_decision"] else 403
        return web.json_response({
            "final_decision": cached["final_decision"],
            "proof_verified": cached["proof_verified"],
            "revocation_ok": cached["revocation_ok"],
            "policy_allowed": cached["policy_allowed"],
            "reason": cached["reason"],
            "supi": supi,
            "slice": cached.get("slice"),
            "cache_hit": True,
            "cache_age_s": round(cache_age, 1),
            "timings_ms": cached.get("timings_ms", {}),
            "latency_ms": latency
        }, status=status_code)
    else:
        await run_did_verification(supi)
        result = did_cache.get(supi)
        if not result:
            # Fail-close: if no result, deny
            return web.json_response({
                "final_decision": False,
                "reason": "verification_produced_no_result",
                "supi": supi
            }, status=403)

        latency = int((time.time() - t_start) * 1000)
        status_code = 200 if result["final_decision"] else 403
        return web.json_response({
            "final_decision": result["final_decision"],
            "proof_verified": result["proof_verified"],
            "revocation_ok": result["revocation_ok"],
            "policy_allowed": result["policy_allowed"],
            "reason": result["reason"],
            "supi": supi,
            "slice": result.get("slice"),
            "cache_hit": False,
            "timings_ms": result.get("timings_ms", {}),
            "latency_ms": latency
        }, status=status_code)

async def handle_health(request):
    return web.json_response({
        "status": "ok",
        "version": "3.0",
        "fail_mode": "close" if not FAIL_OPEN else "open",
        "cached_supis": list(did_cache.keys())
    })

async def handle_cache(request):
    return web.json_response(did_cache)

app = web.Application()
app.router.add_post("/did-auth", handle_did_auth)
app.router.add_get("/health", handle_health)
app.router.add_get("/cache", handle_cache)

if __name__ == "__main__":
    log.info("Starting DID Auth Sidecar v3.0 on port 5000...")
    log.info(f"Fail mode: {'open' if FAIL_OPEN else 'close'}")
    web.run_app(app, host="127.0.0.1", port=5000)
