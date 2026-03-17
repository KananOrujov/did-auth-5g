#!/usr/bin/env python3
"""
DID Authentication Sidecar v2.0
- Network slice attribute enforcement
- Multi-UE support
- Cache-assisted fast path
"""
import asyncio
import time
import logging
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', force=True)
log = logging.getLogger(__name__)

VERIFIER_URL  = "http://localhost:8041"
HOLDER_URL    = "http://localhost:8031"
CRED_DEF_ID   = "QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable"
VERIFIER_CONN = "4a229530-2c7c-4202-a762-f3c84bcfa45e"
CACHE_TTL     = 300
_supi_locks = {}
_global_proof_semaphore = None

def get_supi_lock(supi):
    if supi not in _supi_locks:
        _supi_locks[supi] = asyncio.Lock()
    return _supi_locks[supi]

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
    "imsi-001010000000001": "5192e3ea-78ef-4593-b648-3ce5f2e60170",
    "imsi-001010000000002": "40dd6224-bb79-4350-8953-8e257d63db31",
    "imsi-001010000000003": "30a67241-eba2-47d9-838e-8252b351a66d",
    "imsi-001010000000004": "1ab7dcfc-4eb6-4318-a8b7-311b3bc47723",
    "imsi-001010000000005": "ee84735e-5282-4f46-9353-64aac032072f",
    "imsi-001010000000006": "95d3fb40-e671-4347-a2d4-973d2a89fef4",
}

did_cache = {}

async def run_did_verification(supi):
    async with get_semaphore():
        await _run_did_verification_inner(supi)

async def _run_did_verification_inner(supi):
    t_start = time.time()
    cred_ref = SUPI_CRED_MAP.get(supi, list(SUPI_CRED_MAP.values())[0])
    required_slice = SLICE_POLICY.get(supi, "SST:1")
    timeout = ClientTimeout(total=30)
    try:
        async with ClientSession(timeout=timeout) as session:
            # Step 1: Send proof request
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

            # Step 2: Holder auto-responds using matching credential
            for _ in range(15):
                async with session.get(f"{HOLDER_URL}/present-proof/records") as r:
                    records = (await r.json()).get("results", [])
                    pending = [x for x in records if x["state"] == "request_received"]
                    if pending:
                        # Match by thread_id to avoid race conditions between concurrent UEs
                        matched = [x for x in pending if x.get("thread_id") == pex_id]
                        pex_h = (matched[0] if matched else pending[0])["presentation_exchange_id"]
                        # Let holder auto-select matching attributes
                        async with session.get(
                            f"{HOLDER_URL}/present-proof/records/{pex_h}/credentials"
                        ) as cr:
                            cred_list = await cr.json()

                        # Build presentation from available credentials
                        req_attrs = {}
                        for item in cred_list:
                            for ref in item.get("presentation_referents", []):
                                if ref not in req_attrs:
                                    item_cred_id = item["cred_info"]["referent"]
                                    # Prefer the credential matching SUPI_CRED_MAP
                                    if item_cred_id == cred_ref or ref not in req_attrs:
                                        req_attrs[ref] = {
                                            "cred_id": item_cred_id,
                                            "revealed": True
                                        }
                        # Override with exact credential from SUPI_CRED_MAP
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

            # Step 3: Wait for verifier and check result
            deadline = time.time() + 25
            verified = False
            slice_value = None
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
                            crypto_ok = vd.get("verified") == True or vd.get("verified") == "true"
                            try:
                                revealed = vd["presentation"]["requested_proof"]["revealed_attrs"]
                                slice_value = revealed["slice_attr"]["raw"]
                            except Exception:
                                slice_value = None
                            slice_ok = (slice_value == required_slice)
                            verified = crypto_ok and slice_ok
                            if crypto_ok and not slice_ok:
                                log.warning(f"[SLICE] DENIED {supi}: got={slice_value} required={required_slice}")
                        break
                await asyncio.sleep(1)

            latency = int((time.time() - t_start) * 1000)
            did_cache[supi] = {
                "verified": verified,
                "timestamp": time.time(),
                "latency_ms": latency,
                "slice": slice_value,
                "slice_ok": slice_value == required_slice if slice_value else False
            }
            log.info(f"[BG] {supi}: verified={verified} slice={slice_value} latency={latency}ms")

    except Exception as e:
        log.error(f"[BG] Error for {supi}: {e}")



async def handle_did_auth(request):
    t_start = time.time()
    try:
        body = await request.json()
    except Exception:
        return web.json_response({"status": "fail", "error": "invalid JSON"}, status=400)

    supi = body.get("supi", "")
    log.info(f"[AUSF] DID auth request for SUPI: {supi}")

    cached = did_cache.get(supi)
    cache_age = time.time() - cached["timestamp"] if cached else 999

    if cached and cache_age < CACHE_TTL:
        latency = int((time.time() - t_start) * 1000)
        if cache_age > CACHE_TTL / 2:
            asyncio.create_task(run_did_verification(supi))
        status_code = 200 if cached["verified"] else 403
        return web.json_response({
            "status": "ok" if cached["verified"] else "fail",
            "verified": cached["verified"],
            "supi": supi,
            "slice": cached.get("slice"),
            "cache_age_s": round(cache_age, 1),
            "latency_ms": latency
        }, status=status_code)
    else:
        await run_did_verification(supi)
        result = did_cache.get(supi, {"verified": False, "latency_ms": 0})
        latency = int((time.time() - t_start) * 1000)
        status_code = 200 if result["verified"] else 403
        return web.json_response({
            "status": "ok" if result["verified"] else "fail",
            "verified": result["verified"],
            "supi": supi,
            "slice": result.get("slice"),
            "latency_ms": latency
        }, status=status_code)


async def handle_health(request):
    return web.json_response({"status": "ok", "cached_supis": list(did_cache.keys())})

async def handle_cache(request):
    return web.json_response(did_cache)

app = web.Application()
app.router.add_post("/did-auth", handle_did_auth)
app.router.add_get("/health", handle_health)
app.router.add_get("/cache", handle_cache)

if __name__ == "__main__":
    log.info("Starting DID Auth Sidecar v2.0 on port 5000...")
    web.run_app(app, host="127.0.0.1", port=5000)
