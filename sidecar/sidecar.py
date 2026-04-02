#!/usr/bin/env python3
"""
DID Authentication Sidecar v4.0
- Configurable via CLI flags and environment variables
- Separated decision logic (proof_verified, revocation_ok, policy_allowed)
- Fail-close by default
- Structured JSON logging
- Latency breakdown per component
- Stage 3: --ledger, --cache, --fail-mode, --verifier-url flags
"""
import asyncio
import time
import logging
import json
import argparse
import os
from aiohttp import web, ClientSession, ClientTimeout

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s', force=True)
log = logging.getLogger(__name__)

# ── CLI / ENV configuration ───────────────────────────────
def parse_args():
    parser = argparse.ArgumentParser(description="DID Auth Sidecar v4.0")
    parser.add_argument("--fail-mode", choices=["open","close"],
                        default=os.environ.get("FAIL_MODE","close"),
                        help="Fail open or closed when sidecar errors (default: close)")
    parser.add_argument("--cache", choices=["on","off"],
                        default=os.environ.get("CACHE_MODE","on"),
                        help="Enable or disable result caching (default: on)")
    parser.add_argument("--cache-ttl", type=int,
                        default=int(os.environ.get("CACHE_TTL","300")),
                        help="Cache TTL in seconds (default: 300)")
    parser.add_argument("--ledger", choices=["local","bcovrin","any"],
                        default=os.environ.get("LEDGER_MODE","local"),
                        help="Ledger mode — affects cred def used (default: local)")
    parser.add_argument("--verifier-url",
                        default=os.environ.get("VERIFIER_URL","http://localhost:8041"),
                        help="ACA-Py verifier admin URL")
    parser.add_argument("--holder-url",
                        default=os.environ.get("HOLDER_URL","http://localhost:8031"),
                        help="ACA-Py holder admin URL")
    parser.add_argument("--port", type=int,
                        default=int(os.environ.get("SIDECAR_PORT","5000")),
                        help="Port to listen on (default: 5000)")
    return parser.parse_args()

ARGS = parse_args()

FAIL_OPEN     = (ARGS.fail_mode == "open")
CACHE_ENABLED = (ARGS.cache == "on")
CACHE_TTL     = ARGS.cache_ttl
VERIFIER_URL  = ARGS.verifier_url
HOLDER_URL    = ARGS.holder_url
LEDGER_MODE   = ARGS.ledger

# ── Ledger-specific credential config ─────────────────────
LEDGER_CONFIG = {
    "local": {
        "cred_def_id":   "YbmLV9CGCk8Uq1NAJqvD77:3:CL:9:revocable2",
        "verifier_conn": "e546aae9-6ad5-4f32-b129-53cb28b5ec68",
        "supi_cred_map": {
            "imsi-001010000000001": "9c69c256-d701-484c-a588-77ec36ef42bc",  # rev_id=2
            "imsi-001010000000002": "7d7bcb6e-b700-4c9a-9887-8239545afb96",  # rev_id=4
            "imsi-001010000000003": "9845b976-450f-4317-963c-6284ab5ba796",  # rev_id=6
            "imsi-001010000000004": "bda892cd-f365-46f1-9652-aeb6c71ed721",  # rev_id=3
            "imsi-001010000000005": "5fcbd8a0-6c04-405b-852f-5330fa964eb9",  # rev_id=1
            "imsi-001010000000006": "dad066ed-2e2a-4ffa-8467-d62eefdd41c3",  # rev_id=5 SST:2 -> DENY
        }
    },
    "bcovrin": {
        "cred_def_id":   "QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable",
        "verifier_conn": "4a229530-2c7c-4202-a762-f3c84bcfa45e",
        "supi_cred_map": {
            "imsi-001010000000001": "ce8e519e-2022-482a-919f-02646493f73c",  # rev_id=39, REVOKED
            "imsi-001010000000002": "40dd6224-bb79-4350-8953-8e257d63db31",  # rev_id=33
            "imsi-001010000000003": "30a67241-eba2-47d9-838e-8252b351a66d",  # rev_id=34
            "imsi-001010000000004": "1ab7dcfc-4eb6-4318-a8b7-311b3bc47723",  # rev_id=35
            "imsi-001010000000005": "ee84735e-5282-4f46-9353-64aac032072f",  # rev_id=36
            "imsi-001010000000006": "95d3fb40-e671-4347-a2d4-973d2a89fef4",  # rev_id=38, SST:2
        }
    }
}

# Use local config as default, fallback to bcovrin
_cfg = LEDGER_CONFIG.get(LEDGER_MODE, LEDGER_CONFIG["local"])
CRED_DEF_ID   = _cfg["cred_def_id"]
VERIFIER_CONN = _cfg["verifier_conn"]
SUPI_CRED_MAP = _cfg["supi_cred_map"]

# ── Extended Policy Rules ─────────────────────────────────
# Per-SUPI policy: required_slice, required_type, trusted_issuers
# Any attribute mismatch → policy_allowed=False with specific reason
POLICY_RULES = {
    "imsi-001010000000001": {
        "required_slice":   "SST:1",
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
    "imsi-001010000000002": {
        "required_slice":   "SST:1",
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
    "imsi-001010000000003": {
        "required_slice":   "SST:1",
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
    "imsi-001010000000004": {
        "required_slice":   "SST:1",
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
    "imsi-001010000000005": {
        "required_slice":   "SST:1",
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
    "imsi-001010000000006": {
        "required_slice":   "SST:1",   # has SST:2 cred -> DENY
        "required_type":    "5G-SA",
        "trusted_issuers":  ["MNO-Open5GS", "MNO-Local"],
    },
}

# Backward-compatible helper
def get_policy(supi):
    return POLICY_RULES.get(supi, {
        "required_slice":  "SST:1",
        "required_type":   "5G-SA",
        "trusted_issuers": ["MNO-Open5GS", "MNO-Local"],
    })

BLOCKED_SUPIS_FILE = "/var/tmp/blocked_ues.txt"
UE_IP_MAP_FILE     = "/var/tmp/ue_ip_map.txt"

_global_proof_semaphore = None

def get_semaphore():
    global _global_proof_semaphore
    if _global_proof_semaphore is None:
        _global_proof_semaphore = asyncio.Semaphore(1)
    return _global_proof_semaphore

def update_enforcement_files(supi, final_decision):
    try:
        try:
            blocked = set(open(BLOCKED_SUPIS_FILE).read().splitlines())
        except FileNotFoundError:
            blocked = set()
        if not final_decision:
            blocked.add(supi)
        else:
            blocked.discard(supi)
        with open(BLOCKED_SUPIS_FILE, 'w') as f:
            f.write('\n'.join(sorted(blocked)) + ('\n' if blocked else ''))
        log.info(f"[ENFORCE] {'BLOCKED' if not final_decision else 'UNBLOCKED'} {supi} -> {BLOCKED_SUPIS_FILE}")
    except Exception as e:
        log.error(f"[ENFORCE] Failed to update enforcement files: {e}")

did_cache = {}

def structured_log(supi, decision, reason, proof_verified, revocation_ok,
                   policy_allowed, slice_value, cache_hit, timings):
    entry = {
        "ts":             time.strftime("%Y-%m-%dT%H:%M:%S"),
        "supi":           supi,
        "final_decision": decision,
        "reason":         reason,
        "proof_verified": proof_verified,
        "revocation_ok":  revocation_ok,
        "policy_allowed": policy_allowed,
        "slice":          slice_value,
        "cache_hit":      cache_hit,
        "timings_ms":     timings,
        "config": {
            "ledger":    LEDGER_MODE,
            "cache":     CACHE_ENABLED,
            "fail_mode": "open" if FAIL_OPEN else "close",
        }
    }
    log.info(f"[AUTH] {json.dumps(entry)}")
    return entry

async def run_did_verification(supi):
    async with get_semaphore():
        await _run_did_verification_inner(supi)

async def _run_did_verification_inner(supi):
    t_total_start = time.time()
    timings = {}

    cred_ref       = SUPI_CRED_MAP.get(supi)
    # Policy loaded per-request via get_policy(supi)

    proof_verified    = False
    revocation_ok     = False
    policy_allowed    = False
    slice_value       = None
    type_value        = None
    issuer_value      = None
    policy_deny_reason = None
    reason            = "unknown_error"

    if not cred_ref:
        reason = "no_credential_mapped"
        _store_cache(supi, False, proof_verified, revocation_ok, policy_allowed,
                     slice_value, reason, timings, t_total_start)
        return

    timeout = ClientTimeout(total=30)
    try:
        async with ClientSession(timeout=timeout) as session:

            # Step 1: Send proof request
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

            # Step 2: Holder responds
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

            # Step 3: Verify presentation
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
                            proof_verified = vd.get("verified") == True or vd.get("verified") == "true"
                            revocation_ok  = proof_verified
                            try:
                                revealed     = vd["presentation"]["requested_proof"]["revealed_attrs"]
                                slice_value  = revealed["slice_attr"]["raw"]
                                type_value   = revealed.get("type_attr",  {}).get("raw")
                                issuer_value = revealed.get("issuer_attr",{}).get("raw")
                            except Exception:
                                slice_value  = None
                                type_value   = None
                                issuer_value = None

                            # Extended policy: slice + type + issuer trust
                            pol        = get_policy(supi)
                            slice_ok   = (slice_value  == pol["required_slice"])
                            type_ok    = (type_value   is None or type_value  == pol["required_type"])
                            issuer_ok  = (issuer_value is None or issuer_value in pol["trusted_issuers"])
                            policy_allowed = slice_ok and type_ok and issuer_ok

                            # Store which check failed for reason field
                            if not slice_ok:
                                policy_deny_reason = f"slice_policy_denied: got={slice_value} required={pol['required_slice']}"
                            elif not type_ok:
                                policy_deny_reason = f"type_policy_denied: got={type_value} required={pol['required_type']}"
                            elif not issuer_ok:
                                policy_deny_reason = f"issuer_not_trusted: issuer={issuer_value} not in {pol['trusted_issuers']}"
                            else:
                                policy_deny_reason = None
                        break
                await asyncio.sleep(1)
            timings["verification_ms"] = int((time.time() - t0) * 1000)

            # Final decision
            if not proof_verified:
                reason = "proof_verification_failed"
            elif not revocation_ok:
                reason = "credential_revoked"
            elif not policy_allowed:
                reason = policy_deny_reason or "policy_denied"
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
        _store_cache(supi, FAIL_OPEN, False, False, False, None, reason, timings, t_total_start)

def _store_cache(supi, final_decision, proof_verified, revocation_ok,
                 policy_allowed, slice_value, reason, timings, t_start):
    if CACHE_ENABLED:
        did_cache[supi] = {
            "final_decision": final_decision,
            "proof_verified": proof_verified,
            "revocation_ok":  revocation_ok,
            "policy_allowed": policy_allowed,
            "slice":          slice_value,
            "reason":         reason,
            "timings_ms":     timings,
            "timestamp":      time.time(),
            "latency_ms":     timings.get("total_ms", int((time.time() - t_start) * 1000))
        }
    structured_log(supi, final_decision, reason, proof_verified, revocation_ok,
                   policy_allowed, slice_value, False, timings)
    update_enforcement_files(supi, final_decision)

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

    # Check cache
    if CACHE_ENABLED:
        cached   = did_cache.get(supi)
        cache_age = time.time() - cached["timestamp"] if cached else 999
        if cached and cache_age < CACHE_TTL:
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
                "revocation_ok":  cached["revocation_ok"],
                "policy_allowed": cached["policy_allowed"],
                "reason":         cached["reason"],
                "supi":           supi,
                "slice":          cached.get("slice"),
                "cache_hit":      True,
                "cache_age_s":    round(cache_age, 1),
                "timings_ms":     cached.get("timings_ms", {}),
                "latency_ms":     latency
            }, status=status_code)

    await run_did_verification(supi)
    result = did_cache.get(supi) if CACHE_ENABLED else None

    # If cache disabled, result is in a temp dict
    if not result:
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
        "revocation_ok":  result["revocation_ok"],
        "policy_allowed": result["policy_allowed"],
        "reason":         result["reason"],
        "supi":           supi,
        "slice":          result.get("slice"),
        "cache_hit":      False,
        "timings_ms":     result.get("timings_ms", {}),
        "latency_ms":     latency
    }, status=status_code)

async def handle_health(request):
    return web.json_response({
        "status":       "ok",
        "version":      "4.0",
        "ledger":       LEDGER_MODE,
        "fail_mode":    "open" if FAIL_OPEN else "close",
        "cache":        "on" if CACHE_ENABLED else "off",
        "cache_ttl_s":  CACHE_TTL,
        "verifier_url": VERIFIER_URL,
        "cred_def_id":  CRED_DEF_ID,
        "cached_supis": list(did_cache.keys())
    })

async def handle_cache_view(request):
    return web.json_response(did_cache)

async def handle_cache_clear(request):
    did_cache.clear()
    return web.json_response({"status": "cache cleared"})

app = web.Application()
app.router.add_post("/did-auth",     handle_did_auth)
app.router.add_get("/health",        handle_health)
app.router.add_get("/cache",         handle_cache_view)
app.router.add_post("/cache/clear",  handle_cache_clear)

if __name__ == "__main__":
    log.info(f"Starting DID Auth Sidecar v4.0 on port {ARGS.port}")
    log.info(f"Ledger:    {LEDGER_MODE}")
    log.info(f"Fail mode: {'open' if FAIL_OPEN else 'close'}")
    log.info(f"Cache:     {'on' if CACHE_ENABLED else 'off'} (TTL={CACHE_TTL}s)")
    log.info(f"Verifier:  {VERIFIER_URL}")
    web.run_app(app, host="127.0.0.1", port=ARGS.port)
