# DID-Based Identity Management for 5G Networks

**MSc Thesis Implementation**
*"On the Decentralization of Identity Management in B5G Networks"*
ELTE Faculty of Informatics | Supervisor: Dr. Mohammed B. Alshawki | Author: Kanan Orujov

---

## Overview

This repository contains the full implementation of a decentralized identity management system integrated into a 5G Standalone (SA) core network using Self-Sovereign Identity (SSI) principles.

The system integrates DID-based authentication directly into the 5G AUSF (Authentication Server Function), enforcing credential verification, revocation checking, and network slice policy before allowing UE registration.

---

## Stack

| Component | Version |
|---|---|
| Open5GS | v2.7.6 (5G SA core) |
| UERANSIM | v3.2.7 (gNB + UE simulator) |
| ACA-Py | 1.0.1 (SSI agents) |
| BCovrin Test Ledger | Hyperledger Indy |
| Python | 3.13 |

---

## Architecture
```
UE → gNB → AMF → AUSF (C patch) → Sidecar (Python v3.1) → ACA-Py Verifier → BCovrin Ledger
                                        ↓
                               blocked_ues.txt
                                        ↓
                            upf_enforcer.sh → iptables DID_BLOCK
```

### Authentication Flow

1. UE sends Registration Request to AMF
2. AMF forwards to AUSF for 5G-AKA
3. AUSF patch calls sidecar at `http://127.0.0.1:5000/did-auth` with SUPI
4. Sidecar sends proof request to ACA-Py Verifier
5. Holder agent presents Verifiable Credential proof
6. Verifier checks: cryptographic validity + revocation status + network slice policy
7. Sidecar returns structured decision to AUSF:
   - HTTP 200 → `final_decision: true` → authentication proceeds
   - HTTP 403 → `final_decision: false` → AUSF rejects with Registration Reject
8. On deny: sidecar writes SUPI to `blocked_ues.txt`
9. `upf_enforcer.sh` instantly applies iptables DROP rules via inotifywait

---

## Repository Structure
```
sidecar/
  sidecar.py              # DID auth sidecar v3.1 - structured logging,
                          # fail-close, separated decision logic,
                          # latency breakdown, iptables enforcement trigger

scripts/
  start-issuer.sh         # ACA-Py issuer agent
  start-holder.sh         # ACA-Py holder agent
  start-verifier.sh       # ACA-Py verifier agent
  ue_ip_map.sh            # SUPI->IP mapper (watches SMF logs)
  upf_enforcer.sh         # UPF iptables enforcer v3.1 (inotifywait)

ausf-patch/
  nudm-handler.c          # Modified AUSF with DID auth check,
                          # 15s timeout, strict fail-close

config/
  open5gs-gnb.yaml        # UERANSIM gNB config
  open5gs-ue.yaml         # UERANSIM UE config

evaluation/
  run_experiments.py      # Master experiment runner (all experiments)
  latency_comparison.py   # Vanilla vs DID latency comparison
  multi_ue_test.py        # Multi-UE sequential + concurrent
  revocation_test.py      # Revocation enforcement test
  revocation_under_load.py
  results/                # Structured CSV + JSON experiment results

thesis-results.txt        # Raw experimental results log
```

---

## Sidecar Decision Logic (v3.1)

Every authentication returns a structured JSON response:
```json
{
  "final_decision": true,
  "proof_verified": true,
  "revocation_ok": true,
  "policy_allowed": true,
  "reason": "all_checks_passed",
  "supi": "imsi-001010000000001",
  "slice": "SST:1",
  "cache_hit": false,
  "timings_ms": {
    "proof_request_ms": 341,
    "holder_response_ms": 1692,
    "verification_ms": 2407,
    "total_ms": 4443
  }
}
```

Deny reasons:
- `proof_verification_failed` — credential revoked or invalid
- `slice_policy_denied: got=SST:2 required=SST:1` — wrong network slice
- `sidecar_error: ...` — verifier unreachable (fail-close)
- `no_credential_mapped` — unknown SUPI

---

## UPF Enforcement

When a UE is denied, traffic is blocked at two layers:

**Layer 1 — Control plane (AUSF):**
- AUSF returns failure to AMF
- AMF sends `Registration Reject` to UE
- UE never gets a PDU session

**Layer 2 — User plane (iptables):**
- Sidecar writes denied SUPI to `/var/tmp/blocked_ues.txt`
- `ue_ip_map.sh` maps SUPI → UE IP from SMF logs
- `upf_enforcer.sh` uses inotifywait for instant rule application
- iptables `DID_BLOCK` chain drops all traffic to/from denied UE IP
```bash
# Verified blocking:
# ICMP: 100% packet loss
# TCP: connection refused/timeout
# Unblock: rules removed instantly on file change
```

---

## Ledger & Credentials

| Item | Value |
|---|---|
| Ledger | BCovrin Test (http://test.bcovrin.vonx.io) |
| Issuer DID | `QTbY98psM6bDviJj9A6JLU` |
| Schema | `QTbY98psM6bDviJj9A6JLU:2:5g-subscriber:1.0` |
| Cred Def (revocable) | `QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable` |
| Rev Reg | `QTbY98psM6bDviJj9A6JLU:4:...:CL_ACCUM:55375973-...` |

### Credential Attributes
- `supi` — full SUPI (e.g. `imsi-001010000000001`)
- `imsi` — IMSI number
- `network_slice` — slice identifier (e.g. `SST:1`)
- `subscription_type` — e.g. `5G-SA`
- `issued_by` — operator identifier

---

## Setup

### Prerequisites
- Open5GS v2.7.6 compiled from source
- UERANSIM v3.2.7
- Python 3.13 + ACA-Py 1.0.1
- MongoDB
- inotify-tools (`apt install inotify-tools`)

### AUSF Patch

The AUSF patch adds `did_auth_check()` in `nudm-handler.c`:
- Timeout: 15000ms (fail-close on timeout)
- On HTTP 200: authentication proceeds
- On HTTP 403 or timeout: AUSF rejects → Registration Reject
```bash
# Compile patched AUSF
cd /home/kali/open5gs
ninja -C build src/ausf/open5gs-ausfd

# Start script uses patched binary automatically
bash /home/kali/open5gs/start-open5gs.sh
```

### Start Full Stack
```bash
# 1. Start Open5GS (uses patched AUSF automatically)
bash /home/kali/open5gs/start-open5gs.sh

# 2. Start ACA-Py agents
bash scripts/start-issuer.sh &
bash scripts/start-holder.sh &
bash scripts/start-verifier.sh &

# 3. Start sidecar
cd /home/kali/did-auth-5g
python3 sidecar/sidecar.py &

# 4. Start UPF enforcement
bash scripts/ue_ip_map.sh &
bash scripts/upf_enforcer.sh &

# 5. Start UERANSIM
/home/kali/UERANSIM/build/nr-gnb -c config/open5gs-gnb.yaml &
/home/kali/UERANSIM/build/nr-ue -c config/open5gs-ue.yaml &
```

---

## Run Experiments
```bash
cd evaluation

# Run all experiments (produces CSV + JSON in results/)
python3 run_experiments.py

# Individual experiments
python3 latency_comparison.py   # Vanilla vs DID latency
python3 multi_ue_test.py        # Multi-UE test
python3 revocation_test.py      # Revocation enforcement
```

---

## Key Experimental Results

| Metric | Result |
|---|---|
| Vanilla 5G auth latency | avg 256ms |
| DID cold verification latency | avg 4653ms |
| DID warm (cache hit) latency | ~0ms |
| DID overhead vs vanilla | ~+4400ms |
| Revocation enforcement | Confirmed (proof_verified=false) |
| Slice policy enforcement | Confirmed (HTTP 403 on wrong slice) |
| Fail-close on verifier down | Confirmed (sidecar_error → deny) |
| Multi-UE sequential (4 UEs) | All verified=True, avg ~3775ms |
| Concurrent UEs (4 UEs) | All verified=True, wall=11609ms |
| Edge simulation (50ms RTT) | +1000ms overhead |
| ICMP blocking (iptables) | 100% packet loss confirmed |
| TCP blocking (iptables) | Confirmed |
| Instant unblock | Confirmed (<1s via inotifywait) |

---

## SUPI Credential Map

| SUPI | Cred Ref | Slice | Status |
|---|---|---|---|
| imsi-001010000000001 | ce8e519e-... | SST:1 | revoked (test) |
| imsi-001010000000002 | 40dd6224-... | SST:1 | active |
| imsi-001010000000003 | 30a67241-... | SST:1 | active |
| imsi-001010000000004 | 1ab7dcfc-... | SST:1 | active |
| imsi-001010000000005 | ee84735e-... | SST:1 | active |
| imsi-001010000000006 | 95d3fb40-... | SST:2 | active (deny test) |
