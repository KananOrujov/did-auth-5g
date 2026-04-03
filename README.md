# DID-Based Identity Management for 5G Networks

**MSc Thesis Implementation**
*"On the Decentralization of Identity Management in B5G Networks"*
ELTE Faculty of Informatics | Supervisor: Dr. Mohammed B. Alshawki | Author: Kanan Orujov

---

## Overview

This repository contains the full implementation of a decentralized identity management system integrated into a 5G Standalone (SA) core network using Self-Sovereign Identity (SSI) principles.

The system integrates DID-based authentication directly into the 5G AUSF (Authentication Server Function), enforcing credential verification, revocation checking, and network slice policy before allowing UE registration. The implementation supports both a public BCovrin ledger and a local von-network Hyperledger Indy ledger.

---

## Stack

| Component | Version | Role |
|---|---|---|
| Open5GS | v2.7.6 | 5G SA core network |
| UERANSIM | v3.2.7 | gNB + UE simulator |
| ACA-Py | 1.0.1 | SSI agents (Issuer, Holder, Verifier) |
| Hyperledger Indy | von-network | Local distributed ledger |
| BCovrin Test | Public | Public Hyperledger Indy ledger |
| Python | 3.13 | DID Auth Sidecar v4.2 |
| Docker | 27.5.1 | von-network containerized ledger |

---

## Architecture
UE → gNB → AMF → AUSF (C patch) → Sidecar (Python v4.2) → ACA-Py Verifier → Indy Ledger
↓
blocked_ues.txt
↓
upf_enforcer.sh → iptables DID_BLOCK

### Authentication Flow

1. UE sends Registration Request to AMF
2. AMF forwards to AUSF for 5G-AKA
3. **AUSF C patch** calls sidecar at `http://127.0.0.1:5000/did-auth` with SUPI
4. Sidecar performs **revocation pre-check** (skips proof if already known revoked — ~75ms)
5. Sidecar sends proof request to ACA-Py Verifier
6. Holder agent presents Verifiable Credential proof (ZKP — reveals only SUPI, IMSI, slice)
7. Verifier checks: cryptographic validity + revocation status + network slice + issuer trust
8. Sidecar returns structured decision to AUSF:
   - HTTP 200 → `final_decision: true` → authentication proceeds
   - HTTP 403 → `final_decision: false` → AUSF rejects with Registration Reject
9. On deny: sidecar writes SUPI to `blocked_ues.txt`
10. `upf_enforcer.sh` instantly applies iptables DROP rules via inotifywait

---

## Repository Structure
sidecar/
sidecar.py              # DID auth sidecar v4.2
# Configurable: --ledger, --cache, --fail-mode, --port
# Features: dynamic wallet lookup, revocation pre-check,
# extended policy (slice+type+issuer), load protection,
# structured JSON logging, latency breakdown
scripts/
start-full-stack.sh     # ONE-COMMAND full stack startup (bcovrin or local mode)
setup_credentials.py    # Auto setup: connections + issue + store + sidecar update
start-local-ledger.sh   # Start von-network local Indy ledger
start-issuer.sh         # ACA-Py issuer agent (BCovrin)
start-holder.sh         # ACA-Py holder agent (BCovrin)
start-verifier.sh       # ACA-Py verifier agent (BCovrin)
start-issuer-local.sh   # ACA-Py issuer agent (local ledger)
start-holder-local.sh   # ACA-Py holder agent (local ledger)
start-verifier-local.sh # ACA-Py verifier agent (local ledger)
ue_ip_map.sh            # SUPI→IP mapper (watches SMF logs)
upf_enforcer.sh         # UPF iptables enforcer v3.1 (inotifywait)
ausf-patch/
nudm-handler.c          # Modified AUSF: DID auth check, 15s timeout,
# fail-close, 30s in-memory cache (C-level)
config/
open5gs-gnb.yaml        # UERANSIM gNB config
open5gs-ue.yaml         # UERANSIM UE config
evaluation/
concurrent_stress_test.py  # Concurrent UE stress test (2/4/5/10 UEs)
security_tests.py          # Security evaluation (5 attack scenarios)
latency_comparison.py      # Vanilla vs DID latency
multi_ue_test.py           # Multi-UE sequential + concurrent
revocation_test.py         # Revocation enforcement
run_experiments.py         # Master experiment runner
results/                   # All CSV + JSON experiment results
thesis-results.txt           # Raw experimental results log

---

## Quick Start

### Option A: BCovrin Public Ledger (internet required)
```bash
bash scripts/start-full-stack.sh bcovrin
```

### Option B: Local Ledger (offline, faster)
```bash
# Start local Indy ledger (Docker required)
bash scripts/start-local-ledger.sh

# Start full stack in local mode
bash scripts/start-full-stack.sh local

# First time only: setup credentials
python3 scripts/setup_credentials.py local
```

### Test Authentication
```bash
# Allow case
curl -s -X POST http://localhost:5000/did-auth \
  -H "Content-Type: application/json" \
  -d '{"supi":"imsi-001010000000002"}' | python3 -m json.tool

# Check health + config
curl -s http://localhost:5000/health | python3 -m json.tool
```

---

## Sidecar v4.2 — Configuration
```bash
python3 sidecar/sidecar.py \
  --ledger    local|bcovrin  # Ledger mode (default: local)
  --cache     on|off         # Result caching (default: on)
  --cache-ttl 300            # Cache TTL in seconds (default: 300)
  --fail-mode close|open     # Fail-close or fail-open (default: close)
  --port      5000           # Port (default: 5000)
```

### Decision Response
```json
{
  "final_decision": true,
  "proof_verified": true,
  "revocation_ok": true,
  "policy_allowed": true,
  "reason": "all_checks_passed",
  "supi": "imsi-001010000000002",
  "slice": "SST:1",
  "cache_hit": false,
  "timings_ms": {
    "proof_request_ms": 120,
    "holder_response_ms": 1358,
    "verification_ms": 1181,
    "total_ms": 2658
  },
  "config": {
    "ledger": "local",
    "cache": true,
    "fail_mode": "close"
  }
}
```

### Deny Reasons

| Reason | Cause |
|---|---|
| `proof_verification_failed` | Credential invalid or revoked |
| `credential_revoked_precheck` | Revoked — detected before proof (fast path) |
| `slice_policy_denied: got=X required=Y` | Wrong network slice |
| `type_policy_denied: got=X required=Y` | Wrong subscription type |
| `issuer_not_trusted: issuer=X` | Untrusted credential issuer |
| `no_credential_mapped` | Unknown SUPI |
| `sidecar_error: ...` | Verifier unreachable (fail-close) |

---

## AUSF C Patch

The patch adds `did_auth_check()` in `nudm-handler.c`:

| Parameter | Value | Purpose |
|---|---|---|
| `DID_TIMEOUT_MS` | 15,000ms | Total sidecar call timeout |
| `DID_CONNECT_TIMEOUT_MS` | 500ms | Connection timeout |
| `DID_CACHE_TTL_SEC` | 30s | C-level result cache TTL |
| `DID_CACHE_SIZE` | 16 entries | Max cached SUPIs |
| `DID_FAIL_OPEN` | 0 (false) | **Fail-close** — deny on any error |
```bash
# Compile patched AUSF
cd /home/kali/open5gs
ninja -C build src/ausf/open5gs-ausfd
```

---

## UPF Enforcement

When a UE is denied, traffic is blocked at two independent layers:

**Layer 1 — Control plane (AUSF):**
- AUSF returns HTTP 403 FORBIDDEN to AMF
- AMF sends `Registration Reject [111]` to UE
- UE is ejected from the core network

**Layer 2 — User plane (iptables):**
- Sidecar writes denied SUPI to `/var/tmp/blocked_ues.txt`
- `ue_ip_map.sh` maps SUPI → IP from SMF logs
- `upf_enforcer.sh` uses inotifywait — instant rule application < 1 second
- iptables `DID_BLOCK` chain drops all ICMP + TCP traffic
Verified:
ICMP → 100% packet loss
TCP  → connection timeout
Unblock → rules removed instantly on file change

---

## Ledger Configuration

### Local Ledger (Stage 3 — Recommended)

| Item | Value |
|---|---|
| Ledger | von-network (localhost:9000) |
| Issuer DID | `YbmLV9CGCk8Uq1NAJqvD77` |
| Schema | `YbmLV9CGCk8Uq1NAJqvD77:2:5g-subscriber:1.0` |
| Cred Def | `YbmLV9CGCk8Uq1NAJqvD77:3:CL:9:revocable2` |

### BCovrin Public Ledger (Stage 2)

| Item | Value |
|---|---|
| Ledger | BCovrin Test (http://test.bcovrin.vonx.io) |
| Issuer DID | `QTbY98psM6bDviJj9A6JLU` |
| Schema | `QTbY98psM6bDviJj9A6JLU:2:5g-subscriber:1.0` |
| Cred Def | `QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable` |

### Credential Attributes

| Attribute | Example | Purpose |
|---|---|---|
| `supi` | `imsi-001010000000002` | UE identity |
| `imsi` | `001010000000002` | Network identifier |
| `network_slice` | `SST:1` | Slice entitlement |
| `subscription_type` | `5G-SA` | Service type |
| `issued_by` | `MNO-Local` | Issuer identifier |

---

## Experimental Results

### Latency

| Metric | BCovrin | Local Ledger |
|---|---|---|
| DID cold (min) | 4,396ms | 2,421ms |
| DID cold (avg) | 4,690ms | 2,658ms |
| DID cold (max) | 5,181ms | 3,069ms |
| DID warm (cache) | ~0ms | ~0ms |
| Vanilla 5G auth | 256ms | 256ms |
| Ledger RTT overhead | +2,033ms vs local | baseline |
| Local ledger speedup | — | **1.8x faster** |

### Revocation Pre-check

| Scenario | Latency |
|---|---|
| Full proof (active credential) | ~2,658ms |
| Revocation pre-check (revoked) | **75ms** |
| Speedup | **35x faster** |

### Concurrent UE Stress Test

| Test | Wall Time | Success Rate |
|---|---|---|
| 2 UEs cold | 10,145ms | 2/2 |
| 4 UEs cold | 5,128ms | 4/4 |
| 5 UEs warm (cache) | 25ms | 5/5 |
| 10 UEs warm (cache) | 34ms | 10/10 |

### Security Evaluation

| Attack | Result |
|---|---|
| Replay Attack | ✓ Mitigated — nonce-per-proof |
| Impersonation | ✓ Mitigated — credential binding |
| Revoked Credential | ✓ Mitigated — ledger revocation registry |
| Policy Bypass (slice) | ✓ Mitigated — cryptographic policy binding |
| DoS / Load Attack | ✓ Mitigated — queue limit + fail-close |

### All Confirmed Properties

| Property | Status |
|---|---|
| Fail-close on sidecar down | ✓ Confirmed |
| Revocation enforcement | ✓ Confirmed |
| Slice policy enforcement | ✓ Confirmed |
| Issuer trust enforcement | ✓ Confirmed |
| Traffic blocking (ICMP+TCP) | ✓ Confirmed |
| Instant block/unblock (<1s) | ✓ Confirmed |
| Minimal credential disclosure | ✓ By design (ZKP) |
| Dynamic credential lookup | ✓ Confirmed |
| Load protection (MAX_QUEUE) | ✓ Confirmed |

---

## Run Experiments
```bash
cd evaluation

# Latency comparison (vanilla vs DID)
python3 latency_comparison.py

# Concurrent stress test
python3 concurrent_stress_test.py

# Security evaluation (5 attack scenarios)
python3 security_tests.py

# Revocation enforcement
python3 revocation_test.py

# Multi-UE test
python3 multi_ue_test.py
```

---

## B5G Alignment

| B5G Requirement | Our Implementation |
|---|---|
| Multi-stakeholder trust | Ledger-based verification — any operator verifies any credential |
| User-centric identity | UE holds credential in self-sovereign wallet |
| Zero-trust security | Fresh proof + revocation + policy check on every authentication |
| Decentralized control | Ledger replaces UDM/HSS as authentication authority |
| Policy-based slicing | Slice entitlement cryptographically bound in credential |
| Dynamic trust management | Real-time revocation via ledger registry |
