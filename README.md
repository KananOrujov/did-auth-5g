# DID-Based Identity Management for 5G Networks

MSc Thesis Implementation — "On the Decentralization of Identity Management in B5G Networks"  
ELTE Faculty of Informatics | Supervisor: Dr. Mohammed B. Alshawki | Author: Kanan Orujov

## Overview

This repository contains the full implementation of a decentralized identity management system integrated into a 5G Standalone (SA) core network using Self-Sovereign Identity (SSI) principles.

**Stack:**
- Open5GS v2.7.6 (5G SA core)
- UERANSIM v3.2.7 (gNB + UE simulator)
- ACA-Py 1.0.1 (SSI agents)
- BCovrin Test Ledger (Hyperledger Indy)

## Architecture
```
UE → gNB → AMF → AUSF (C patch) → Sidecar (Python) → ACA-Py Verifier → Ledger
```

The AUSF is patched to call a Python sidecar via HTTP before completing 5G-AKA authentication. The sidecar requests a Verifiable Credential (VC) proof from the UE's holder agent, verifies it against the ledger (including revocation and network slice checks), and returns allow/deny to the AUSF.

## Repository Structure
```
sidecar/           # DID auth sidecar (v2.0) with slice enforcement
scripts/           # Startup scripts for agents and demo
ausf-patch/        # Modified nudm-handler.c for Open5GS AUSF
config/            # UERANSIM gNB and UE config files
evaluation/        # Evaluation scripts
  latency_test.py      # Full verification latency (n runs)
  throughput_test.py   # Cache-hit throughput measurement
  revocation_test.py   # Revocation lifecycle test
  multi_ue_test.py     # Multi-UE sequential + concurrent test
thesis-results.txt # Raw experimental results
```

## Key Results

| Metric | Result |
|--------|--------|
| DID proof verification latency | min 2708ms, max 5517ms, avg ~4000ms |
| Cache-hit latency | ~0ms |
| Cache-hit throughput | 230 req/s |
| Revocation enforcement | ✓ (verified=False on revoked credential) |
| Network slice enforcement | ✓ (SST:1 checked in proof) |
| Multi-UE sequential (5 UEs) | all verified=True, avg 3516ms |

## Setup

### Prerequisites
- Open5GS v2.7.6 compiled from source
- UERANSIM v3.2.7
- Python 3.13 + ACA-Py 1.0.1
- MongoDB
- tails-server

### Start Full Stack
```bash
# 1. Start Open5GS
bash /home/kali/open5gs/start-open5gs.sh

# 2. Start tails server
tails-server --host 0.0.0.0 --port 6543 --storage-path /home/kali/tails-files &

# 3. Start ACA-Py agents
bash scripts/start-issuer.sh &
bash scripts/start-holder.sh &
bash scripts/start-verifier.sh &

# 4. Start sidecar
python3 sidecar/sidecar.py &

# 5. Start UERANSIM
nr-gnb -c config/open5gs-gnb.yaml &
nr-ue -c config/open5gs-ue.yaml &
```

### Run Demo
```bash
bash scripts/run-demo.sh
```

### Run Evaluation
```bash
cd evaluation
python3 latency_test.py 10
python3 throughput_test.py 20
python3 revocation_test.py
python3 multi_ue_test.py
```

## AUSF Patch

The patch adds a `did_auth_check()` call in `nudm-handler.c` that POSTs the SUPI to the sidecar at `http://127.0.0.1:5000/did-auth`. On HTTP 200 the authentication proceeds; on 403 or timeout (500ms) it fails open (allows) to preserve 5G-AKA compatibility.

## Ledger & Credentials

- **Ledger:** BCovrin Test (http://test.bcovrin.vonx.io)
- **Issuer DID:** `QTbY98psM6bDviJj9A6JLU`
- **Schema:** `QTbY98psM6bDviJj9A6JLU:2:5g-subscriber:1.0`
- **Cred Def:** `QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable`

## License

MIT
