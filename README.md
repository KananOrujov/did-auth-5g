# DID-Based Identity Management for 5G Networks

MSc thesis implementation accompanying *On the Decentralization of Identity Management in B5G Networks* (ELTE Faculty of Informatics, 2026). This repository contains the full source code, deployment scripts, evaluation suite, and experimental results for a decentralized identity authentication layer integrated into a real 5G Standalone core network using Self-Sovereign Identity principles, Hyperledger Indy, and Aries Cloud Agent Python.

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Architecture](#architecture)
4. [Repository Structure](#repository-structure)
5. [Software Installation](#software-installation)
6. [Configuration](#configuration)
7. [Quick Start](#quick-start)
8. [Authentication Flow](#authentication-flow)
9. [Validation and Testing](#validation-and-testing)
10. [Experimental Results](#experimental-results)
11. [Security Properties](#security-properties)
12. [Troubleshooting](#troubleshooting)
13. [References](#references)

## Overview

The 5G Authentication and Key Agreement (5G-AKA) protocol authenticates devices through a centralized model in which every access decision depends on the home network operator's infrastructure. This creates scalability bottlenecks, single points of failure, high latency in distributed scenarios, and constrained privacy guarantees, limitations that become increasingly problematic as networks evolve toward Beyond Fifth Generation environments.

This project integrates Self-Sovereign Identity directly into the 5G AUSF (Authentication Server Function) by intercepting every UE registration attempt and delegating the identity verification decision to a Python sidecar before the standard 5G-AKA procedure continues. The sidecar coordinates a four-stage verification pipeline: dynamic credential lookup, revocation pre-check, DIDComm proof exchange using Anoncreds CL Zero-Knowledge Proofs, and extended policy evaluation covering network slice entitlement, subscription type, and issuer trust. Denied UEs are blocked at both the control plane through Registration Reject and the user plane through iptables rules applied within one second of denial.

## System Requirements

### Tested Specs

- OS: Kali Linux (kernel 6.x)
- CPU: 4 cores or more
- RAM: 8 GB minimum (16 GB recommended for concurrent stress tests)
- Disk: 20 GB free
- Network: localhost loopback only (no external connectivity required for local ledger mode)

### Required Software Versions

- Open5GS v2.7.6
- UERANSIM v3.2.7
- ACA-Py 1.0.1
- Python 3.13
- Docker 27.5.1
- MongoDB 6.x

## Architecture

### System Layers

The system consists of four concurrently operating layers: the 5G network layer (Open5GS core functions and UERANSIM), the DID sidecar layer (Python with aiohttp), the SSI agent layer (three ACA-Py agents (issuer, holder, verifier), each with its own Askar wallet), and the ledger layer (Hyperledger Indy via von-network or BCovrin).

### Component Diagram

The flow proceeds top-down from UE through the 5G core to the SSI layer:

- UE -> gNB -> AMF -> AUSF (C patch) -> Sidecar (Python v4.2)
- Sidecar fans out to three parallel checks: Wallet Query, Revocation Pre-check, Policy Evaluation
- Sidecar then drives DIDComm: ACA-Py Verifier <-> ACA-Py Holder
- Verifier consults Hyperledger Indy Ledger (von-network or BCovrin)
- Denial path: blocked_ues.txt -> upf_enforcer.sh -> iptables DID_BLOCK chain

### Software Stack

| Component | Version | Role |
|---|---|---|
| Open5GS | v2.7.6 | 5G SA core (AMF, SMF, UPF, AUSF, UDM, NRF, PCF) |
| UERANSIM | v3.2.7 | gNB + UE simulator |
| ACA-Py | 1.0.1 | SSI agents (Issuer, Holder, Verifier) |
| von-network | Docker | Local Hyperledger Indy ledger (4 nodes) |
| BCovrin Test | Public | Public Hyperledger Indy test ledger |
| Python | 3.13 | DID Authentication Sidecar v4.2 |
| Docker | 27.5.1 | Container runtime for von-network |
| MongoDB | 6.x | Open5GS subscriber profile storage |

## Repository Structure

### sidecar/

Contains the DID authentication orchestration layer.

- sidecar.py: DID auth sidecar v4.2, configurable via --ledger, --cache, --fail-mode, --port. Implements dynamic wallet lookup, revocation pre-check, extended policy evaluation, load protection, structured JSON logging, and per-stage latency breakdown.

### scripts/

Contains deployment, setup, and runtime helper scripts.

- start-full-stack.sh: one-command startup of the full stack (bcovrin or local mode)
- setup_credentials.py: automated setup, DIDComm connections, credential issuance, wallet storage, sidecar configuration update
- start-local-ledger.sh: start von-network local Indy ledger
- start-issuer.sh, start-holder.sh, start-verifier.sh: ACA-Py agents (BCovrin)
- start-issuer-local.sh, start-holder-local.sh, start-verifier-local.sh: ACA-Py agents (local ledger)
- ue_ip_map.sh: SUPI-to-IP mapper that watches SMF logs
- upf_enforcer.sh: UPF iptables enforcer v3.1 driven by inotifywait

### ausf-patch/

Contains the C-language patch to the Open5GS AUSF.

- nudm-handler.c: modified AUSF source with DID auth check, 15-second timeout, fail-close error handling, and a 30-second in-memory C-level decision cache.

### config/

UERANSIM configuration files.

- open5gs-gnb.yaml: gNB configuration
- open5gs-ue.yaml: UE configuration

### evaluation/

Experimental evaluation suite.

- concurrent_stress_test.py: concurrent UE stress test (2/4/5/10 UEs)
- security_tests.py: security evaluation across five attack scenarios
- latency_comparison.py: vanilla 5G-AKA vs DID-augmented latency comparison
- multi_ue_test.py: multi-UE sequential and concurrent tests
- revocation_test.py: revocation enforcement test
- run_experiments.py: master experiment runner
- results/: all CSV and JSON experiment outputs

### thesis-results.txt

Raw experimental results log captured during thesis evaluation runs.

## Software Installation

### 1. Operating System

Install Kali Linux or Ubuntu 22.04+ with kernel 6.x or newer. Ensure Docker, MongoDB, and Python 3.13 are available before proceeding.

### 2. Dependencies

Install Open5GS, UERANSIM, ACA-Py, and the Python packages required by the sidecar (aiohttp, async libraries). Refer to each upstream project's installation guide for platform-specific instructions.

### 3. Network Stack Components

Open5GS provides the 5G SA core. UERANSIM provides software-defined gNB and UE implementations. The three ACA-Py agents provide the SSI layer. Hyperledger Indy (via von-network or BCovrin) provides the distributed ledger.

### 4. AUSF Patch Compilation

Apply the patch in ausf-patch/nudm-handler.c to the Open5GS source tree, then rebuild with: cd /home/kali/open5gs && ninja -C build src/ausf/open5gs-ausfd

## Configuration

### AUSF Patch Parameters

| Parameter | Value | Purpose |
|---|---|---|
| DID_TIMEOUT_MS | 15000 | Total time allowed for sidecar response |
| DID_CONNECT_TIMEOUT_MS | 500 | TCP connection timeout |
| DID_CACHE_TTL_SEC | 30 | C-level SUPI decision cache TTL |
| DID_CACHE_SIZE | 16 | Maximum cached decisions |
| DID_FAIL_OPEN | 0 | Deny on any error (fail-close policy) |

### Sidecar Configuration

The sidecar accepts the following command-line flags: --ledger local or bcovrin, --cache on or off, --cache-ttl 300, --fail-mode close or open, --port 5000.

### Test UE Profiles

Six test UEs are provisioned in MongoDB, each covering a distinct decision path:

| SUPI | Slice | Status | Expected Decision |
|---|---|---|---|
| imsi-001010000000001 | SST:1 | Revoked | Deny: revocation pre-check |
| imsi-001010000000002 | SST:1 | Active | Allow |
| imsi-001010000000003 | SST:1 | Active | Allow |
| imsi-001010000000004 | SST:1 | Active | Allow |
| imsi-001010000000005 | SST:1 | Active | Allow |
| imsi-001010000000006 | SST:2 | Active | Deny: slice policy |

## Quick Start

### Option A: Local Ledger (recommended)

Run: bash scripts/start-full-stack.sh local, then python3 scripts/setup_credentials.py local.

### Option B: BCovrin Public Ledger

Run: bash scripts/start-full-stack.sh bcovrin, then python3 scripts/setup_credentials.py bcovrin.

### Sanity Check

After startup, verify the sidecar is healthy with: curl -s http://localhost:5000/health. Then test a valid UE registration: curl -s -X POST http://localhost:5000/did-auth -H "Content-Type: application/json" -d '{"supi":"imsi-001010000000002"}'. A successful response shows final_decision: true and a per-stage timing breakdown.

## Authentication Flow

1. UE sends NAS Registration Request to gNB.
2. gNB forwards to AMF over the N2 interface.
3. AMF invokes AUSF authentication over N12 with the SUCI.
4. AUSF decrypts the SUCI to recover the SUPI; the patched nudm-handler.c calls did_auth_check(supi).
5. The sidecar begins the four-stage verification pipeline.
6. Stage 1 Wallet lookup: credential identifiers retrieved for the SUPI. If none found, the sidecar returns HTTP 403 with no_credential_mapped.
7. Stage 2 Revocation pre-check: the issuer revocation API is queried. If revoked, denial is returned in approximately 75 ms with credential_revoked_precheck.
8. Stage 3 DIDComm proof exchange: the verifier sends a proof request to the holder; the holder generates an Anoncreds CL ZKP revealing only SUPI, IMSI, and network slice; the verifier checks the proof against the ledger.
9. Stage 4 Policy evaluation: verified attributes are checked against per-SUPI rules. Mismatches return HTTP 403 with slice_policy_denied or similar.
10. Sidecar returns HTTP 200 (allow) or HTTP 403 (deny) with per-stage timing.
11. Allowed UEs continue through standard 5G-AKA and receive Registration Accept.
12. Denied UEs receive Registration Reject; the sidecar writes the SUPI to blocked_ues.txt and upf_enforcer.sh applies iptables DROP rules within one second.

## Validation and Testing

### Running the Concurrent Stress Test

Run: cd evaluation && python3 concurrent_stress_test.py. This executes 2, 4, 5, and 10 simultaneous UE registrations under cold and warm cache conditions and reports wall-clock time, success rate, and per-UE latency.

### Running the Security Evaluation

Run: cd evaluation && python3 security_tests.py. This executes five attack scenarios (replay, impersonation, revoked credential reuse, network slice policy bypass, and denial of service) against the running 5G core and confirms each is mitigated by the implemented mechanisms.

### Running the Revocation Pre-check Benchmark

Run: cd evaluation && python3 revocation_test.py. This measures denial latency for revoked credentials with and without the pre-check optimization.

### Running the Latency Comparison

Run: cd evaluation && python3 latency_comparison.py. This compares standard 5G-AKA latency against DID-augmented authentication under cold and warm cache conditions.

## Experimental Results

### Latency Summary

| Authentication Mode | Average Latency | Overhead vs 5G-AKA |
|---|---|---|
| Standard 5G-AKA (baseline) | 256 ms | reference |
| DID cold local ledger | 2,658 ms | +2,402 ms (x10.4) |
| DID cold BCovrin public | 4,690 ms | +4,434 ms (x18.3) |
| DID warm cache hit | under 5 ms | approximately zero |

### Revocation Pre-check Performance

| Scenario | Average Latency | Mechanism |
|---|---|---|
| Without pre-check | 2,658 ms | Full DIDComm exchange |
| Pre-check, cold | 75 ms | Issuer revocation API query |
| Pre-check, cached | under 5 ms | Local revocation cache |

The pre-check optimization delivers a 35-fold reduction in denial latency for revoked credentials.

### Concurrent UE Scalability

| Configuration | UEs | Wall Time | Success |
|---|---|---|---|
| 2 UEs cold | 2 | 10,145 ms | 2/2 |
| 4 UEs cold | 4 | 5,128 ms | 4/4 |
| 5 UEs cold | 5 | 2,498 ms | 5/5 |
| 5 UEs warm | 5 | 25 ms | 5/5 |
| 10 UEs warm | 10 | 34 ms | 10/10 |

## Security Properties

### Five Attack Scenarios, All Mitigated

| Attack | Result | Primary Mitigation |
|---|---|---|
| Replay | Mitigated | Nonce-per-proof in Anoncreds CL |
| Impersonation | Mitigated | Credential binding in holder wallet |
| Revoked credential reuse | Mitigated | Ledger revocation registry plus pre-check cache |
| Network slice policy bypass | Mitigated | Cryptographic attribute binding in VC |
| Denial of service / load | Mitigated | Queue limit plus concurrency semaphore plus fail-close |

### Privacy Properties

The verifier receives only three attributes per proof presentation: SUPI, IMSI, and network slice. The remaining credential attributes (subscription type, issuer identifier) are concealed at the Anoncreds CL cryptographic level. Each proof presentation generates a fresh randomized output, providing proof-layer unlinkability that the standard 5G-AKA protocol does not provide.

## Troubleshooting

### Sidecar returns HTTP 400 with JSON parse error

Most common cause: hardcoded credential definition ID or DIDComm connection ID in sidecar.py no longer match the live ledger after a wallet reset. Update the constants in sidecar.py to match the current values from the ACA-Py agent APIs and restart the sidecar.

### Issuer agent fails to start with verkey error

The issuer DID is not registered on the ledger. For the local ledger, register it with a POST request to http://localhost:9000/register containing the issuer seed, alias 5G-Issuer, and role TRUST_ANCHOR.

### Schema not found when creating credential definition

The credential schema has not been published on the local ledger. Publish it with a POST request to http://localhost:8021/schemas containing schema_name 5g-subscriber, schema_version 1.0, and the five attributes supi, imsi, network_slice, subscription_type, issued_by.

### Concurrent stress test shows occasional UE failures under cold load

This is the SQLite Askar wallet's file-level locking, mitigated by the concurrency semaphore that caps simultaneous DIDComm proof exchanges at three. A production deployment would use the PostgreSQL-backed Askar wallet to remove this constraint. See thesis Section 4.9.3.

## References

- Open5GS: https://open5gs.org
- UERANSIM: https://github.com/aligungr/UERANSIM
- Hyperledger Aries Cloud Agent Python (ACA-Py): https://github.com/hyperledger/aries-cloudagent-python
- Hyperledger Indy: https://www.hyperledger.org/projects/hyperledger-indy
- von-network: https://github.com/bcgov/von-network
- W3C Decentralized Identifiers (DIDs): https://www.w3.org/TR/did-core/
- W3C Verifiable Credentials Data Model: https://www.w3.org/TR/vc-data-model/
- 3GPP TS 33.501, Security architecture and procedures for 5G System: https://www.3gpp.org/ftp/Specs/archive/33_series/33.501/

## PORTAL_METADATA

```portal
slug: did-auth-5g
title: Decentralized Identity Management for 5G Networks
summary: Removes the centralized trust dependency in 5G authentication by integrating DID-based Self-Sovereign Identity into a real 5G Standalone core. Credentials, revocation registries, and network slice policy are anchored on a Hyperledger Indy distributed ledger and verifiable by any party, eliminating the home-network operator as the single point of authority.
startDate: 2025-09-01
endDate: 2026-04-30
repositoryUrl: https://github.com/KananOrujov/did-auth-5g
logos: []
```
