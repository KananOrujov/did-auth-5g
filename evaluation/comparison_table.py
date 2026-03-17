#!/usr/bin/env python3
"""
Comparison Table: Centralized vs Decentralized Identity Management in 5G
"""
import time

RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"

print("=== Centralized vs Decentralized Identity Management in 5G ===\n")

table = [
    # (Metric, Traditional 5G, DID/VC System, Notes)
    ("Identity Storage",
     "Centralized HSS/UDM database",
     "Self-sovereign (UE holds credential)",
     "DID: no central store"),

    ("Authentication Protocol",
     "5G-AKA (SUPI/SUCI based)",
     "5G-AKA + DID proof verification",
     "DID layer on top of 5G-AKA"),

    ("Credential Issuance",
     "Operator provisions SIM/eSIM",
     "Issuer agent issues VC (~11s one-time)",
     "One-time setup cost"),

    ("Auth Latency (no cache)",
     "~300-340ms (5G-AKA only)",
     "~4000ms avg (DID proof + ledger)",
     "BCovrin RTT dominates"),

    ("Auth Latency (cache hit)",
     "~300-340ms",
     "~1ms (cache) + 300ms (5G-AKA)",
     "Cache eliminates DID overhead"),

    ("Throughput (cache)",
     "Limited by RAN/core",
     "230 req/s (sidecar cache)",
     "Cache enables high throughput"),

    ("Revocation",
     "Immediate (operator disables SIM)",
     "~30-90s (ledger propagation)",
     "BCovrin test ledger latency"),

    ("Privacy (linkability)",
     "HIGH - operator tracks all sessions",
     "MEDIUM - credential referent linkable",
     "ZKP improves over traditional"),

    ("Selective Disclosure",
     "NOT supported",
     "SUPPORTED (ZKP, reveal only needed attrs)",
     "Key DID advantage"),

    ("Network Slice Enforcement",
     "Policy-based (AMF/SMF)",
     "Cryptographic (VC attribute)",
     "DID: tamper-proof slice claim"),

    ("Credential Portability",
     "NOT portable (tied to operator)",
     "Portable (DID standard)",
     "Cross-operator possible"),

    ("Third-party Verification",
     "NOT supported",
     "SUPPORTED (any verifier with ledger access)",
     "Enables MEC/edge auth"),

    ("Single Point of Failure",
     "HSS/UDM (mitigated by redundancy)",
     "Ledger (mitigated by distribution)",
     "Both have SPOF risk"),

    ("Standards Compliance",
     "3GPP TS 33.501",
     "3GPP + W3C DID + Hyperledger Indy",
     "DID adds new standards layer"),

    ("Implementation Complexity",
     "LOW (standard 3GPP)",
     "HIGH (5G + SSI + ledger)",
     "Significant integration effort"),

    ("Scalability",
     "Proven at carrier scale",
     "Sequential: proven; Concurrent: limited by single connection",
     "ACA-Py connection bottleneck"),
]

# Print table
header = f"{'Metric':<35} {'Traditional 5G':<35} {'DID/VC System':<40} {'Notes':<40}"
print(header)
print("-" * 150)
for row in table:
    print(f"{row[0]:<35} {row[1]:<35} {row[2]:<40} {row[3]:<40}")

# Save
with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Comparison Table - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    f.write(f"{'Metric':<35} {'Traditional 5G':<35} {'DID/VC System':<40}\n")
    f.write("-" * 110 + "\n")
    for row in table:
        f.write(f"{row[0]:<35} {row[1]:<35} {row[2]:<40}\n")

print("\nResults saved to thesis-results.txt")
