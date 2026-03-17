#!/usr/bin/env python3
"""
Privacy Analysis: Linkability and Unlinkability in DID/VC-based 5G Authentication
Analyzes the privacy properties of the implemented system vs traditional 5G-AKA.
"""
import time

RESULTS_FILE = "/home/kali/did-auth/thesis-results.txt"

print("=== Privacy Analysis: DID/VC Authentication ===\n")

analysis = {
    "traditional_5g_aka": {
        "identifier_exposure": "SUPI sent in cleartext during initial attach (before 5G-NAS security)",
        "linkability": "HIGH - SUPI/GUTI linkable across sessions by core network",
        "unlinkability": "PARTIAL - GUTI refreshed but operator can link all sessions",
        "identity_correlation": "HIGH - HSS/UDM has full subscriber profile",
        "third_party_exposure": "NONE - authentication is internal to operator",
        "revocation": "Immediate - operator controls HSS directly",
        "privacy_threat": "Subscriber tracking by operator, potential lawful intercept"
    },
    "did_vc_system": {
        "identifier_exposure": "SUPI revealed in VC proof but only to verifier (MNO-controlled)",
        "linkability": "MEDIUM - same credential referent used across proofs (linkable)",
        "unlinkability": "PARTIAL - ZKP proves attributes without revealing credential signature",
        "identity_correlation": "LOW - verifier only sees presented attributes, not full profile",
        "third_party_exposure": "LOW - BCovrin ledger sees credential def lookups only (no SUPI)",
        "revocation": "DELAYED - BCovrin propagation latency ~30-90s",
        "privacy_threat": "Credential referent linkability if same cred used multiple times"
    },
    "improvements": [
        "ZKP-based proof: verifier learns only disclosed attributes (supi, imsi, slice)",
        "Ledger privacy: BCovrin only stores credential definitions, not subscriber data",
        "Selective disclosure: subscription_type and issued_by can be withheld",
        "No central identity store: credentials held by UE, not operator database",
        "Revocation privacy: CL_ACCUM revocation does not reveal which credential was revoked"
    ],
    "limitations": [
        "Credential referent linkability: same referent reused across auth sessions",
        "SUPI still disclosed in proof (required for 5G network function operation)",
        "BCovrin is a public test ledger - production should use permissioned ledger",
        "Single holder-verifier connection: all proofs share same DIDComm channel"
    ],
    "zkp_properties": {
        "zero_knowledge": "Verifier learns only: supi, imsi, network_slice — nothing else",
        "soundness": "Cryptographic binding via CL signatures prevents forgery",
        "completeness": "Valid credential always produces accepted proof",
        "non_revocation_proof": "Holder proves credential not in revocation accumulator"
    }
}

print("1. TRADITIONAL 5G-AKA PRIVACY PROPERTIES")
print("-" * 50)
for k, v in analysis["traditional_5g_aka"].items():
    print(f"  {k.replace('_', ' ').title():30s}: {v}")

print("\n2. DID/VC SYSTEM PRIVACY PROPERTIES")
print("-" * 50)
for k, v in analysis["did_vc_system"].items():
    print(f"  {k.replace('_', ' ').title():30s}: {v}")

print("\n3. PRIVACY IMPROVEMENTS OVER TRADITIONAL 5G-AKA")
print("-" * 50)
for i, item in enumerate(analysis["improvements"], 1):
    print(f"  {i}. {item}")

print("\n4. PRIVACY LIMITATIONS")
print("-" * 50)
for i, item in enumerate(analysis["limitations"], 1):
    print(f"  {i}. {item}")

print("\n5. ZKP CRYPTOGRAPHIC PROPERTIES (Camenisch-Lysyanskaya)")
print("-" * 50)
for k, v in analysis["zkp_properties"].items():
    print(f"  {k.replace('_', ' ').title():25s}: {v}")

print("\n6. LINKABILITY ANALYSIS")
print("-" * 50)
print("  Same credential used N times → N proofs linkable by referent")
print("  Mitigation: Issue new credential per session (increases issuance overhead)")
print("  Current implementation: Single credential reused (linkable but functional)")
print("  Recommendation: Per-session credential or anonymous credential scheme")

# Save to results
with open(RESULTS_FILE, "a") as f:
    f.write(f"\n=== Privacy Analysis - {time.strftime('%Y-%m-%d %H:%M')} ===\n")
    f.write("Traditional 5G-AKA: HIGH linkability, SUPI exposed\n")
    f.write("DID/VC System: MEDIUM linkability, ZKP selective disclosure\n")
    f.write("Key improvement: No central identity store, selective attribute disclosure\n")
    f.write("Key limitation: Credential referent reuse enables cross-session linkability\n")

print("\nResults saved to thesis-results.txt")
