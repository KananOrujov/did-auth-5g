#!/bin/bash
LOG=/home/kali/did-auth/demo-results.txt
ISSUER=http://localhost:8021
HOLDER=http://localhost:8031
SIDECAR=http://localhost:5000
REV_REG="QTbY98psM6bDviJj9A6JLU:4:QTbY98psM6bDviJj9A6JLU:3:CL:3132200:revocable:CL_ACCUM:55375973-1fdd-4349-aa7e-47983a4aa460"
SUPI="imsi-001010000000001"

echo "================================================" | tee $LOG
echo " 5G DID/VC Auth Demo - $(date)" | tee -a $LOG
echo "================================================" | tee -a $LOG

update_sidecar() {
  local ref=$1
  sed -i "s|CRED_REF      = \".*\"|CRED_REF      = \"$ref\"|" /home/kali/did-auth/sidecar.py
}

restart_sidecar() {
  pkill -f sidecar.py 2>/dev/null; sleep 2
  python3 -u /home/kali/did-auth/sidecar.py > /home/kali/did-auth/logs/sidecar.log 2>&1 &
  sleep 4
}

check_auth() {
  local label=$1
  local result=$(curl -s -X POST $SIDECAR/did-auth \
    -H "Content-Type: application/json" \
    -d "{\"supi\": \"$SUPI\"}")
  local verified=$(echo $result | python3 -c "import sys,json; print(json.load(sys.stdin)['verified'])")
  local latency=$(echo $result | python3 -c "import sys,json; print(json.load(sys.stdin)['latency_ms'])")
  echo "[$label] verified=$verified latency=${latency}ms" | tee -a $LOG >&2
  echo $verified
}

# Get two unrevoked credentials from wallet
echo "" | tee -a $LOG
echo "--- Checking available credentials ---" | tee -a $LOG
CREDS=$(curl -s $HOLDER/credentials | python3 -c "
import sys,json
creds = [c for c in json.load(sys.stdin).get('results',[]) if c.get('rev_reg_id')]
creds.sort(key=lambda x: int(x.get('cred_rev_id',0)))
for c in creds[-3:]:
    print(c['referent'], c['cred_rev_id'])
")
echo "Available credentials (last 3):" | tee -a $LOG
echo "$CREDS" | tee -a $LOG

CRED1_REF=7827733c-d57b-4472-be50-26c998363bfd
CRED1_REV=23
CRED2_REF=3a241042-2991-40bf-9e61-ca6344913db5
CRED2_REV=24

echo "Will use: cred1=$CRED1_REF (rev_id=$CRED1_REV)" | tee -a $LOG
echo "Will use: cred2=$CRED2_REF (rev_id=$CRED2_REV)" | tee -a $LOG

# STEP 1: Valid credential
echo "" | tee -a $LOG
echo "STEP 1: Valid credential verify (expect: True)" | tee -a $LOG
update_sidecar $CRED1_REF
restart_sidecar
V=$(check_auth "VALID CRED")
if [ "$V" = "True" ]; then echo "PASS" | tee -a $LOG; else echo "FAIL (got: $V)" | tee -a $LOG; fi

# STEP 2: Revoke cred1 and verify (expect: False)
echo "" | tee -a $LOG
echo "STEP 2: Revoke cred (rev_id=$CRED1_REV) and verify (expect: False)" | tee -a $LOG
curl -s -X POST $ISSUER/revocation/revoke \
  -H "Content-Type: application/json" \
  -d "{\"cred_rev_id\": \"$CRED1_REV\", \"rev_reg_id\": \"$REV_REG\", \"publish\": true}" > /dev/null
echo "Revocation published. Waiting 30s for ledger..." | tee -a $LOG
sleep 30
restart_sidecar
V=$(check_auth "REVOKED CRED")
if [ "$V" = "False" ]; then echo "PASS" | tee -a $LOG; else echo "FAIL (got: $V)" | tee -a $LOG; fi

# STEP 3: Switch to cred2 (valid) and verify (expect: True)
echo "" | tee -a $LOG
echo "STEP 3: Re-verify with valid credential (expect: True)" | tee -a $LOG
update_sidecar $CRED2_REF
restart_sidecar
V=$(check_auth "VALID CRED2")
if [ "$V" = "True" ]; then echo "PASS" | tee -a $LOG; else echo "FAIL (got: $V)" | tee -a $LOG; fi

# STEP 4: Latency measurements
echo "" | tee -a $LOG
echo "STEP 4: Latency measurements (n=5)" | tee -a $LOG
LATS=""
for i in 1 2 3 4 5; do
  restart_sidecar
  RESULT=$(curl -s -X POST $SIDECAR/did-auth \
    -H "Content-Type: application/json" \
    -d "{\"supi\": \"$SUPI\"}")
  LAT=$(echo $RESULT | python3 -c "import sys,json; print(json.load(sys.stdin)['latency_ms'])")
  LATS="$LATS $LAT"
  echo "  Run $i: ${LAT}ms" | tee -a $LOG
done

python3 << PYEOF | tee -a $LOG
lats = list(map(int, "$LATS".split()))
print(f"  Min: {min(lats)}ms")
print(f"  Max: {max(lats)}ms")
print(f"  Avg: {sum(lats)//len(lats)}ms")
PYEOF

echo "" | tee -a $LOG
echo "================================================" | tee -a $LOG
echo " DEMO COMPLETE" | tee -a $LOG
echo "================================================" | tee -a $LOG
echo ""
echo "========== CLEAN SUMMARY =========="
grep -E "STEP|PASS|FAIL|Run [0-9]|Min:|Max:|Avg:|cred1=|cred2=" $LOG
echo "===================================="
echo "Full log: $LOG"
