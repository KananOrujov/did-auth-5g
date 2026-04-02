#!/bin/bash
# ============================================================
# DID-Auth-5G Full Stack Startup Script
# Starts everything in the correct order
# Usage: bash scripts/start-full-stack.sh [local|bcovrin]
# ============================================================

LEDGER_MODE=${1:-bcovrin}  # default to bcovrin
BASE="/home/kali/did-auth-5g"
LOG_DIR="$BASE/logs"
mkdir -p "$LOG_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log()  { echo -e "${CYAN}[STACK]${NC} $*"; }
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
fail() { echo -e "${RED}[FAIL]${NC} $*"; exit 1; }

# ── Kill anything already running ──────────────────────────
log "Stopping any existing processes..."
pkill -f open5gs 2>/dev/null
pkill -f nr-ue 2>/dev/null
pkill -f nr-gnb 2>/dev/null
pkill -f aca-py 2>/dev/null
pkill -f sidecar.py 2>/dev/null
pkill -f upf_enforcer 2>/dev/null
pkill -f ue_ip_map 2>/dev/null
pkill -f tails-server 2>/dev/null
sleep 3

# ── Step 1: Local ledger (if requested) ───────────────────
if [ "$LEDGER_MODE" = "local" ]; then
    log "Step 1: Starting local Indy ledger (von-network)..."
    systemctl start docker 2>/dev/null
    sleep 2
    cd /home/kali/von-network
    ./manage start > "$LOG_DIR/von-network.log" 2>&1 &
    sleep 15
    if curl -s http://localhost:9000/genesis | grep -q "reqSignature"; then
        ok "Local ledger running at http://localhost:9000"
    else
        fail "Local ledger failed to start. Check $LOG_DIR/von-network.log"
    fi
    cd "$BASE"
else
    log "Step 1: Using BCovrin public ledger (no local setup needed)"
    ok "BCovrin: http://test.bcovrin.vonx.io"
fi

# ── Step 2: Open5GS ───────────────────────────────────────
log "Step 2: Starting Open5GS 5G core..."
bash /home/kali/open5gs/start-open5gs.sh > "$LOG_DIR/open5gs.log" 2>&1 &
sleep 10
if pgrep -f open5gs-ausfd > /dev/null; then
    ok "Open5GS running (AUSF patched binary confirmed)"
else
    fail "Open5GS failed to start. Check $LOG_DIR/open5gs.log"
fi

# ── Step 3: Tails server ──────────────────────────────────
log "Step 3: Starting tails server..."
tails-server \
    --host 0.0.0.0 \
    --port 6543 \
    --storage-path /home/kali/tails-files \
    --log-level WARNING > "$LOG_DIR/tails.log" 2>&1 &
sleep 3
ok "Tails server running on port 6543"

# ── Step 4: ACA-Py agents ─────────────────────────────────
log "Step 4: Starting ACA-Py agents (mode: $LEDGER_MODE)..."

if [ "$LEDGER_MODE" = "local" ]; then
    GENESIS_URL="http://localhost:9000/genesis"
    ISSUER_SEED="Local5GIssuer0000000000000000001"
    ISSUER_WALLET="issuer-local-wallet2"
    HOLDER_WALLET="holder-local-wallet"
    VERIFIER_WALLET="verifier-local-wallet"
else
    GENESIS_URL="http://test.bcovrin.vonx.io/genesis"
    ISSUER_SEED="Issuer00000000000000000000000001"
    ISSUER_WALLET="issuer-wallet"
    HOLDER_WALLET="holder-wallet"
    VERIFIER_WALLET="verifier-wallet"
fi

nohup python3 -m aries_cloudagent start \
    --label "5G-Issuer" \
    --inbound-transport http 0.0.0.0 8020 \
    --outbound-transport http \
    --admin 0.0.0.0 8021 --admin-insecure-mode \
    --genesis-url "$GENESIS_URL" \
    --seed "$ISSUER_SEED" \
    --endpoint http://127.0.0.1:8020 \
    --wallet-type askar --wallet-name "$ISSUER_WALLET" \
    --wallet-key issuer-key-01 --auto-provision \
    --tails-server-base-url http://127.0.0.1:6543 \
    --log-level warning > "$LOG_DIR/issuer.log" 2>&1 &
sleep 10

nohup python3 -m aries_cloudagent start \
    --label "5G-Holder-UE" \
    --inbound-transport http 0.0.0.0 8030 \
    --outbound-transport http \
    --admin 0.0.0.0 8031 --admin-insecure-mode \
    --genesis-url "$GENESIS_URL" \
    --endpoint http://127.0.0.1:8030 \
    --wallet-type askar --wallet-name "$HOLDER_WALLET" \
    --wallet-key holder-key-01 --auto-provision \
    --tails-server-base-url http://127.0.0.1:6543 \
    --log-level warning > "$LOG_DIR/holder.log" 2>&1 &
sleep 10

nohup python3 -m aries_cloudagent start \
    --label "5G-Verifier-AUSF" \
    --inbound-transport http 0.0.0.0 8040 \
    --outbound-transport http \
    --admin 0.0.0.0 8041 --admin-insecure-mode \
    --genesis-url "$GENESIS_URL" \
    --endpoint http://127.0.0.1:8040 \
    --wallet-type askar --wallet-name "$VERIFIER_WALLET" \
    --wallet-key verifier-key-01 --auto-provision \
    --tails-server-base-url http://127.0.0.1:6543 \
    --log-level warning > "$LOG_DIR/verifier.log" 2>&1 &
sleep 12

# Check all three agents
ISSUER_OK=$(curl -s http://localhost:8021/status | python3 -c "import sys,json; print(json.load(sys.stdin).get('label',''))" 2>/dev/null)
HOLDER_OK=$(curl -s http://localhost:8031/status | python3 -c "import sys,json; print(json.load(sys.stdin).get('label',''))" 2>/dev/null)
VERIFIER_OK=$(curl -s http://localhost:8041/status | python3 -c "import sys,json; print(json.load(sys.stdin).get('label',''))" 2>/dev/null)

[ -n "$ISSUER_OK" ]   && ok "Issuer: $ISSUER_OK"   || fail "Issuer failed. Check $LOG_DIR/issuer.log"
[ -n "$HOLDER_OK" ]   && ok "Holder: $HOLDER_OK"   || fail "Holder failed. Check $LOG_DIR/holder.log"
[ -n "$VERIFIER_OK" ] && ok "Verifier: $VERIFIER_OK" || fail "Verifier failed. Check $LOG_DIR/verifier.log"

# ── Step 5: Sidecar ───────────────────────────────────────
log "Step 5: Starting DID Auth sidecar..."
cd "$BASE"
python3 sidecar/sidecar.py > "$LOG_DIR/sidecar.log" 2>&1 &
sleep 4
if curl -s http://localhost:5000/health | grep -q "ok"; then
    ok "Sidecar running on port 5000"
else
    fail "Sidecar failed. Check $LOG_DIR/sidecar.log"
fi

# ── Step 6: UPF enforcement ───────────────────────────────
log "Step 6: Starting UPF enforcement..."
bash "$BASE/scripts/ue_ip_map.sh" > "$LOG_DIR/ue_ip_map.log" 2>&1 &
bash "$BASE/scripts/upf_enforcer.sh" > "$LOG_DIR/upf_enforcer.log" 2>&1 &
sleep 3
ok "UPF enforcement running (iptables DID_BLOCK chain)"

# ── Step 7: UERANSIM ──────────────────────────────────────
log "Step 7: Starting UERANSIM..."
/home/kali/UERANSIM/build/nr-gnb \
    -c "$BASE/config/open5gs-gnb.yaml" > "$LOG_DIR/gnb.log" 2>&1 &
sleep 3
/home/kali/UERANSIM/build/nr-ue \
    -c "$BASE/config/open5gs-ue.yaml" > "$LOG_DIR/ue.log" 2>&1 &
sleep 3
ok "UERANSIM started (gNB + UE)"

# ── Final status ──────────────────────────────────────────
echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}  DID-Auth-5G Stack Started!${NC}"
echo -e "${GREEN}========================================${NC}"
echo -e "  Ledger mode:  ${CYAN}$LEDGER_MODE${NC}"
echo -e "  Sidecar:      ${CYAN}http://localhost:5000/health${NC}"
echo -e "  Issuer API:   ${CYAN}http://localhost:8021${NC}"
echo -e "  Holder API:   ${CYAN}http://localhost:8031${NC}"
echo -e "  Verifier API: ${CYAN}http://localhost:8041${NC}"
echo -e "  Logs:         ${CYAN}$LOG_DIR/${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
if [ "$LEDGER_MODE" = "local" ]; then
echo -e "  Run credential setup: ${CYAN}python3 scripts/setup_credentials.py${NC}"
fi
echo -e "  Test auth:  ${CYAN}curl -s -X POST http://localhost:5000/did-auth -H 'Content-Type: application/json' -d '{\"supi\":\"imsi-001010000000002\"}'${NC}"
echo ""
