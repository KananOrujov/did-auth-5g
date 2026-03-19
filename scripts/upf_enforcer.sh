#!/bin/bash
# UPF Traffic Enforcer v3.1 - no log spam on periodic refresh
BLOCKED_FILE="/var/tmp/blocked_ues.txt"
MAP_FILE="/var/tmp/ue_ip_map.txt"
CHAIN="DID_BLOCK"
LOG_TAG="[ENFORCE]"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_TAG $*"; }

setup_chains() {
    iptables -N $CHAIN 2>/dev/null || true
    iptables -D INPUT -j $CHAIN 2>/dev/null || true
    iptables -D OUTPUT -j $CHAIN 2>/dev/null || true
    iptables -D FORWARD -j $CHAIN 2>/dev/null || true
    iptables -I INPUT 1 -j $CHAIN
    iptables -I OUTPUT 1 -j $CHAIN
    iptables -I FORWARD 1 -j $CHAIN
    log "Chains initialized (INPUT/OUTPUT/FORWARD -> $CHAIN)"
}

apply_rules() {
    TRIGGER="$1"  # "change" or "refresh"
    iptables -F $CHAIN 2>/dev/null

    if [ ! -f "$BLOCKED_FILE" ] || [ ! -s "$BLOCKED_FILE" ]; then
        [ "$TRIGGER" = "change" ] && log "No blocked UEs - chain cleared"
        return
    fi

    BLOCKED_COUNT=0
    MISSING_COUNT=0
    BLOCKED_LIST=""

    while IFS= read -r supi; do
        [ -z "$supi" ] && continue
        IP=$(grep "^$supi=" "$MAP_FILE" 2>/dev/null | tail -1 | cut -d= -f2)
        if [ -n "$IP" ]; then
            iptables -A $CHAIN -s "$IP" -j DROP
            iptables -A $CHAIN -d "$IP" -j DROP
            BLOCKED_LIST="$BLOCKED_LIST $supi($IP)"
            BLOCKED_COUNT=$((BLOCKED_COUNT + 1))
        else
            MISSING_COUNT=$((MISSING_COUNT + 1))
            [ "$TRIGGER" = "change" ] && log "WARNING: No IP mapping for $supi"
        fi
    done < "$BLOCKED_FILE"

    # Only log on actual file change, not periodic refresh
    if [ "$TRIGGER" = "change" ]; then
        for entry in $BLOCKED_LIST; do
            log "BLOCK $entry"
        done
        log "Rules applied: $BLOCKED_COUNT blocked, $MISSING_COUNT pending mapping"
    fi
}

cleanup() {
    log "Shutting down - flushing rules"
    iptables -F $CHAIN 2>/dev/null
    iptables -D INPUT -j $CHAIN 2>/dev/null
    iptables -D OUTPUT -j $CHAIN 2>/dev/null
    iptables -D FORWARD -j $CHAIN 2>/dev/null
    iptables -X $CHAIN 2>/dev/null
    exit 0
}

trap cleanup SIGTERM SIGINT

log "Starting UPF enforcer v3.1"
touch "$BLOCKED_FILE" "$MAP_FILE"
setup_chains
apply_rules "change"

while true; do
    # Wait for file change or 30s timeout
    RESULT=$(inotifywait -q -t 30 -e modify,create,close_write \
        "$BLOCKED_FILE" "$MAP_FILE" 2>/dev/null)
    if [ -n "$RESULT" ]; then
        apply_rules "change"
    else
        apply_rules "refresh"  # silent periodic refresh
    fi
done
