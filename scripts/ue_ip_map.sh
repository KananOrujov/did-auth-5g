#!/bin/bash
# SUPI -> IP mapper v2 - watches SMF log for UE IP assignments
# Handles reconnects and stale entries

MAP_FILE="/var/tmp/ue_ip_map.txt"
LOG_TAG="[UE_MAP]"

log() { echo "$(date '+%Y-%m-%d %H:%M:%S') $LOG_TAG $*"; }

touch "$MAP_FILE"
log "Starting SUPI->IP mapper v2"
log "Watching: /home/kali/open5gs/install/var/log/open5gs/smf.log"

tail -F /home/kali/open5gs/install/var/log/open5gs/smf.log 2>/dev/null | \
while read -r line; do
    # Match PDU session assignment: UE SUPI[imsi-X] DNN[internet] IPv4[Y]
    if echo "$line" | grep -q "UE SUPI\[imsi-"; then
        SUPI=$(echo "$line" | grep -oP 'SUPI\[\K[^\]]+')
        IP=$(echo "$line" | grep -oP 'IPv4\[\K[^\]]+')

        if [ -n "$SUPI" ] && [ -n "$IP" ] && [ "$IP" != "" ]; then
            # Get old IP if exists
            OLD_IP=$(grep "^$SUPI=" "$MAP_FILE" 2>/dev/null | cut -d= -f2)

            # Always update - handles reconnects with new IP
            grep -v "^$SUPI=" "$MAP_FILE" > /tmp/ue_map_tmp.txt 2>/dev/null || true
            echo "$SUPI=$IP" >> /tmp/ue_map_tmp.txt
            mv /tmp/ue_map_tmp.txt "$MAP_FILE"

            if [ "$OLD_IP" != "$IP" ]; then
                log "MAPPED $SUPI -> $IP (was: ${OLD_IP:-none})"
            fi
        fi
    fi

    # Handle session removal - mark IP as gone
    if echo "$line" | grep -q "Removed Session.*IMSI:\[imsi-"; then
        SUPI=$(echo "$line" | grep -oP 'IMSI:\[\K[^\]]+')
        if [ -n "$SUPI" ]; then
            OLD_IP=$(grep "^$SUPI=" "$MAP_FILE" 2>/dev/null | cut -d= -f2)
            if [ -n "$OLD_IP" ]; then
                log "SESSION REMOVED $SUPI (was $OLD_IP) - keeping mapping for enforcement"
            fi
        fi
    fi
done
