#!/bin/bash
python3 -m aries_cloudagent start \
  --label "5G-Verifier-AUSF" \
  --inbound-transport http 0.0.0.0 8040 \
  --outbound-transport http \
  --admin 0.0.0.0 8041 \
  --admin-insecure-mode \
  --genesis-url http://localhost:9000/genesis \
  --endpoint http://127.0.0.1:8040 \
  --wallet-type askar \
  --wallet-name verifier-local-wallet \
  --wallet-key verifier-key-01 \
  --auto-provision \
  --log-level info \
  2>&1 | tee /home/kali/did-auth/logs/verifier.log
