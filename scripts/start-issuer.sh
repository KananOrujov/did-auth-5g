#!/bin/bash
python3 -m aries_cloudagent start \
  --label "5G-Issuer" \
  --inbound-transport http 0.0.0.0 8020 \
  --outbound-transport http \
  --admin 0.0.0.0 8021 \
  --admin-insecure-mode \
  --genesis-url http://test.bcovrin.vonx.io/genesis \
  --seed "Issuer00000000000000000000000001" \
  --endpoint http://127.0.0.1:8020 \
  --wallet-type askar \
  --wallet-name issuer-wallet \
  --wallet-key issuer-key-01 \
  --auto-provision \
  --tails-server-base-url http://127.0.0.1:6543 \
  --log-level info \
  2>&1 | tee /home/kali/did-auth/logs/issuer.log
