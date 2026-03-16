#!/bin/bash
python3 -m aries_cloudagent start \
  --label "5G-Holder-UE" \
  --inbound-transport http 0.0.0.0 8030 \
  --outbound-transport http \
  --admin 0.0.0.0 8031 \
  --admin-insecure-mode \
  --genesis-url http://test.bcovrin.vonx.io/genesis \
  --endpoint http://127.0.0.1:8030 \
  --wallet-type askar \
  --wallet-name holder-wallet \
  --wallet-key holder-key-01 \
  --auto-provision \
  --log-level info \
  2>&1 | tee /home/kali/did-auth/logs/holder.log
