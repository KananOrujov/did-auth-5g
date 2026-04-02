#!/bin/bash
# Start local Hyperledger Indy ledger using von-network
# Run this BEFORE starting ACA-Py agents for local ledger mode
cd /home/kali/von-network
./manage start
echo "Local ledger running at http://localhost:9000"
echo "Genesis: http://localhost:9000/genesis"
