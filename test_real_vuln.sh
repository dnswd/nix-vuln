#!/usr/bin/env bash

set -euo pipefail

echo "[+] Downloading real CVE feed..."
if [ ! -f nvdcve-1.1-2023.json ]; then
    curl -sLO https://github.com/jeffpound/NVD-JSON-Feeds/raw/main/nvdcve-1.1-2023.json.gz
    gunzip -f nvdcve-1.1-2023.json.gz
else
    echo "Already downloaded."
fi

echo "[+] Crafting dummy derivation..."
DRV_PATH="dummy_cortex_xsoar-6.8.0.drv"
printf "%s" 'Derive([("out","/nix/store/11111111111111111111111111111111-cortex_xsoar-6.8.0","","")],[],[],"x86_64-linux","/nix/store/11111111111111111111111111111111-builder.sh",[],[("name","cortex_xsoar-6.8.0"),("out","/nix/store/11111111111111111111111111111111-cortex_xsoar-6.8.0")])' > "$DRV_PATH"

echo "[+] Building nix-vuln..."
cargo build

echo "[+] Ingesting feed..."
rm -f cves.db
./target/debug/nix-vuln --ingest nvdcve-1.1-2023.json

echo "[+] Scanning derivation..."
OUTPUT=$(./target/debug/nix-vuln "$DRV_PATH" || true)
echo "$OUTPUT"

echo "[+] Asserting CVE ID..."
if echo "$OUTPUT" | grep -q "CVE-2023-0003"; then
    echo "SUCCESS: Found CVE-2023-0003 in output!"
    exit 0
else
    echo "FAILURE: Did not find CVE-2023-0003 in output."
    exit 1
fi
