#!/bin/bash
set -e

echo "Building the project..."
cargo build

echo "Instantiating the current flake..."
DRV=$(nix path-info --derivation . 2>/dev/null | grep '\.drv' | head -n1)
echo "Got DRV: $DRV"

echo "Starting nix-vuln server..."
./target/debug/nix-vuln --closure "$DRV" &
PID=$!
trap "kill $PID 2>/dev/null || true" EXIT

echo "Waiting for server to start..."
sleep 3

echo "Fetching graph data..."
curl -s http://127.0.0.1:3000/api/graph > graph.json

echo "Nodes: $(nix run nixpkgs#jq -- '.nodes | length' graph.json), Links: $(nix run nixpkgs#jq -- '.links | length' graph.json)"

