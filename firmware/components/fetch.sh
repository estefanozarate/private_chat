#!/usr/bin/env bash
# Vendor Monocypher (X25519 + Ed25519/RFC8032 add-on) into this component.
# Run once from the repo root:  ./firmware/components/monocypher/fetch.sh
set -euo pipefail
cd "$(dirname "$0")"
BASE="https://raw.githubusercontent.com/LoupVaillant/Monocypher/master/src"
curl -fsSL "$BASE/monocypher.c"                  -o monocypher.c
curl -fsSL "$BASE/monocypher.h"                  -o monocypher.h
curl -fsSL "$BASE/optional/monocypher-ed25519.c" -o monocypher-ed25519.c
curl -fsSL "$BASE/optional/monocypher-ed25519.h" -o monocypher-ed25519.h
echo "Monocypher vendored:"
ls -l monocypher*.c monocypher*.h
