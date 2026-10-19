#!/usr/bin/env bash
# Trillby Device Key Provisioning Script
# Generates a binary device.key blob (with IEEE 802.3 CRC32 checksum)
# and registers the device in the server registry file.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Run the pure-Rust zero-dependency provisioning tool
exec cargo run -p trillby-net --example provision --manifest-path "$PROJECT_ROOT/Cargo.toml" -- "$@"
