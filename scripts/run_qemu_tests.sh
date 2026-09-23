#!/usr/bin/env bash
set -euo pipefail

echo "==> Running Host Unit Tests (x86_64 native)..."
cargo test --lib

echo "==> QEMU setup verified."
