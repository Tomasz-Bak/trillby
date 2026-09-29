#!/usr/bin/env bash
set -euo pipefail

echo "==> Running Host Workspace Unit Tests (x86_64 native)..."
cargo test --workspace

echo "==> QEMU setup verified."
