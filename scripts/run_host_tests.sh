#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

echo "==> Running Host Workspace Unit & E2E Tests (x86_64 native)..."
cargo test --workspace

echo "==> Running CLI Provisioning & Floor Server E2E Smoke Test..."
TMP_DIR="$(mktemp -d)"
SMOKE_HOST="127.0.0.1"
SMOKE_PORT="18088"
SERVER_PID=""
cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    rm -rf "$TMP_DIR"
}
trap cleanup EXIT

./scripts/provision_device.sh \
    --out "$TMP_DIR/device.key" \
    --registry "$TMP_DIR/registry.tsv" \
    --server-ip "$SMOKE_HOST" \
    --server-port "$SMOKE_PORT"

./scripts/provision_device.sh --dump "$TMP_DIR/device.key"

SERVER_LOG="$TMP_DIR/server.log"
cargo run -p trillby-server -- \
    --bind "$SMOKE_HOST" \
    --port "$SMOKE_PORT" \
    --registry "$TMP_DIR/registry.tsv" \
    --dev > "$SERVER_LOG" 2>&1 &
SERVER_PID=$!

for _ in $(seq 1 50); do
    if grep -q "LISTEN" "$SERVER_LOG" 2>/dev/null; then
        break
    fi
    sleep 0.1
done

if ! grep -q "LISTEN" "$SERVER_LOG"; then
    echo "ERROR: trillby-server failed to start listening:" >&2
    cat "$SERVER_LOG" >&2
    exit 1
fi

cargo run -p trillby-server --example fake_client -- "$SMOKE_PORT"

for expected in "AUTH" "WORK_START" "WORK_STOP" "LOGOUT" "HEARTBEAT"; do
    if ! grep -q "$expected" "$SERVER_LOG"; then
        echo "ERROR: Missing expected '$expected' event in server log:" >&2
        cat "$SERVER_LOG" >&2
        exit 1
    fi
done

echo "==> Workspace & E2E smoke tests verified."
