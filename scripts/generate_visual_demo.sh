#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${1:-/home/gherd/.gemini/antigravity/brain/66d1f5da-324c-4eca-b988-4da43c09a455}"

echo "==> Building and running visual demo generator..."
cargo run --bin visual_demo

echo "==> Converting PPM frame dumps to PNG..."
for ppm in demo_frame_*.ppm; do
    png="${ppm%.ppm}.png"
    convert "$ppm" "$png"
    cp "$png" "$ARTIFACT_DIR/"
    echo "  Generated: $ARTIFACT_DIR/$png"
    rm "$ppm" "$png"
done

echo "==> Visual demo generation complete!"
