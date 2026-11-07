#!/usr/bin/env bash
# Trillby QEMU 800x480 Graphical Machine Launcher
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_ROOT"

MEMORY="512M"
WIDTH=800
HEIGHT=480
TARGET="aarch64-unknown-linux-musl"
PROFILE="debug"
KERNEL_DIR="${KERNEL_DIR:-$PROJECT_ROOT/linux}"
KERNEL="${KERNEL:-$KERNEL_DIR/arch/arm64/boot/Image}"
INITRD="$PROJECT_ROOT/initramfs.cpio.gz"
echo "============================================================"
echo " Launching Trillby QEMU ${WIDTH}x${HEIGHT} Graphical Machine"
echo " Kernel: $KERNEL"
echo " Initrd: $INITRD"
echo " Resolution: ${WIDTH}x${HEIGHT} | Memory: ${MEMORY}"
echo "============================================================"

if [ ! -f "$KERNEL" ]; then
    echo "ERROR: Kernel image not found at $KERNEL"
    echo "Please build the kernel first via ./scripts/build_kernel.sh"
    exit 1
fi

echo "==> Building static AArch64 Trillby binary..."
RUSTC_BOOTSTRAP=1 \
cargo build -Z build-std --target "$TARGET" --package trillby --features qemu-sim

STAGING_DIR="$PROJECT_ROOT/target/initramfs_staging"
echo "==> Packaging initramfs with static Trillby binary as /init..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"/{dev,proc,sys,etc}
cp "target/$TARGET/$PROFILE/trillby" "$STAGING_DIR/init"
chmod +x "$STAGING_DIR/init"

(cd "$STAGING_DIR" && find . | cpio -o -H newc | gzip > "$INITRD")
rm -rf "$STAGING_DIR"

# Detect display backend (gtk, sdl, or default)
DISPLAY_OPT="default"
if qemu-system-aarch64 -display help 2>&1 | grep -q "gtk"; then
    DISPLAY_OPT="gtk,show-cursor=on"
elif qemu-system-aarch64 -display help 2>&1 | grep -q "sdl"; then
    DISPLAY_OPT="sdl,show-cursor=on"
fi

echo "Selected display backend: $DISPLAY_OPT"

exec qemu-system-aarch64 \
    -M virt \
    -cpu cortex-a53 \
    -smp 2 \
    -m "$MEMORY" \
    -kernel "$KERNEL" \
    -initrd "$INITRD" \
    -append "console=tty0 console=ttyAMA0 video=${WIDTH}x${HEIGHT}-32 earlycon devtmpfs.mount=1 rw" \
    -device virtio-gpu-pci,xres=$WIDTH,yres=$HEIGHT \
    -device virtio-tablet-pci \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    -display "$DISPLAY_OPT" \
    -serial stdio
