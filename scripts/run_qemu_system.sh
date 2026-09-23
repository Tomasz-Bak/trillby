#!/usr/bin/env bash
# Trillby QEMU 800x480 Graphical Machine Launcher
set -euo pipefail

MEMORY="512M"
WIDTH=800
HEIGHT=480
KERNEL="$(pwd)/linux/arch/arm64/boot/Image"
INITRD="$(pwd)/initramfs.cpio.gz"

echo "============================================================"
echo " Launching Trillby QEMU 800x480 Graphical Machine"
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
CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_LINKER=aarch64-unknown-linux-gnu-gcc \
RUSTFLAGS="-C target-feature=+crt-static" \
RUSTC_BOOTSTRAP=1 \
cargo build -Z build-std --target aarch64-unknown-linux-gnu --features qemu-sim

STAGING_DIR="$(pwd)/target/initramfs_staging"
echo "==> Packaging initramfs with static Trillby binary as /init..."
rm -rf "$STAGING_DIR"
mkdir -p "$STAGING_DIR"/{dev,proc,sys,etc}
cp target/aarch64-unknown-linux-gnu/debug/trillby "$STAGING_DIR/init"
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
    -display "$DISPLAY_OPT" \
    -serial stdio


