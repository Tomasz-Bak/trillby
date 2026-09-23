#!/usr/bin/env bash
# Trillby Raspberry Pi Zero 2 W Kernel Build Script
set -euo pipefail

KERNEL_DIR="${1:-./linux}"
CONFIG_SRC="$(pwd)/kernel/rpi_zero2w_defconfig"
ARCH="arm64"

# Add LLVM binaries to PATH if available
export PATH="/usr/lib/llvm/22/bin:/usr/lib/llvm/21/bin:$PATH"

# Auto-detect toolchain: GCC cross-compiler or LLVM/Clang
if command -v aarch64-unknown-linux-gnu-gcc &>/dev/null; then
    MAKE_ARGS="ARCH=$ARCH CROSS_COMPILE=aarch64-unknown-linux-gnu-"
    echo "==> Toolchain selected: GCC (aarch64-unknown-linux-gnu-gcc)"
elif command -v aarch64-linux-gnu-gcc &>/dev/null; then
    MAKE_ARGS="ARCH=$ARCH CROSS_COMPILE=aarch64-linux-gnu-"
    echo "==> Toolchain selected: GCC (aarch64-linux-gnu-gcc)"
elif command -v clang &>/dev/null; then
    MAKE_ARGS="ARCH=$ARCH LLVM=1"
    echo "==> Toolchain selected: LLVM / Clang (target=aarch64-linux-gnu)"
else
    echo "ERROR: Neither GCC cross-compiler nor Clang found!"
    echo "Please install 'cross-aarch64-unknown-linux-gnu/gcc' or 'clang'."
    exit 1
fi

echo "============================================================"
echo " Trillby Raspberry Pi Zero 2 W Kernel Build (Linux 6.6 LTS)"
echo " Config: $CONFIG_SRC"
echo "============================================================"

if [ ! -d "$KERNEL_DIR" ]; then
    echo "Usage: $0 <path-to-linux-source-tree>"
    echo ""
    echo "To fetch the official Raspberry Pi Linux kernel source tree:"
    echo "  git clone --depth=1 -b rpi-6.6.y https://github.com/raspberrypi/linux.git"
    echo ""
    echo "Then run:"
    echo "  $0 ./linux"
    exit 1
fi

cd "$KERNEL_DIR"
echo "==> Copying kernel config..."
cp "$CONFIG_SRC" .config

echo "==> Expanding config..."
make $MAKE_ARGS olddefconfig

echo "==> Building kernel Image, modules, and Device Tree Blobs (dtbs)..."
make $MAKE_ARGS -j"$(nproc)" Image modules dtbs

echo "============================================================"
echo " ==> Kernel build completed successfully!"
echo "     Kernel Image: $KERNEL_DIR/arch/arm64/boot/Image"
echo "     DTB:          $KERNEL_DIR/arch/arm64/boot/dts/broadcom/bcm2710-rpi-zero-2-w.dtb"
echo "============================================================"
