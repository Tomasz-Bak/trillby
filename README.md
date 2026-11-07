# Trillby

`#![no_std]` Linux PID-1 shop-floor terminal for Raspberry Pi Zero 2 W (800×480 RGB565 framebuffer UI, evdev touch/RFID/barcode input, PSK-authenticated ChaCha20-Poly1305 TCP telemetry) and companion `trillby-server` floor sink.

## Crates

| Crate | Target | Role |
|---|---|---|
| `trillby-core` | `no_std` | Pure state machine: operator session, job timer, virtual keyboard, layout geometry |
| `trillby-ui` | `no_std` | `embedded-graphics` RGB565 renderer, dark floor theme, widgets, keyboard grid |
| `trillby-net` | `no_std` | Zero-alloc POSIX sockets, ChaCha20-Poly1305 / SHA-256 / HKDF, durable outbox, client & server |
| `trillby` | `no_std` (`#main`) | PID-1 appliance binary: mounts `/proc`/`/sys`/`/dev`, drives `poll(2)`, writes `/dev/fb0` |
| `trillby-server` | `std` | Host floor server: device registry, session key derivation, structured stdout event log |

## Usage

```sh
# Unit, integration, E2E, and CLI smoke tests
./scripts/run_host_tests.sh

# Line coverage (enforces COVERAGE_FLOOR=93%)
./scripts/coverage.sh

# Provision a device key + append to server registry
./scripts/provision_device.sh

# Build static aarch64-unknown-linux-musl binary and boot in QEMU virt
./scripts/run_qemu_system.sh

# Build RPi Zero 2 W kernel (Image, modules, dtbs)
./scripts/build_kernel.sh ./linux
```

See [`ARCHITECTURE.md`](ARCHITECTURE.md) for wire protocol, state machine, and module details.
