# Product Requirements Document
## Handheld Production Floor Scanner — Rust Client

---

### 1. Work Context

**Team:** Small production line (~20 operators), internal tooling initiative.
**Platform:** Raspberry Pi Zero 2 W running a minimal Gentoo Linux image, deployed as a handheld device on the production floor.
**Constraint:** Parts are on order. Development begins with UI/simulator work and integrates hardware incrementally. Physical enclosure is handled separately (3D printing). The Rust client must be lean, high-performance, and portable — designed with a future custom PCB migration in mind.

---

### 2. Problem Statement

Operators currently record work manually into a legacy Windows application. This creates:
- Data entry friction and errors
- No real-time floor visibility for leadership
- Reliance on manual observation or social pressure to gather timing data
- No reliable operator accountability trail

---

### 3. Goals & Success Criteria

- Operators can identify themselves via RFID card and begin logging work with minimal interaction
- Work session metrics (start, pause/resume, finish, QA notes) are captured automatically with timestamps
- Data is transmitted to a local floor server in real time
- Leadership has live floor status without needing to ask or observe
- The binary runs efficiently within the Pi Zero 2 W's 512MB RAM constraint
- At end of 4 weeks: fully functional software + hardware integration, ready for enclosure

---

### 4. Hardware Bill of Materials

| Component | Choice | Function |
|---|---|---|
| SBC | Raspberry Pi Zero 2 W | Quad-core ARM64, Wi-Fi |
| Display | Waveshare 4.0" DSI Capacitive LCD | DSI display + I2C touch |
| RFID | NXP PN532 Breakout | 13.56MHz NFC/RFID via I2C |
| Barcode | Grow GM67 2D Imager | USB HID barcode scanner |
| Power/RTC | PiSugar 3 Zero | Battery management via I2C |
| Battery | 3.7V 2500mAh LiPo | JST-PH 2.0 to PiSugar |

---

### 5. Core Deliverables

#### 5.1 UI Module (Week 1–2, pre-hardware)
- Pixel-buffer rendering via [embedded-graphics](https://github.com/embedded-graphics/embedded-graphics) + [embedded-graphics-framebuf](https://github.com/bernii/embedded-graphics-framebuf) targeting the Linux framebuffer (`/dev/fb0`)
- Touch input handling over I2C (Waveshare DSI panel)
- Screens: Login (card prompt), Work Session (start/pause/resume/finish), QA Notes input, Status/confirmation
- Desktop simulator mode for development before hardware arrives

#### 5.2 Hardware Integration Module (Week 2–3, on hardware arrival)
- GPIO/I2C peripheral access via [rppal](https://github.com/golemparts/rppal)
- PN532 RFID/NFC card reader via [pn532-rs](https://github.com/Funcoil/pn532-rs) over I2C — operator identity
- GM67 barcode scanner via USB HID using [hidapi-rs](https://github.com/ruabmbua/hidapi-rs)
- PiSugar 3 battery telemetry via I2C (battery level display)

#### 5.3 Business Logic Module (Week 2–3)
- Operator session state machine:
  - `Idle → Authenticated → WorkStarted → Paused ⇄ Running → Finished`
- Timestamped event log: process start, pause/unpause vector, finish
- QA notes capture (touchscreen keyboard or barcode-driven input)
- Local session buffer — queues events if network is unavailable

#### 5.4 Network Module (Week 3–4)
- Lightweight async runtime via [smol](https://github.com/smol-rs/smol) with [async-net](https://github.com/smol-rs/async-net) and [async-io](https://github.com/smol-rs/async-io)
- TLS-encrypted transport via [rustls](https://github.com/rustls/rustls)
- Sends standardized JSON payloads to the local floor server
- Designed to optionally forward aggregated data upstream to the company API (deferred)

---

### 6. Scope & Constraints

#### In Scope (4 weeks)
- Full Rust client binary: UI, hardware drivers, business logic, networking
- Runs on Gentoo minimal image on Pi Zero 2 W
- Targets the specific hardware BOM above
- Local floor server communication (basic REST or custom protocol TBD)

#### Deferred
- Physical enclosure (handled externally)
- Local floor server implementation
- Upstream company API integration
- Multi-device fleet management
- Custom PCB design
- Camera/image capture for QA documentation

#### Constraints
- 512MB RAM — no heap-heavy frameworks, no GUI runtime dependencies
- Must cross-compile for `aarch64-unknown-linux-gnu` from a development machine
- Network protocol and encryption must be production-safe from day one (operator identity data)
- No shell dependencies at runtime — single self-contained binary

---

### 7. Suggested Weekly Timeline

| Week | Focus |
|---|---|
| 1 | UI module: framebuffer rendering, touch input, screen layouts, desktop simulator |
| 2 | Business logic: session state machine, event model, local buffering |
| 3 | Hardware integration: PN532 (RFID), GM67 (HID), PiSugar (I2C telemetry) |
| 4 | Network module: async transport, TLS, JSON payloads, end-to-end integration |
