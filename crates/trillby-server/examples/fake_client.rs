//! Smoke-test client: connects with the dev credentials, sends one badge login,
//! a work start/stop cycle, an operator logout, and one heartbeat, waits for ACKs, then exits.
//!
//!   cargo run -p trillby-server -- --dev &
//!   cargo run -p trillby-server --example fake_client [port]

use trillby_net::{AuthInitPayload, HeartbeatPayload, NetClient, WorkEventPayload};

fn step<const N: usize>(c: &mut NetClient<N>) {
    let fd = c.socket_fd();
    let mut revents = 0;
    if fd >= 0 {
        let mut events = libc::POLLIN;
        if c.wants_write() {
            events |= libc::POLLOUT;
        }
        let mut p = libc::pollfd { fd, events, revents: 0 };
        if unsafe { libc::poll(&mut p, 1, 20) } > 0 {
            revents = p.revents;
        }
    }
    c.poll_step_with(trillby_net::monotonic_ms(), revents, |_, _| {});
}

fn main() {
    let port = std::env::args().nth(1).and_then(|p| p.parse().ok()).unwrap_or(8088);
    let mut c = NetClient::<8>::new([0x42; 32], *b"TRILLBY_0001\0\0\0\0", [127, 0, 0, 1], port);

    // Enqueue events immediately while offline: tests that events queued before
    // handshake are correctly sealed with the established session key upon connection.

    let mut auth = AuthInitPayload { auth_data_len: 8, auth_data: [0; 32], timestamp_ms: 1000 };
    auth.auth_data[..8].copy_from_slice(b"BADGE042");
    c.send_auth(&auth).unwrap();
    c.send_work_event(&WorkEventPayload::work_start(b"BADGE042", b"LOT-2026-0042", 1100))
        .unwrap();
    c.send_work_event(&WorkEventPayload::work_stop(b"BADGE042", b"LOT-2026-0042", 2600, 1500))
        .unwrap();
    c.send_work_event(&WorkEventPayload::operator_logout(b"BADGE042", 2700))
        .unwrap();
    c.send_heartbeat(&HeartbeatPayload { battery_pct: 87, rssi: -61, pending_outbox: 0, uptime_s: 42 })
        .unwrap();

    let deadline = trillby_net::monotonic_ms() + 5000;
    while trillby_net::monotonic_ms() < deadline {
        step(&mut c);
        if c.outbox_pending_count() == 0 {
            println!("all events ACKed");
            return;
        }
    }
    eprintln!("timeout: {} events still pending (status {:?})", c.outbox_pending_count(), c.status());
    std::process::exit(1);
}
