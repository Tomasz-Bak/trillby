//! Hardware facade and platform-specific device adapters.

mod evdev;

#[cfg_attr(feature = "qemu-sim", path = "qemu.rs")]
#[cfg_attr(not(feature = "qemu-sim"), path = "device.rs")]
mod adapter;

pub use adapter::{configure_network, default_server_ip};

use trillby_core::{Rect, UiState};
use trillby_ui::LayoutZones;

pub struct Hardware {
    touch: evdev::EvdevTouch,
    adapter: adapter::DeviceAdapter,
}

impl Hardware {
    pub fn new() -> Self {
        Self {
            adapter: adapter::DeviceAdapter::new(),
            touch: evdev::EvdevTouch::new(),
        }
    }

    pub fn register_poll(&self, pollfds: &mut [libc::pollfd], poll_count: &mut usize) {
        self.adapter.register_poll(pollfds, poll_count);
        self.touch.register_poll(pollfds, poll_count);
    }

    pub fn handle_poll(
        &mut self,
        pollfds: &[libc::pollfd],
        state: &mut UiState<256>,
        zones: &LayoutZones,
        core_bounds: Rect,
        core_kb_bounds: Option<Rect>,
    ) {
        for pfd in pollfds {
            if (pfd.revents & libc::POLLIN) != 0 {
                if self
                    .adapter
                    .handle_fd(pfd, state, zones, core_bounds, core_kb_bounds)
                {
                    continue;
                }
                let _ = self.touch.handle_fd(
                    pfd,
                    &self.adapter,
                    state,
                    zones,
                    core_bounds,
                    core_kb_bounds,
                );
            }
        }
        self.touch.finish_poll_step(
            &self.adapter,
            state,
            zones,
            core_bounds,
            core_kb_bounds,
        );
    }
}
