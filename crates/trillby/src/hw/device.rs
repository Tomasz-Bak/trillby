//! Physical device hardware adapter.

use embedded_graphics::geometry::Point;
use trillby_core::Point as CorePoint;
use trillby_ui::{LayoutZones, SCREEN_HEIGHT, SCREEN_WIDTH};

#[inline(always)]
pub fn configure_network() {}

#[inline(always)]
pub fn default_server_ip() -> [u8; 4] {
    [127, 0, 0, 1]
}

pub struct DeviceAdapter;

impl DeviceAdapter {
    #[inline(always)]
    pub fn new() -> Self {
        Self
    }

    #[inline(always)]
    pub fn drop_fd(&mut self, _fd: libc::c_int) -> bool {
        false
    }

    #[inline(always)]
    pub fn register_poll(&self, _poll_set: &mut crate::hw::PollSet) {}

    #[inline(always)]
    pub fn handle_fd(
        &mut self,
        _pfd: &libc::pollfd,
        _state: &mut crate::AppState,
        _zones: &LayoutZones,
    ) -> bool {
        false
    }

    #[inline(always)]
    pub fn scale_touch(&self, raw_x: i32, raw_y: i32) -> Point {
        Point::new(
            raw_x.clamp(0, SCREEN_WIDTH as i32 - 1),
            raw_y.clamp(0, SCREEN_HEIGHT as i32 - 1),
        )
    }

    #[inline(always)]
    pub fn log_touch_down(&self, _raw_x: i32, _raw_y: i32, _scaled: CorePoint) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_adapter_scale_touch_clamping() {
        let adapter = DeviceAdapter::new();

        assert_eq!(adapter.scale_touch(-10, -20), Point::new(0, 0));
        assert_eq!(adapter.scale_touch(0, 0), Point::new(0, 0));
        assert_eq!(
            adapter.scale_touch(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1),
            Point::new(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1)
        );
        assert_eq!(
            adapter.scale_touch(SCREEN_WIDTH as i32, SCREEN_HEIGHT as i32),
            Point::new(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1)
        );
        assert_eq!(
            adapter.scale_touch(10_000, 10_000),
            Point::new(SCREEN_WIDTH as i32 - 1, SCREEN_HEIGHT as i32 - 1)
        );
    }

}
