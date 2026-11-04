//! Physical device hardware adapter.

use embedded_graphics::geometry::Point;
use trillby_core::{Point as CorePoint, Rect, UiState};
use trillby_ui::LayoutZones;

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
    pub fn register_poll(&self, _pollfds: &mut [libc::pollfd], _poll_count: &mut usize) {}

    #[inline(always)]
    pub fn handle_fd(
        &mut self,
        _pfd: &libc::pollfd,
        _state: &mut UiState<256>,
        _zones: &LayoutZones,
        _core_bounds: Rect,
        _core_kb_bounds: Option<Rect>,
    ) -> bool {
        false
    }

    #[inline(always)]
    pub fn scale_touch(&self, raw_x: i32, raw_y: i32) -> Point {
        // Physical touchscreens report direct 1:1 pixel coordinates (0..799, 0..479)
        Point::new(raw_x.clamp(0, 799), raw_y.clamp(0, 479))
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
        assert_eq!(adapter.scale_touch(799, 479), Point::new(799, 479));
        assert_eq!(adapter.scale_touch(800, 480), Point::new(799, 479));
        assert_eq!(adapter.scale_touch(10_000, 10_000), Point::new(799, 479));
    }
}
