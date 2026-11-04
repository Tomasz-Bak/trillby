//! Linux `evdev` (`/dev/input/event*`) touchscreen input handler.

use crate::BufferWriter;
use core::fmt::Write;
use trillby_core::{Point as CorePoint, Rect, UiEvent, UiState};
use trillby_ui::{KeyboardGrid, LayoutZones};

#[repr(C)]
#[derive(Debug, Copy, Clone, Default)]
pub struct InputEvent {
    pub time: libc::timeval,
    pub type_: u16,
    pub code: u16,
    pub value: i32,
}

pub struct EvdevTouch {
    fds: [libc::c_int; 10],
    count: usize,
    raw_x: i32,
    raw_y: i32,
    is_touch_down: bool,
    touch_moved: bool,
}

impl EvdevTouch {
    pub fn new() -> Self {
        let mut fds = [-1; 10];
        let mut count = 0;

        for i in 0..10 {
            let mut path_buf = [0u8; 32];
            let mut w = BufferWriter::new(&mut path_buf);
            let _ = write!(w, "/dev/input/event{}\0", i);

            let fd = unsafe {
                libc::open(
                    path_buf.as_ptr() as *const _,
                    libc::O_RDONLY | libc::O_NONBLOCK,
                )
            };
            if fd >= 0 {
                fds[count] = fd;
                count += 1;
            }
        }

        Self {
            fds,
            count,
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        }
    }

    pub fn register_poll(&self, pollfds: &mut [libc::pollfd], poll_count: &mut usize) {
        for i in 0..self.count {
            pollfds[*poll_count] = libc::pollfd {
                fd: self.fds[i],
                events: libc::POLLIN,
                revents: 0,
            };
            *poll_count += 1;
        }
    }

    pub fn handle_fd(
        &mut self,
        pfd: &libc::pollfd,
        adapter: &super::adapter::DeviceAdapter,
        state: &mut UiState<256>,
        zones: &LayoutZones,
        core_bounds: Rect,
        core_kb_bounds: Option<Rect>,
    ) -> bool {
        if !self.fds[..self.count].contains(&pfd.fd) {
            return false;
        }

        loop {
            let mut events = [InputEvent::default(); 64];
            let n = unsafe {
                libc::read(
                    pfd.fd,
                    events.as_mut_ptr() as *mut _,
                    events.len() * core::mem::size_of::<InputEvent>(),
                )
            };
            if n <= 0 {
                break;
            }
            let ev_count = n as usize / core::mem::size_of::<InputEvent>();
            for ev in &events[..ev_count] {
                match ev.type_ {
                    3 => {
                        // EV_ABS
                        if ev.code == 0 || ev.code == 53 {
                            self.raw_x = ev.value;
                            self.touch_moved = true;
                        } else if ev.code == 1 || ev.code == 54 {
                            self.raw_y = ev.value;
                            self.touch_moved = true;
                        }
                    }
                    2 => {
                        // EV_REL
                        if ev.code == 0 {
                            self.raw_x = (self.raw_x + ev.value * 10).clamp(0, 32767);
                            self.touch_moved = true;
                        } else if ev.code == 1 {
                            self.raw_y = (self.raw_y + ev.value * 10).clamp(0, 32767);
                            self.touch_moved = true;
                        }
                    }
                    1 => {
                        // EV_KEY
                        if ev.code == 330 || ev.code == 272 {
                            // BTN_TOUCH or BTN_LEFT
                            let eg_pt = adapter.scale_touch(self.raw_x, self.raw_y);
                            let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
                            if ev.value == 1 {
                                self.is_touch_down = true;
                                self.touch_moved = false;
                                adapter.log_touch_down(self.raw_x, self.raw_y, core_pt);
                                let key = zones.keyboard_area.and_then(|kb| {
                                    KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_layer)
                                });
                                state.handle_event(
                                    UiEvent::TouchDown {
                                        scaled: core_pt,
                                        raw: (self.raw_x, self.raw_y),
                                    },
                                    core_bounds,
                                    core_kb_bounds,
                                    key,
                                );
                            } else if ev.value == 0 {
                                self.is_touch_down = false;
                                self.touch_moved = false;
                                let key = zones.keyboard_area.and_then(|kb| {
                                    KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_layer)
                                });
                                state.handle_event(
                                    UiEvent::TouchUp {
                                        scaled: core_pt,
                                        raw: (self.raw_x, self.raw_y),
                                    },
                                    core_bounds,
                                    core_kb_bounds,
                                    key,
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }

        true
    }

    pub fn finish_poll_step(
        &mut self,
        adapter: &super::adapter::DeviceAdapter,
        state: &mut UiState<256>,
        zones: &LayoutZones,
        core_bounds: Rect,
        core_kb_bounds: Option<Rect>,
    ) {
        if self.is_touch_down && self.touch_moved {
            let eg_pt = adapter.scale_touch(self.raw_x, self.raw_y);
            let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
            let key = zones
                .keyboard_area
                .and_then(|kb| KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_layer));
            state.handle_event(
                UiEvent::TouchMove {
                    scaled: core_pt,
                    raw: (self.raw_x, self.raw_y),
                },
                core_bounds,
                core_kb_bounds,
                key,
            );
            self.touch_moved = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::geometry::{Point, Size};
    use embedded_graphics::primitives::Rectangle;
    use trillby_ui::eg_rect_to_core;

    fn write_event(wfd: libc::c_int, type_: u16, code: u16, value: i32) {
        let ev = InputEvent {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            type_,
            code,
            value,
        };
        let n = unsafe {
            libc::write(
                wfd,
                &ev as *const _ as *const libc::c_void,
                core::mem::size_of::<InputEvent>(),
            )
        };
        assert_eq!(n as usize, core::mem::size_of::<InputEvent>());
    }

    fn setup_test_pipe() -> (libc::c_int, libc::c_int, EvdevTouch) {
        let mut pipe_fds = [0; 2];
        let rc = unsafe { libc::pipe2(pipe_fds.as_mut_ptr(), libc::O_NONBLOCK) };
        assert_eq!(rc, 0);
        let rfd = pipe_fds[0];
        let wfd = pipe_fds[1];

        let touch = EvdevTouch {
            fds: [rfd, -1, -1, -1, -1, -1, -1, -1, -1, -1],
            count: 1,
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        };

        (rfd, wfd, touch)
    }

    #[test]
    fn test_evdev_hover_abs_without_btn_touch() {
        let (rfd, wfd, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut state = UiState::<256>::new();
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
        let core_bounds = eg_rect_to_core(screen_bounds);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        let pfd = libc::pollfd {
            fd: rfd,
            events: libc::POLLIN,
            revents: libc::POLLIN,
        };

        write_event(wfd, 3, 0, 100);
        write_event(wfd, 3, 1, 200);

        let handled = touch.handle_fd(&pfd, &adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert!(handled);
        assert_eq!(touch.raw_x, 100);
        assert_eq!(touch.raw_y, 200);
        assert!(!touch.is_touch_down);
        assert!(touch.touch_moved);

        touch.finish_poll_step(&adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert_eq!(state.last_touch_scaled, None);
        assert_eq!(state.touch_count, 0);

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    }

    #[test]
    fn test_evdev_btn_touch_batching_and_coalesced_touch_move() {
        let (rfd, wfd, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut state = UiState::<256>::new();
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
        let core_bounds = eg_rect_to_core(screen_bounds);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        let pfd = libc::pollfd {
            fd: rfd,
            events: libc::POLLIN,
            revents: libc::POLLIN,
        };

        write_event(wfd, 1, 330, 1);
        write_event(wfd, 3, 0, 300);
        write_event(wfd, 3, 1, 200);
        write_event(wfd, 2, 0, 5);
        write_event(wfd, 2, 1, 5);

        let handled = touch.handle_fd(&pfd, &adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert!(handled);
        assert_eq!(touch.raw_x, 350);
        assert_eq!(touch.raw_y, 250);
        assert!(touch.is_touch_down);
        assert!(touch.touch_moved);
        assert_eq!(state.touch_count, 1);

        touch.finish_poll_step(&adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert_eq!(state.touch_count, 1);
        let expected_scaled = adapter.scale_touch(350, 250);
        assert_eq!(state.last_touch_scaled, Some(CorePoint::new(expected_scaled.x, expected_scaled.y)));
        assert!(!touch.touch_moved);

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    }

    #[test]
    fn test_evdev_rel_clamping_at_zero_and_32767() {
        let (rfd, wfd, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut state = UiState::<256>::new();
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
        let core_bounds = eg_rect_to_core(screen_bounds);
        let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

        let pfd = libc::pollfd {
            fd: rfd,
            events: libc::POLLIN,
            revents: libc::POLLIN,
        };

        touch.raw_x = 100;
        touch.raw_y = 100;

        write_event(wfd, 2, 0, -5000);
        write_event(wfd, 2, 1, -5000);
        touch.handle_fd(&pfd, &adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert_eq!(touch.raw_x, 0);
        assert_eq!(touch.raw_y, 0);

        write_event(wfd, 2, 0, 5000);
        write_event(wfd, 2, 1, 5000);
        touch.handle_fd(&pfd, &adapter, &mut state, &zones, core_bounds, core_kb_bounds);
        assert_eq!(touch.raw_x, 32767);
        assert_eq!(touch.raw_y, 32767);

        unsafe {
            libc::close(rfd);
            libc::close(wfd);
        }
    }
}
