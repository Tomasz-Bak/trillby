//! Linux `evdev` (`/dev/input/event*`) touchscreen input handler.

use crate::BufferWriter;
use core::fmt::Write;
use trillby_core::{Point as CorePoint, UiEvent};
use trillby_ui::LayoutZones;

// From <linux/input-event-codes.h>
#[allow(dead_code)]
pub(crate) const EV_SYN: u16 = 0;
#[allow(dead_code)]
pub(crate) const SYN_REPORT: u16 = 0;
pub(crate) const EV_KEY: u16 = 1;
pub(crate) const EV_REL: u16 = 2;
pub(crate) const EV_ABS: u16 = 3;

pub(crate) const REL_X: u16 = 0;
pub(crate) const REL_Y: u16 = 1;

pub(crate) const ABS_X: u16 = 0;
pub(crate) const ABS_Y: u16 = 1;
pub(crate) const ABS_MT_POSITION_X: u16 = 53;
pub(crate) const ABS_MT_POSITION_Y: u16 = 54;

pub(crate) const BTN_LEFT: u16 = 272;
pub(crate) const BTN_TOUCH: u16 = 330;

pub(crate) const RAW_AXIS_MAX: i32 = 32767;
pub(crate) const REL_STEP: i32 = 10;
pub(crate) const MAX_EVDEV_DEVICES: usize = 10;
const DEV_PATH_BUF_LEN: usize = 32;
pub struct EvdevTouch {
    fds: [libc::c_int; MAX_EVDEV_DEVICES],
    count: usize,
    raw_x: i32,
    raw_y: i32,
    is_touch_down: bool,
    touch_moved: bool,
}

impl EvdevTouch {
    pub fn new() -> Self {
        let mut fds = [-1; MAX_EVDEV_DEVICES];
        let mut count = 0;

        for i in 0..MAX_EVDEV_DEVICES {
            let mut path_buf = [0u8; DEV_PATH_BUF_LEN];
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

    #[cfg(test)]
    pub(crate) fn with_fds(fds: &[libc::c_int]) -> Self {
        assert!(fds.len() <= MAX_EVDEV_DEVICES);
        let mut dev_fds = [-1; MAX_EVDEV_DEVICES];
        dev_fds[..fds.len()].copy_from_slice(fds);
        Self {
            fds: dev_fds,
            count: fds.len(),
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        }
    }

    pub fn register_poll(&self, poll_set: &mut super::PollSet) {
        for &fd in &self.fds[..self.count] {
            if fd >= 0 {
                poll_set.push(fd, libc::POLLIN);
            }
        }
    }

    pub fn drop_fd(&mut self, fd: libc::c_int) -> bool {
        if let Some(i) = self.fds[..self.count].iter().position(|&f| f == fd) {
            unsafe { libc::close(fd) };
            self.fds[i] = self.fds[self.count - 1];
            self.fds[self.count - 1] = -1;
            self.count -= 1;
            crate::print_fmt(format_args!("WARN: input fd {} hung up; closed\n", fd));
            true
        } else {
            false
        }
    }

    pub fn handle_fd(
        &mut self,
        pfd: &libc::pollfd,
        adapter: &super::adapter::DeviceAdapter,
        state: &mut crate::AppState,
        zones: &LayoutZones,
    ) -> bool {
        if !self.fds[..self.count].contains(&pfd.fd) {
            return false;
        }

        loop {
            let mut events = [libc::input_event {
                time: libc::timeval { tv_sec: 0, tv_usec: 0 },
                type_: 0,
                code: 0,
                value: 0,
            }; 64];
            let n = unsafe {
                libc::read(
                    pfd.fd,
                    events.as_mut_ptr() as *mut _,
                    events.len() * core::mem::size_of::<libc::input_event>(),
                )
            };
            if n < 0 {
                let errno = unsafe { *libc::__errno_location() };
                if errno == libc::EINTR {
                    continue;
                } else if errno == libc::EAGAIN {
                    break;
                } else {
                    self.drop_fd(pfd.fd);
                    break;
                }
            } else if n == 0 {
                break;
            }
            let ev_count = n as usize / core::mem::size_of::<libc::input_event>();
            for ev in &events[..ev_count] {
                match ev.type_ {
                    EV_ABS => {
                        if ev.code == ABS_X || ev.code == ABS_MT_POSITION_X {
                            self.raw_x = ev.value;
                            self.touch_moved = true;
                        } else if ev.code == ABS_Y || ev.code == ABS_MT_POSITION_Y {
                            self.raw_y = ev.value;
                            self.touch_moved = true;
                        }
                    }
                    EV_REL => {
                        if ev.code == REL_X {
                            self.raw_x = (self.raw_x + ev.value * REL_STEP).clamp(0, RAW_AXIS_MAX);
                            self.touch_moved = true;
                        } else if ev.code == REL_Y {
                            self.raw_y = (self.raw_y + ev.value * REL_STEP).clamp(0, RAW_AXIS_MAX);
                            self.touch_moved = true;
                        }
                    }
                    EV_KEY if ev.code == BTN_TOUCH || ev.code == BTN_LEFT => {
                        let eg_pt = adapter.scale_touch(self.raw_x, self.raw_y);
                        let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
                        if ev.value == 1 {
                            self.is_touch_down = true;
                            self.touch_moved = false;
                            adapter.log_touch_down(self.raw_x, self.raw_y, core_pt);
                            trillby_ui::dispatch_touch(
                                state,
                                zones,
                                UiEvent::TouchDown {
                                    scaled: core_pt,
                                    raw: (self.raw_x, self.raw_y),
                                },
                            );
                        } else if ev.value == 0 {
                            self.is_touch_down = false;
                            self.touch_moved = false;
                            trillby_ui::dispatch_touch(
                                state,
                                zones,
                                UiEvent::TouchUp {
                                    scaled: core_pt,
                                    raw: (self.raw_x, self.raw_y),
                                },
                            );
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
        state: &mut crate::AppState,
        zones: &LayoutZones,
    ) {
        if self.is_touch_down && self.touch_moved {
            let eg_pt = adapter.scale_touch(self.raw_x, self.raw_y);
            let core_pt = CorePoint::new(eg_pt.x, eg_pt.y);
            trillby_ui::dispatch_touch(
                state,
                zones,
                UiEvent::TouchMove {
                    scaled: core_pt,
                    raw: (self.raw_x, self.raw_y),
                },
            );
            self.touch_moved = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hw::test_util::{write_event, PipeFds, UiFixture};

    fn setup_test_pipe() -> (PipeFds, EvdevTouch) {
        let pipe = PipeFds::new();
        let touch = EvdevTouch::with_fds(&[pipe.rfd]);
        (pipe, touch)
    }

    #[test]
    fn test_evdev_hover_abs_without_btn_touch() {
        let (pipe, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut ui = UiFixture::new();

        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        write_event(pipe.wfd, EV_ABS, ABS_X, 100);
        write_event(pipe.wfd, EV_ABS, ABS_Y, 200);

        let handled = touch.handle_fd(&pfd, &adapter, &mut ui.state, &ui.zones);
        assert!(handled);
        assert_eq!(touch.raw_x, 100);
        assert_eq!(touch.raw_y, 200);
        assert!(!touch.is_touch_down);
        assert!(touch.touch_moved);

        touch.finish_poll_step(&adapter, &mut ui.state, &ui.zones);
        assert_eq!(ui.state.last_touch_scaled, None);
        assert_eq!(ui.state.touch_count, 0);
    }

    #[test]
    fn test_evdev_btn_touch_batching_and_coalesced_touch_move() {
        let (pipe, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut ui = UiFixture::new();

        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        write_event(pipe.wfd, EV_KEY, BTN_TOUCH, 1);
        write_event(pipe.wfd, EV_ABS, ABS_X, 300);
        write_event(pipe.wfd, EV_ABS, ABS_Y, 200);
        write_event(pipe.wfd, EV_REL, REL_X, 5);
        write_event(pipe.wfd, EV_REL, REL_Y, 5);

        let handled = touch.handle_fd(&pfd, &adapter, &mut ui.state, &ui.zones);
        assert!(handled);
        assert_eq!(touch.raw_x, 350);
        assert_eq!(touch.raw_y, 250);
        assert!(touch.is_touch_down);
        assert!(touch.touch_moved);
        assert_eq!(ui.state.touch_count, 1);

        touch.finish_poll_step(&adapter, &mut ui.state, &ui.zones);
        assert_eq!(ui.state.touch_count, 1);
        let expected_scaled = adapter.scale_touch(350, 250);
        assert_eq!(ui.state.last_touch_scaled, Some(CorePoint::new(expected_scaled.x, expected_scaled.y)));
        assert!(!touch.touch_moved);
    }

    #[test]
    fn test_evdev_rel_clamping_at_zero_and_32767() {
        let (pipe, mut touch) = setup_test_pipe();
        let adapter = super::super::adapter::DeviceAdapter::new();
        let mut ui = UiFixture::new();

        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        touch.raw_x = 100;
        touch.raw_y = 100;

        write_event(pipe.wfd, EV_REL, REL_X, -5000);
        write_event(pipe.wfd, EV_REL, REL_Y, -5000);
        touch.handle_fd(&pfd, &adapter, &mut ui.state, &ui.zones);
        assert_eq!(touch.raw_x, 0);
        assert_eq!(touch.raw_y, 0);

        write_event(pipe.wfd, EV_REL, REL_X, 5000);
        write_event(pipe.wfd, EV_REL, REL_Y, 5000);
        touch.handle_fd(&pfd, &adapter, &mut ui.state, &ui.zones);
        assert_eq!(touch.raw_x, RAW_AXIS_MAX);
        assert_eq!(touch.raw_y, RAW_AXIS_MAX);
    }

    #[test]
    fn test_evdev_drop_fd_closes_and_compacts() {
        let _guard = super::super::tests::FD_TEST_LOCK.lock().unwrap();
        let mut pipe1 = PipeFds::new();
        let orig_rfd1 = pipe1.rfd;
        let rfd1 = unsafe { libc::fcntl(orig_rfd1, libc::F_DUPFD_CLOEXEC, 500) };
        assert!(rfd1 >= 500);
        unsafe { libc::close(orig_rfd1) };
        pipe1.rfd = -1;

        let pipe2 = PipeFds::new();
        let rfd2 = pipe2.rfd;

        let mut touch = EvdevTouch {
            fds: [-1; MAX_EVDEV_DEVICES],
            count: 2,
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        };
        touch.fds[0] = rfd1;
        touch.fds[1] = rfd2;

        assert!(touch.drop_fd(rfd1));
        assert_eq!(touch.count, 1);
        assert_eq!(touch.fds[0], rfd2);
        assert_eq!(touch.fds[1], -1);
        assert!(!touch.drop_fd(rfd1));
        assert_eq!(unsafe { libc::fcntl(rfd1, libc::F_GETFD) }, -1);
    }

    #[test]
    fn test_evdev_drop_unknown_fd_returns_false() {
        let mut touch = EvdevTouch {
            fds: [-1; MAX_EVDEV_DEVICES],
            count: 0,
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        };
        assert!(!touch.drop_fd(999));
        assert_eq!(touch.count, 0);
    }

    #[test]
    fn test_evdev_register_poll() {
        let mut touch = EvdevTouch {
            fds: [-1; MAX_EVDEV_DEVICES],
            count: 2,
            raw_x: 0,
            raw_y: 0,
            is_touch_down: false,
            touch_moved: false,
        };
        touch.fds[0] = 42;
        touch.fds[1] = 43;

        let mut poll_set = super::super::PollSet::new();
        touch.register_poll(&mut poll_set);

        assert_eq!(poll_set.len(), 2);
        assert_eq!(poll_set.as_slice()[0].fd, 42);
        assert_eq!(poll_set.as_slice()[0].events, libc::POLLIN);
        assert_eq!(poll_set.as_slice()[1].fd, 43);
        assert_eq!(poll_set.as_slice()[1].events, libc::POLLIN);
    }
}
