//! Hardware facade and platform-specific device adapters.

pub(crate) mod evdev;

#[cfg_attr(feature = "qemu-sim", path = "qemu.rs")]
#[cfg_attr(not(feature = "qemu-sim"), path = "device.rs")]
mod adapter;

pub use adapter::{configure_network, default_server_ip};

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

    pub fn register_poll(&self, poll_set: &mut PollSet) {
        self.adapter.register_poll(poll_set);
        self.touch.register_poll(poll_set);
    }

    pub fn handle_poll(
        &mut self,
        pollfds: &[libc::pollfd],
        state: &mut crate::AppState,
        zones: &LayoutZones,
    ) {
        for pfd in pollfds {
            if (pfd.revents & libc::POLLIN) != 0
                && !self
                    .adapter
                    .handle_fd(pfd, state, zones)
            {
                let _ = self.touch.handle_fd(
                    pfd,
                    &self.adapter,
                    state,
                    zones,
                );
            }
            if pfd.revents & (libc::POLLHUP | libc::POLLERR | libc::POLLNVAL) != 0
                && !self.adapter.drop_fd(pfd.fd)
            {
                self.touch.drop_fd(pfd.fd);
            }
        }
        self.touch.finish_poll_step(
            &self.adapter,
            state,
            zones,
        );
    }
}

pub const MAX_POLL_FDS: usize = 16;
const _: () = assert!(evdev::MAX_EVDEV_DEVICES + 2 <= MAX_POLL_FDS);

pub struct PollSet {
    fds: [libc::pollfd; MAX_POLL_FDS],
    len: usize,
}

impl PollSet {
    pub const fn new() -> Self {
        Self {
            fds: [libc::pollfd { fd: -1, events: 0, revents: 0 }; MAX_POLL_FDS],
            len: 0,
        }
    }

    pub fn push(&mut self, fd: libc::c_int, events: i16) -> usize {
        let idx = self.len;
        if idx < MAX_POLL_FDS {
            self.fds[idx] = libc::pollfd { fd, events, revents: 0 };
            self.len += 1;
        }
        idx
    }

    pub fn as_mut_slice(&mut self) -> &mut [libc::pollfd] {
        &mut self.fds[..self.len]
    }

    pub fn as_slice(&self) -> &[libc::pollfd] {
        &self.fds[..self.len]
    }

    pub fn revents(&self, idx: usize) -> i16 {
        if idx < self.len {
            self.fds[idx].revents
        } else {
            0
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl Default for PollSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::test_util::{write_event, PipeFds, UiFixture};

    pub(crate) static FD_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_adapter() -> adapter::DeviceAdapter {
        #[cfg(feature = "qemu-sim")]
        {
            adapter::DeviceAdapter::with_tty_fd(-1)
        }
        #[cfg(not(feature = "qemu-sim"))]
        {
            adapter::DeviceAdapter::new()
        }
    }

    #[test]
    fn test_poll_set() {
        let mut ps = PollSet::new();
        assert!(ps.is_empty());
        assert_eq!(ps.len(), 0);
        assert_eq!(ps.revents(0), 0);

        let idx0 = ps.push(10, libc::POLLIN);
        assert_eq!(idx0, 0);
        assert_eq!(ps.len(), 1);
        assert!(!ps.is_empty());
        assert_eq!(ps.as_slice()[0].fd, 10);
        assert_eq!(ps.as_slice()[0].events, libc::POLLIN);

        ps.as_mut_slice()[0].revents = libc::POLLIN;
        assert_eq!(ps.revents(0), libc::POLLIN);
        assert_eq!(ps.revents(1), 0);

        let idx1 = ps.push(11, libc::POLLOUT);
        assert_eq!(idx1, 1);
        assert_eq!(ps.len(), 2);

        for i in 2..MAX_POLL_FDS {
            let idx = ps.push(100 + i as libc::c_int, libc::POLLIN);
            assert_eq!(idx, i);
        }
        assert_eq!(ps.len(), MAX_POLL_FDS);

        let overflow_idx = ps.push(999, libc::POLLIN);
        assert_eq!(overflow_idx, MAX_POLL_FDS);
        assert_eq!(ps.len(), MAX_POLL_FDS);
        assert_eq!(ps.revents(overflow_idx), 0);
    }
    #[test]
    fn hardware_handle_poll_hangup_closes_input_fd() {
        let _guard = FD_TEST_LOCK.lock().unwrap();
        let mut pipe = PipeFds::new();
        let orig_rfd = pipe.rfd;
        let rfd = unsafe { libc::fcntl(orig_rfd, libc::F_DUPFD_CLOEXEC, 500) };
        assert!(rfd >= 500);
        unsafe { libc::close(orig_rfd) };
        pipe.rfd = -1;

        let mut hw = Hardware {
            touch: evdev::EvdevTouch::with_fds(&[rfd]),
            adapter: test_adapter(),
        };

        unsafe { libc::close(pipe.wfd) };
        pipe.wfd = -1;

        let mut pfd = libc::pollfd {
            fd: rfd,
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pfd, 1, 10) };
        assert!(ret > 0);
        assert!((pfd.revents & libc::POLLHUP) != 0);

        let mut ui = UiFixture::new();
        hw.handle_poll(&[pfd], &mut ui.state, &ui.zones);

        assert_eq!(unsafe { libc::fcntl(rfd, libc::F_GETFD) }, -1);

        let mut ps = PollSet::new();
        hw.register_poll(&mut ps);
        assert_eq!(ps.len(), 0);
    }

    #[test]
    fn hardware_handle_poll_routes_touch_to_evdev() {
        let pipe = PipeFds::new();

        write_event(pipe.wfd, evdev::EV_KEY, evdev::BTN_TOUCH, 1);
        write_event(pipe.wfd, evdev::EV_SYN, evdev::SYN_REPORT, 0);
        write_event(pipe.wfd, evdev::EV_KEY, evdev::BTN_TOUCH, 0);
        write_event(pipe.wfd, evdev::EV_SYN, evdev::SYN_REPORT, 0);

        let mut hw = Hardware {
            touch: evdev::EvdevTouch::with_fds(&[pipe.rfd]),
            adapter: test_adapter(),
        };

        let mut ui = UiFixture::new();

        let mut pfd = pipe.readable_pollfd();
        pfd.revents = libc::POLLIN;

        hw.handle_poll(&[pfd], &mut ui.state, &ui.zones);

        assert_eq!(ui.state.touch_count, 1);
    }
}

#[cfg(test)]
pub(crate) mod test_util {
    use embedded_graphics::geometry::{Point, Size};
    use embedded_graphics::primitives::Rectangle;
    use trillby_ui::layout::LayoutZones;
    use trillby_ui::{SCREEN_HEIGHT, SCREEN_WIDTH};

    pub struct PipeFds {
        pub rfd: libc::c_int,
        pub wfd: libc::c_int,
    }

    impl PipeFds {
        pub fn new() -> Self {
            let mut fds = [0; 2];
            let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK) };
            assert_eq!(rc, 0);
            Self {
                rfd: fds[0],
                wfd: fds[1],
            }
        }

        pub fn readable_pollfd(&self) -> libc::pollfd {
            libc::pollfd {
                fd: self.rfd,
                events: libc::POLLIN,
                revents: 0,
            }
        }
    }

    impl Default for PipeFds {
        fn default() -> Self {
            Self::new()
        }
    }

    impl Drop for PipeFds {
        fn drop(&mut self) {
            if self.rfd >= 0 {
                unsafe { libc::close(self.rfd) };
                self.rfd = -1;
            }
            if self.wfd >= 0 {
                unsafe { libc::close(self.wfd) };
                self.wfd = -1;
            }
        }
    }

    pub fn write_event(fd: libc::c_int, type_: u16, code: u16, value: i32) {
        #[repr(C)]
        struct InputEvent {
            time: libc::timeval,
            type_: u16,
            code: u16,
            value: i32,
        }
        let ev = InputEvent {
            time: libc::timeval { tv_sec: 0, tv_usec: 0 },
            type_,
            code,
            value,
        };
        let n = unsafe {
            libc::write(
                fd,
                &ev as *const _ as *const libc::c_void,
                core::mem::size_of::<InputEvent>(),
            )
        };
        assert_eq!(n as usize, core::mem::size_of::<InputEvent>());
    }

    pub struct UiFixture {
        pub state: crate::AppState,
        pub zones: LayoutZones,
    }

    impl UiFixture {
        pub fn new() -> Self {
            let state = crate::AppState::new();
            let screen_bounds = Rectangle::new(
                Point::zero(),
                Size::new(SCREEN_WIDTH, SCREEN_HEIGHT),
            );
            let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
            Self { state, zones }
        }

        #[allow(dead_code)]
        pub fn refresh(&mut self) {
            let screen_bounds = Rectangle::new(
                Point::zero(),
                Size::new(SCREEN_WIDTH, SCREEN_HEIGHT),
            );
            self.zones = LayoutZones::compute(screen_bounds, self.state.keyboard_visible);
        }
    }

    impl Default for UiFixture {
        fn default() -> Self {
            Self::new()
        }
    }
}
