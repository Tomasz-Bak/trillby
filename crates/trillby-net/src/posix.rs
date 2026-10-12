//! Minimal POSIX Non-Blocking Socket Wrapper (#![no_std])
//!
//! Encapsulates all unsafe libc syscalls into a centralized `sys` facade,
//! providing a safe, zero-allocation socket abstraction.

extern crate libc;

mod sys {
    extern crate libc;

    #[inline]
    pub fn last_errno() -> libc::c_int {
        unsafe { *libc::__errno_location() }
    }

    #[inline]
    unsafe fn cvt_int(ret: libc::c_int) -> Result<libc::c_int, libc::c_int> {
        if ret < 0 {
            Err(last_errno())
        } else {
            Ok(ret)
        }
    }

    #[inline]
    unsafe fn cvt_ssize(ret: libc::ssize_t) -> Result<usize, libc::c_int> {
        if ret < 0 {
            Err(last_errno())
        } else {
            Ok(ret as usize)
        }
    }

    pub fn socket(domain: libc::c_int, type_: libc::c_int, protocol: libc::c_int) -> Result<libc::c_int, libc::c_int> {
        unsafe { cvt_int(libc::socket(domain, type_, protocol)) }
    }

    pub fn connect(fd: libc::c_int, addr: &libc::sockaddr_in) -> Result<bool, libc::c_int> {
        let ret = unsafe {
            libc::connect(
                fd,
                addr as *const _ as *const libc::sockaddr,
                core::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            )
        };
        if ret == 0 {
            Ok(true)
        } else {
            let errno = last_errno();
            if errno == libc::EINPROGRESS {
                Ok(false)
            } else {
                Err(errno)
            }
        }
    }

    pub fn getsockopt_error(fd: libc::c_int) -> Result<(), libc::c_int> {
        let mut err: libc::c_int = 0;
        let mut len = core::mem::size_of::<libc::c_int>() as libc::socklen_t;
        unsafe {
            cvt_int(libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                &mut err as *mut _ as *mut libc::c_void,
                &mut len,
            ))?;
        }
        if err != 0 {
            Err(err)
        } else {
            Ok(())
        }
    }

    pub fn send(fd: libc::c_int, data: &[u8], flags: libc::c_int) -> Result<usize, libc::c_int> {
        unsafe { cvt_ssize(libc::send(fd, data.as_ptr() as *const libc::c_void, data.len(), flags)) }
    }

    pub fn recv(fd: libc::c_int, buf: &mut [u8], flags: libc::c_int) -> Result<usize, libc::c_int> {
        unsafe { cvt_ssize(libc::recv(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len(), flags)) }
    }

    pub fn close(fd: libc::c_int) {
        unsafe {
            libc::close(fd);
        }
    }

    pub fn monotonic_ms() -> u64 {
        let mut ts = libc::timespec { tv_sec: 0, tv_nsec: 0 };
        unsafe {
            libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut ts);
        }
        (ts.tv_sec as u64) * 1000 + (ts.tv_nsec as u64) / 1_000_000
    }
}

/// Query the Linux monotonic clock (CLOCK_MONOTONIC) in milliseconds.
/// Pure zero-allocation, vDSO-backed on Linux AArch64 (~15ns overhead).
pub fn monotonic_ms() -> u64 {
    sys::monotonic_ms()
}

pub struct PosixSocket {
    fd: libc::c_int,
}

impl PosixSocket {
    pub const fn invalid() -> Self {
        Self { fd: -1 }
    }

    pub fn new_nonblocking_tcp() -> Result<Self, libc::c_int> {
        sys::socket(
            libc::AF_INET,
            libc::SOCK_STREAM | libc::SOCK_NONBLOCK,
            0,
        )
        .map(|fd| Self { fd })
    }

    pub fn fd(&self) -> libc::c_int {
        self.fd
    }

    pub fn is_open(&self) -> bool {
        self.fd >= 0
    }

    /// Initiate non-blocking connection to an IPv4 address and port.
    /// Returns `Ok(true)` if connected immediately, `Ok(false)` if `EINPROGRESS`, or `Err(errno)`.
    pub fn connect_ipv4(&self, ip: [u8; 4], port: u16) -> Result<bool, libc::c_int> {
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: port.to_be(),
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip),
            },
            sin_zero: [0; 8],
        };
        sys::connect(self.fd, &addr)
    }

    /// Check SO_ERROR on the socket after `poll` indicates writability (POLLOUT).
    pub fn check_connect_completed(&self) -> Result<(), libc::c_int> {
        sys::getsockopt_error(self.fd)
    }

    /// Non-blocking send. Returns number of bytes sent, or Err(errno).
    pub fn send(&self, data: &[u8]) -> Result<usize, libc::c_int> {
        sys::send(self.fd, data, libc::MSG_DONTWAIT | libc::MSG_NOSIGNAL)
    }

    /// Non-blocking recv. Returns number of bytes received (0 = disconnected), or Err(errno).
    pub fn recv(&self, buf: &mut [u8]) -> Result<usize, libc::c_int> {
        sys::recv(self.fd, buf, libc::MSG_DONTWAIT)
    }

    pub fn close(&mut self) {
        if self.fd >= 0 {
            sys::close(self.fd);
            self.fd = -1;
        }
    }
}

impl Drop for PosixSocket {
    fn drop(&mut self) {
        self.close();
    }
}
