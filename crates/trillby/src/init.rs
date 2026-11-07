//! PID-1 responsibilities, kept in the binary (not on the kernel command line)
//! so they travel with the app when the kernel/bootloader is swapped.

use crate::{console, raw_print};
use core::ffi::CStr;

/// Pseudo-filesystems PID 1 must mount itself: with an initramfs root the
/// kernel does not auto-mount devtmpfs (CONFIG_DEVTMPFS_MOUNT only applies to
/// a block-device root), and nothing else is around to do it.
const MOUNTS: &[(&CStr, &CStr)] = &[
    // (mount point, filesystem type)
    (c"/proc", c"proc"),
    (c"/sys", c"sysfs"),
    (c"/dev", c"devtmpfs"),
];

#[allow(dead_code)] // kernel ABI layout
#[repr(C)]
struct IfreqAddr {
    ifr_name: [u8; 16],
    ifr_addr: libc::sockaddr_in,
    _pad: [u8; 8],
}

#[allow(dead_code)] // kernel ABI layout
#[repr(C)]
struct IfreqFlags {
    ifr_name: [u8; 16],
    ifr_flags: libc::c_short,
    _pad: [u8; 22],
}

#[inline]
pub(crate) fn is_pid1() -> bool {
    unsafe { libc::getpid() == 1 }
}

/// One-time system bring-up when running as init. No-op otherwise, so the
/// binary can still be started from a shell during development.
pub fn setup_pid1() {
    if !is_pid1() {
        return;
    }
    raw_print("Running as PID 1: mounting pseudo-filesystems\n");
    for &(target, fstype) in MOUNTS {
        mount_pseudo_fs(target, fstype);
    }
    configure_ipv4_iface(c"lo", [127, 0, 0, 1], [255, 0, 0, 0]);
    crate::hw::configure_network();
    // After /dev exists: needs /dev/tty0.
    console::enter_graphics_mode();
}

fn mount_pseudo_fs(target: &CStr, fstype: &CStr) {
    unsafe {
        // EEXIST is fine (the initramfs usually ships the directory).
        libc::mkdir(target.as_ptr(), 0o755);
        if libc::mount(fstype.as_ptr(), target.as_ptr(), fstype.as_ptr(), 0, core::ptr::null()) != 0 {
            log_errno("mount", target);
        }
    }
}

fn ifreq_addr(ifr_name: [u8; 16], ip: [u8; 4]) -> IfreqAddr {
    IfreqAddr {
        ifr_name,
        ifr_addr: libc::sockaddr_in {
            sin_family: libc::AF_INET as libc::sa_family_t,
            sin_port: 0,
            sin_addr: libc::in_addr {
                s_addr: u32::from_ne_bytes(ip),
            },
            sin_zero: [0; 8],
        },
        _pad: [0; 8],
    }
}

unsafe fn set_iface(
    fd: libc::c_int,
    ifr_name: [u8; 16],
    ip: [u8; 4],
    netmask: [u8; 4],
) -> Result<(), &'static str> {
    let addr_req = ifreq_addr(ifr_name, ip);
    if libc::ioctl(fd, libc::SIOCSIFADDR as _, &addr_req) != 0 {
        return Err("SIOCSIFADDR");
    }

    let mask_req = ifreq_addr(ifr_name, netmask);
    if libc::ioctl(fd, libc::SIOCSIFNETMASK as _, &mask_req) != 0 {
        return Err("SIOCSIFNETMASK");
    }

    let flags_req = IfreqFlags {
        ifr_name,
        ifr_flags: (libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short,
        _pad: [0; 22],
    };
    if libc::ioctl(fd, libc::SIOCSIFFLAGS as _, &flags_req) != 0 {
        return Err("SIOCSIFFLAGS");
    }

    Ok(())
}

pub(crate) fn configure_ipv4_iface(ifname: &CStr, ip: [u8; 4], netmask: [u8; 4]) {
    let name_bytes = ifname.to_bytes_with_nul();
    if name_bytes.len() > 16 {
        return;
    }
    let mut ifr_name = [0u8; 16];
    ifr_name[..name_bytes.len()].copy_from_slice(name_bytes);

    unsafe {
        let fd = libc::socket(libc::AF_INET, libc::SOCK_DGRAM | libc::SOCK_CLOEXEC, 0);
        if fd < 0 {
            log_errno("socket(AF_INET) for", ifname);
            return;
        }

        if let Err(step) = set_iface(fd, ifr_name, ip, netmask) {
            log_errno(step, ifname);
        }

        libc::close(fd);
    }
}

/// Print `"<what> <path> failed: errno <n>"` without allocating.
pub fn log_errno(what: &str, path: &CStr) {
    let errno = unsafe { *libc::__errno_location() };
    crate::print_fmt(format_args!(
        "WARN: {} {} failed: errno {}\n",
        what,
        path.to_str().unwrap_or("?"),
        errno
    ));
}

