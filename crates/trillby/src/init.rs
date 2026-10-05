//! PID-1 responsibilities, kept in the binary (not on the kernel command line)
//! so they travel with the app when the kernel/bootloader is swapped.

use crate::{console, raw_print};
use core::ffi::CStr;
use core::fmt::Write;

/// Pseudo-filesystems PID 1 must mount itself: with an initramfs root the
/// kernel does not auto-mount devtmpfs (CONFIG_DEVTMPFS_MOUNT only applies to
/// a block-device root), and nothing else is around to do it.
const MOUNTS: &[(&CStr, &CStr)] = &[
    // (mount point, filesystem type)
    (c"/proc", c"proc"),
    (c"/sys", c"sysfs"),
    (c"/dev", c"devtmpfs"),
];

/// One-time system bring-up when running as init. No-op otherwise, so the
/// binary can still be started from a shell during development.
pub fn setup_pid1() {
    if unsafe { libc::getpid() } != 1 {
        return;
    }
    raw_print("Running as PID 1: mounting pseudo-filesystems\n");
    for &(target, fstype) in MOUNTS {
        mount_pseudo_fs(target, fstype);
    }
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

/// Print `"<what> <path> failed: errno <n>"` without allocating.
pub fn log_errno(what: &str, path: &CStr) {
    let errno = unsafe { *libc::__errno_location() };
    let mut line: heapless::String<96> = heapless::String::new();
    let _ = writeln!(
        line,
        "WARN: {} {} failed: errno {}",
        what,
        path.to_str().unwrap_or("?"),
        errno
    );
    raw_print(&line);
}
