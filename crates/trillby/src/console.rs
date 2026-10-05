//! Kernel virtual-console control.

use crate::init::log_errno;

// From <linux/kd.h>
const KDSETMODE: libc::c_ulong = 0x4B3A;
const KD_GRAPHICS: libc::c_ulong = 0x01;

/// Put the active VT into graphics mode so fbcon stops drawing on top of our
/// framebuffer (blinking cursor block, late printk output).
///
/// Done here rather than via `vt.global_cursor_default=0` on the kernel
/// command line so it can't get lost when the kernel/bootloader is swapped,
/// and because it also silences console text, not just the cursor.
/// The mode belongs to the VT, not the fd, so closing the fd keeps it.
pub fn enter_graphics_mode() {
    let path = c"/dev/tty0"; // tty0 = the currently active VT
    unsafe {
        let fd = libc::open(path.as_ptr(), libc::O_RDWR | libc::O_CLOEXEC);
        if fd < 0 {
            log_errno("open", path);
            return;
        }
        if libc::ioctl(fd, KDSETMODE, KD_GRAPHICS) != 0 {
            log_errno("KDSETMODE(KD_GRAPHICS) on", path);
        }
        libc::close(fd);
    }
}
