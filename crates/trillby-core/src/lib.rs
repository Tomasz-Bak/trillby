#![no_std]

pub mod event;
pub mod geometry;
pub mod header;
pub mod keyboard_types;
pub mod net_types;
pub mod session;
pub mod state;

pub use event::UiEvent;
pub use geometry::{Point, Rect};
pub use header::{
    DebugButton, HeaderButton, CLEAR_BUTTON, DEBUG_AUTH_USER_BUTTON, DEBUG_BUTTON,
    DEBUG_LOGOUT_BUTTON, DEBUG_PANEL, DEBUG_START_JOB_BUTTON, DEBUG_STOP_JOB_BUTTON, HEADER_HEIGHT,
    KEYBOARD_BUTTON,
};
pub use keyboard_types::{Key, KeyboardLayer};
pub use net_types::NetworkStatus;
pub use session::{
    OperatorSession, SessionEvent, SessionRejectReason, SessionState, DUMMY_JOB_ID,
    DUMMY_OPERATOR_ID, MAX_JOB_ID_LEN, MAX_OPERATOR_ID_LEN,
};
pub use state::{Screen, UiState, EVENT_HISTORY_LEN, EVENT_LOG_LINE_CAP};
pub use state::Truncating;

/// Target idle poll frequency in Hertz (Hz).
pub const POLL_FREQ_HZ: u32 = 20;

/// Idle poll timeout in milliseconds for POSIX `poll`.
pub const POLL_TIMEOUT_MS: i32 = (1000 / POLL_FREQ_HZ) as i32;

/// Appends characters from `s` to `dst` until `s` is exhausted or `dst` is full.
/// Returns `true` if all characters fit, or `false` if truncated.
pub(crate) fn push_truncated<const CAP: usize>(dst: &mut heapless::String<CAP>, s: &str) -> bool {
    for ch in s.chars() {
        if dst.push(ch).is_err() {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use heapless::String;

    #[test]
    fn test_push_truncated_fits() {
        let mut s: String<8> = String::new();
        assert!(push_truncated(&mut s, "hello"));
        assert_eq!(s.as_str(), "hello");
    }

    #[test]
    fn test_push_truncated_overflow() {
        let mut s: String<4> = String::new();
        assert!(!push_truncated(&mut s, "hello"));
        assert_eq!(s.as_str(), "hell");
    }

    #[test]
    fn test_push_truncated_multibyte() {
        let mut s: String<4> = String::new();
        // 🦀 is 4 bytes
        assert!(push_truncated(&mut s, "🦀"));
        assert_eq!(s.as_str(), "🦀");

        let mut s2: String<4> = String::new();
        // 'a' (1 byte) + '🦀' (4 bytes) = 5 bytes, does not fit
        assert!(!push_truncated(&mut s2, "a🦀"));
        assert_eq!(s2.as_str(), "a");
    }
}
