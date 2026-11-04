#![no_std]

pub mod event;
pub mod geometry;
pub mod header;
pub mod keyboard_types;
pub mod net_types;
pub mod state;

pub use event::UiEvent;
pub use geometry::{Point, Rect};
pub use header::HeaderButton;
pub use keyboard_types::{Key, KeyboardLayer};
pub use net_types::NetworkStatus;
pub use state::{Screen, UiState};

/// Target idle poll frequency in Hertz (Hz).
pub const POLL_FREQ_HZ: u32 = 20;

/// Idle poll timeout in milliseconds for POSIX `poll`.
pub const POLL_TIMEOUT_MS: i32 = (1000 / POLL_FREQ_HZ) as i32;
