//! Fixed header-bar geometry, shared by the renderer (drawing) and
//! `UiState` (hit-testing) so the two can never drift apart.

use crate::geometry::{Point, Rect};

pub const HEADER_HEIGHT: u32 = 36;

pub const DEBUG_BUTTON: Rect = Rect::new(Point::new(410, 4), 110, 28);
pub const KEYBOARD_BUTTON: Rect = Rect::new(Point::new(530, 4), 120, 28);
pub const CLEAR_BUTTON: Rect = Rect::new(Point::new(660, 4), 120, 28);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderButton {
    Debug,
    Keyboard,
    Clear,
}

impl HeaderButton {
    pub const fn rect(self) -> Rect {
        match self {
            Self::Debug => DEBUG_BUTTON,
            Self::Keyboard => KEYBOARD_BUTTON,
            Self::Clear => CLEAR_BUTTON,
        }
    }

    /// Hit-test a touch against the header buttons. The hit area spans the
    /// full header height (not just the drawn button) for fat-finger tolerance.
    pub fn at(p: Point) -> Option<Self> {
        if p.y < 0 || p.y >= HEADER_HEIGHT as i32 {
            return None;
        }
        [Self::Debug, Self::Keyboard, Self::Clear]
            .into_iter()
            .find(|b| {
                let r = b.rect();
                p.x >= r.top_left.x && p.x < r.top_left.x + r.width as i32
            })
    }
}

pub const DEBUG_STOP_JOB_BUTTON: Rect = Rect::new(Point::new(287, 190), 226, 36);
pub const DEBUG_LOGOUT_BUTTON: Rect = Rect::new(Point::new(287, 234), 226, 36);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugButton {
    StopJob,
    Logout,
}

impl DebugButton {
    pub const fn rect(self) -> Rect {
        match self {
            Self::StopJob => DEBUG_STOP_JOB_BUTTON,
            Self::Logout => DEBUG_LOGOUT_BUTTON,
        }
    }

    pub fn at(p: Point) -> Option<Self> {
        [Self::StopJob, Self::Logout]
            .into_iter()
            .find(|b| b.rect().contains(p))
    }
}
