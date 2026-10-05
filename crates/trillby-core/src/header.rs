//! Fixed header-bar geometry, shared by the renderer (drawing) and
//! `UiState` (hit-testing) so the two can never drift apart.

use crate::geometry::{Point, Rect};

pub const HEADER_HEIGHT: u32 = 36;

pub const KEYBOARD_BUTTON: Rect = Rect::new(Point::new(510, 4), 130, 28);
pub const CLEAR_BUTTON: Rect = Rect::new(Point::new(650, 4), 130, 28);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeaderButton {
    Keyboard,
    Clear,
}

impl HeaderButton {
    pub const fn rect(self) -> Rect {
        match self {
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
        [Self::Keyboard, Self::Clear].into_iter().find(|b| {
            let r = b.rect();
            p.x >= r.top_left.x && p.x < r.top_left.x + r.width as i32
        })
    }
}
