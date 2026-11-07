//! Fixed header-bar geometry, shared by the renderer (drawing) and
//! `UiState` (hit-testing) so the two can never drift apart.

use crate::geometry::{Point, Rect};

pub const HEADER_HEIGHT: u32 = 36;

pub const HEADER_BUTTON_INSET: i32 = 4;
pub const HEADER_BUTTON_H: u32 = HEADER_HEIGHT - 2 * HEADER_BUTTON_INSET as u32;

pub const DEBUG_BUTTON: Rect = Rect::new(Point::new(410, HEADER_BUTTON_INSET), 110, HEADER_BUTTON_H);
pub const KEYBOARD_BUTTON: Rect = Rect::new(Point::new(530, HEADER_BUTTON_INSET), 120, HEADER_BUTTON_H);
pub const CLEAR_BUTTON: Rect = Rect::new(Point::new(660, HEADER_BUTTON_INSET), 120, HEADER_BUTTON_H);

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
        [Self::Debug, Self::Keyboard, Self::Clear]
            .into_iter()
            .find(|b| {
                let r = b.rect();
                Rect::new(Point::new(r.top_left.x, 0), r.width, HEADER_HEIGHT).contains(p)
            })
    }
}

pub const DEBUG_PANEL: Rect = Rect::new(Point::new(275, 96), 250, 180);

const fn debug_button_rect(col: u32, row: u32) -> Rect {
    let x = DEBUG_PANEL.top_left.x + 12 + (col as i32 * 117);
    let y = DEBUG_PANEL.top_left.y + 94 + (row as i32 * 44);
    Rect::new(Point::new(x, y), 109, 36)
}

pub const DEBUG_AUTH_USER_BUTTON: Rect = debug_button_rect(0, 0);
pub const DEBUG_START_JOB_BUTTON: Rect = debug_button_rect(1, 0);
pub const DEBUG_STOP_JOB_BUTTON: Rect = debug_button_rect(0, 1);
pub const DEBUG_LOGOUT_BUTTON: Rect = debug_button_rect(1, 1);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DebugButton {
    AuthUser,
    StartJob,
    StopJob,
    Logout,
}

impl DebugButton {
    pub const fn rect(self) -> Rect {
        match self {
            Self::AuthUser => DEBUG_AUTH_USER_BUTTON,
            Self::StartJob => DEBUG_START_JOB_BUTTON,
            Self::StopJob => DEBUG_STOP_JOB_BUTTON,
            Self::Logout => DEBUG_LOGOUT_BUTTON,
        }
    }

    pub fn at(p: Point) -> Option<Self> {
        [Self::AuthUser, Self::StartJob, Self::StopJob, Self::Logout]
            .into_iter()
            .find(|b| b.rect().contains(p))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_button_fat_finger_vertical_tolerance_and_horizontal_gaps() {
        // Spanning full 0..HEADER_HEIGHT despite DEBUG_BUTTON having y = 4, height = 28
        assert_eq!(HeaderButton::at(Point::new(410, 0)), Some(HeaderButton::Debug));
        assert_eq!(HeaderButton::at(Point::new(519, 0)), Some(HeaderButton::Debug));
        assert_eq!(HeaderButton::at(Point::new(410, 35)), Some(HeaderButton::Debug));
        assert_eq!(HeaderButton::at(Point::new(519, 35)), Some(HeaderButton::Debug));

        // Outside vertical bounds
        assert_eq!(HeaderButton::at(Point::new(450, -1)), None);
        assert_eq!(HeaderButton::at(Point::new(450, 36)), None);

        // Horizontal boundaries and 10px dead zones at y = 15
        assert_eq!(HeaderButton::at(Point::new(409, 15)), None);
        assert_eq!(HeaderButton::at(Point::new(410, 15)), Some(HeaderButton::Debug));
        assert_eq!(HeaderButton::at(Point::new(519, 15)), Some(HeaderButton::Debug));
        assert_eq!(HeaderButton::at(Point::new(520, 15)), None);
        assert_eq!(HeaderButton::at(Point::new(529, 15)), None);

        assert_eq!(HeaderButton::at(Point::new(530, 15)), Some(HeaderButton::Keyboard));
        assert_eq!(HeaderButton::at(Point::new(649, 15)), Some(HeaderButton::Keyboard));
        assert_eq!(HeaderButton::at(Point::new(650, 15)), None);
        assert_eq!(HeaderButton::at(Point::new(659, 15)), None);

        assert_eq!(HeaderButton::at(Point::new(660, 15)), Some(HeaderButton::Clear));
        assert_eq!(HeaderButton::at(Point::new(779, 15)), Some(HeaderButton::Clear));
        assert_eq!(HeaderButton::at(Point::new(780, 15)), None);
    }

    #[test]
    fn debug_button_exact_rectangles_and_inter_button_gaps() {
        // AuthUser: 287..396, 190..226
        assert_eq!(DebugButton::at(Point::new(287, 190)), Some(DebugButton::AuthUser));
        assert_eq!(DebugButton::at(Point::new(395, 190)), Some(DebugButton::AuthUser));
        assert_eq!(DebugButton::at(Point::new(287, 225)), Some(DebugButton::AuthUser));
        assert_eq!(DebugButton::at(Point::new(395, 225)), Some(DebugButton::AuthUser));

        // StartJob: 404..513, 190..226
        assert_eq!(DebugButton::at(Point::new(404, 190)), Some(DebugButton::StartJob));
        assert_eq!(DebugButton::at(Point::new(512, 190)), Some(DebugButton::StartJob));
        assert_eq!(DebugButton::at(Point::new(404, 225)), Some(DebugButton::StartJob));
        assert_eq!(DebugButton::at(Point::new(512, 225)), Some(DebugButton::StartJob));

        // StopJob: 287..396, 234..270
        assert_eq!(DebugButton::at(Point::new(287, 234)), Some(DebugButton::StopJob));
        assert_eq!(DebugButton::at(Point::new(395, 234)), Some(DebugButton::StopJob));
        assert_eq!(DebugButton::at(Point::new(287, 269)), Some(DebugButton::StopJob));
        assert_eq!(DebugButton::at(Point::new(395, 269)), Some(DebugButton::StopJob));

        // Logout: 404..513, 234..270
        assert_eq!(DebugButton::at(Point::new(404, 234)), Some(DebugButton::Logout));
        assert_eq!(DebugButton::at(Point::new(512, 234)), Some(DebugButton::Logout));
        assert_eq!(DebugButton::at(Point::new(404, 269)), Some(DebugButton::Logout));
        assert_eq!(DebugButton::at(Point::new(512, 269)), Some(DebugButton::Logout));

        // Exclusive right/bottom edges
        assert_eq!(DebugButton::at(Point::new(396, 200)), None);
        assert_eq!(DebugButton::at(Point::new(513, 200)), None);
        assert_eq!(DebugButton::at(Point::new(300, 226)), None);
        assert_eq!(DebugButton::at(Point::new(450, 226)), None);
        assert_eq!(DebugButton::at(Point::new(300, 270)), None);
        assert_eq!(DebugButton::at(Point::new(450, 270)), None);

        // 8px horizontal gap (x = 400, y = 200) and 8px vertical gap (x = 300, y = 230)
        assert_eq!(DebugButton::at(Point::new(400, 200)), None);
        assert_eq!(DebugButton::at(Point::new(300, 230)), None);
    }
}
