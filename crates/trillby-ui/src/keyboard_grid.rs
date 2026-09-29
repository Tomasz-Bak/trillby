use embedded_graphics::geometry::Point;
use embedded_graphics::primitives::Rectangle;
use trillby_core::keyboard_types::{Key, KeyboardMode};

pub struct KeyboardGrid;

impl KeyboardGrid {
    pub const ROWS: usize = 4;
    pub const COLS: usize = 10;

    const STANDARD: [&'static str; 3] = [
        "QWERTYUIOP",
        "ASDFGHJKL ",
        "ZXCVBNM,. ",
    ];

    const EXTENDED: [&'static str; 3] = [
        "1234567890",
        "-/:;()$&@ ",
        ".,?!'\"#%* ",
    ];

    /// Resolve a touch point inside keyboard bounds to a Key enum.
    pub fn resolve_key(bounds: Rectangle, point: Point, mode: KeyboardMode) -> Option<Key> {
        if mode == KeyboardMode::Hidden || !bounds.contains(point) {
            return None;
        }

        let row_h = bounds.size.height as i32 / Self::ROWS as i32;
        if row_h == 0 {
            return None;
        }

        let rel_x = point.x - bounds.top_left.x;
        let rel_y = point.y - bounds.top_left.y;
        let row = (rel_y / row_h).clamp(0, Self::ROWS as i32 - 1) as usize;

        if row == 3 {
            // Row 3: Control Row (MODE [0..2], SPACE [2..6], BACKSPACE [6..8], ENTER [8..10])
            let total_w = bounds.size.width as i32;
            let unit_w = total_w / 10;

            if rel_x < unit_w * 2 {
                Some(Key::ModeSwitch)
            } else if rel_x < unit_w * 6 {
                Some(Key::Space)
            } else if rel_x < unit_w * 8 {
                Some(Key::Backspace)
            } else {
                Some(Key::Enter)
            }
        } else {
            // Rows 0..=2: Standard 10-column character rows
            let col_w = bounds.size.width as i32 / Self::COLS as i32;
            if col_w == 0 {
                return None;
            }
            let col = (rel_x / col_w).clamp(0, Self::COLS as i32 - 1) as usize;

            let layout = match mode {
                KeyboardMode::Standard => &Self::STANDARD,
                KeyboardMode::Extended => &Self::EXTENDED,
                KeyboardMode::Hidden => return None,
            };

            let ch = layout[row].as_bytes().get(col).copied().map(|b| b as char)?;
            if ch != ' ' {
                Some(Key::Char(ch))
            } else {
                None
            }
        }
    }

    pub fn get_key_char(row: usize, col: usize, mode: KeyboardMode) -> Option<char> {
        if row >= 3 {
            return None;
        }
        let layout = match mode {
            KeyboardMode::Standard => &Self::STANDARD,
            KeyboardMode::Extended => &Self::EXTENDED,
            KeyboardMode::Hidden => return None,
        };
        layout[row].as_bytes().get(col).copied().map(|b| b as char).filter(|&c| c != ' ')
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::geometry::Size;

    #[test]
    fn test_key_resolution_standard() {
        let bounds = Rectangle::new(Point::new(0, 300), Size::new(800, 180));

        // Top-left key (Q)
        let key_q = KeyboardGrid::resolve_key(bounds, Point::new(10, 310), KeyboardMode::Standard);
        assert_eq!(key_q, Some(Key::Char('Q')));

        // Top-right key (P)
        let key_p = KeyboardGrid::resolve_key(bounds, Point::new(750, 310), KeyboardMode::Standard);
        assert_eq!(key_p, Some(Key::Char('P')));

        // Row 4 MODE switch
        let key_mode = KeyboardGrid::resolve_key(bounds, Point::new(50, 450), KeyboardMode::Standard);
        assert_eq!(key_mode, Some(Key::ModeSwitch));

        // Row 4 SPACE bar
        let key_space = KeyboardGrid::resolve_key(bounds, Point::new(300, 450), KeyboardMode::Standard);
        assert_eq!(key_space, Some(Key::Space));

        // Row 4 BACKSPACE key
        let key_bk = KeyboardGrid::resolve_key(bounds, Point::new(550, 450), KeyboardMode::Standard);
        assert_eq!(key_bk, Some(Key::Backspace));

        // Row 4 ENTER key
        let key_enter = KeyboardGrid::resolve_key(bounds, Point::new(700, 450), KeyboardMode::Standard);
        assert_eq!(key_enter, Some(Key::Enter));
    }

    #[test]
    fn test_key_resolution_extended() {
        let bounds = Rectangle::new(Point::new(0, 300), Size::new(800, 180));

        // Top-left key (1)
        let key_1 = KeyboardGrid::resolve_key(bounds, Point::new(10, 310), KeyboardMode::Extended);
        assert_eq!(key_1, Some(Key::Char('1')));
    }
}
