use embedded_graphics::geometry::Point;
use embedded_graphics::primitives::Rectangle;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Backspace,
    ModeSwitch,
    Enter,
    Space,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyboardMode {
    #[default]
    Hidden,
    Standard, // QWERTY Alpha
    Extended, // Numbers & Symbols
}

pub struct KeyboardGrid;

impl KeyboardGrid {
    pub const COLS: usize = 10;
    pub const ROWS: usize = 4;

    const STANDARD_ROW1: [Key; 10] = [
        Key::Char('Q'), Key::Char('W'), Key::Char('E'), Key::Char('R'), Key::Char('T'),
        Key::Char('Y'), Key::Char('U'), Key::Char('I'), Key::Char('O'), Key::Char('P'),
    ];

    const STANDARD_ROW2: [Key; 10] = [
        Key::Char('A'), Key::Char('S'), Key::Char('D'), Key::Char('F'), Key::Char('G'),
        Key::Char('H'), Key::Char('J'), Key::Char('K'), Key::Char('L'), Key::Char('-'),
    ];

    const STANDARD_ROW3: [Key; 10] = [
        Key::Char('Z'), Key::Char('X'), Key::Char('C'), Key::Char('V'), Key::Char('B'),
        Key::Char('N'), Key::Char('M'), Key::Char('.'), Key::Char('?'), Key::Char('!'),
    ];

    const EXTENDED_ROW1: [Key; 10] = [
        Key::Char('1'), Key::Char('2'), Key::Char('3'), Key::Char('4'), Key::Char('5'),
        Key::Char('6'), Key::Char('7'), Key::Char('8'), Key::Char('9'), Key::Char('0'),
    ];

    const EXTENDED_ROW2: [Key; 10] = [
        Key::Char('-'), Key::Char('/'), Key::Char(':'), Key::Char(';'), Key::Char('('),
        Key::Char(')'), Key::Char('$'), Key::Char('&'), Key::Char('@'), Key::Char('#'),
    ];

    const EXTENDED_ROW3: [Key; 10] = [
        Key::Char('.'), Key::Char(','), Key::Char('?'), Key::Char('!'), Key::Char('\''),
        Key::Char('"'), Key::Char('+'), Key::Char('='), Key::Char('*'), Key::Char('%'),
    ];

    /// Resolve touch point inside keyboard bounds to a specific Key.
    pub fn resolve_key(bounds: Rectangle, point: Point, mode: KeyboardMode) -> Option<Key> {
        if mode == KeyboardMode::Hidden || !bounds.contains(point) {
            return None;
        }

        let rel_x = point.x - bounds.top_left.x;
        let rel_y = point.y - bounds.top_left.y;

        if rel_x < 0 || rel_y < 0 {
            return None;
        }

        let row_height = bounds.size.height as i32 / Self::ROWS as i32;
        if row_height <= 0 {
            return None;
        }

        let row = (rel_y / row_height) as usize;

        if row < 3 {
            let col_width = bounds.size.width as i32 / Self::COLS as i32;
            if col_width <= 0 {
                return None;
            }
            let col = ((rel_x / col_width) as usize).min(Self::COLS - 1);

            match mode {
                KeyboardMode::Standard => match row {
                    0 => Some(Self::STANDARD_ROW1[col]),
                    1 => Some(Self::STANDARD_ROW2[col]),
                    2 => Some(Self::STANDARD_ROW3[col]),
                    _ => None,
                },
                KeyboardMode::Extended => match row {
                    0 => Some(Self::EXTENDED_ROW1[col]),
                    1 => Some(Self::EXTENDED_ROW2[col]),
                    2 => Some(Self::EXTENDED_ROW3[col]),
                    _ => None,
                },
                KeyboardMode::Hidden => None,
            }
        } else if row == 3 {
            // Row 4: Special control keys [ModeSwitch (2 cols)] [Space (4 cols)] [Backspace (2 cols)] [Enter (2 cols)]
            let width = bounds.size.width as i32;
            let unit = width / 10;

            if rel_x < unit * 2 {
                Some(Key::ModeSwitch)
            } else if rel_x < unit * 6 {
                Some(Key::Space)
            } else if rel_x < unit * 8 {
                Some(Key::Backspace)
            } else {
                Some(Key::Enter)
            }
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::geometry::{Point, Size};

    #[test]
    fn test_key_resolution_standard() {
        let kb_bounds = Rectangle::new(Point::new(0, 300), Size::new(800, 180));
        
        // Touch Q (row 0, col 0)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(10, 310), KeyboardMode::Standard);
        assert_eq!(key, Some(Key::Char('Q')));

        // Touch P (row 0, col 9)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(750, 310), KeyboardMode::Standard);
        assert_eq!(key, Some(Key::Char('P')));

        // Touch Backspace (row 3, cols 6-7)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(550, 450), KeyboardMode::Standard);
        assert_eq!(key, Some(Key::Backspace));

        // Touch ModeSwitch (row 3, cols 0-1)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(50, 450), KeyboardMode::Standard);
        assert_eq!(key, Some(Key::ModeSwitch));
    }

    #[test]
    fn test_key_resolution_extended() {
        let kb_bounds = Rectangle::new(Point::new(0, 300), Size::new(800, 180));

        // Touch '1' (row 0, col 0)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(10, 310), KeyboardMode::Extended);
        assert_eq!(key, Some(Key::Char('1')));

        // Touch '#' (row 1, col 9)
        let key = KeyboardGrid::resolve_key(kb_bounds, Point::new(750, 355), KeyboardMode::Extended);
        assert_eq!(key, Some(Key::Char('#')));
    }
}
