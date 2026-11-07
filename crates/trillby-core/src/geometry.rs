#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Point {
    pub x: i32,
    pub y: i32,
}

impl Point {
    pub const fn new(x: i32, y: i32) -> Self {
        Self { x, y }
    }

    pub const fn zero() -> Self {
        Self { x: 0, y: 0 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Rect {
    pub top_left: Point,
    pub width: u32,
    pub height: u32,
}

impl Rect {
    pub const fn new(top_left: Point, width: u32, height: u32) -> Self {
        Self {
            top_left,
            width,
            height,
        }
    }

    pub fn contains(&self, point: Point) -> bool {
        let dx = i64::from(point.x) - i64::from(self.top_left.x);
        let dy = i64::from(point.y) - i64::from(self.top_left.y);
        dx >= 0 && dx < i64::from(self.width) && dy >= 0 && dy < i64::from(self.height)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rect_contains_half_open_boundaries_and_zero_dimensions() {
        let rect = Rect::new(Point::new(10, 20), 100, 50);
        // Inclusive corners
        assert!(rect.contains(Point::new(10, 20)));
        assert!(rect.contains(Point::new(109, 20)));
        assert!(rect.contains(Point::new(10, 69)));
        assert!(rect.contains(Point::new(109, 69)));

        // Exclusive right/bottom edges
        assert!(!rect.contains(Point::new(110, 20)));
        assert!(!rect.contains(Point::new(10, 70)));
        assert!(!rect.contains(Point::new(110, 70)));

        // Outside top/left
        assert!(!rect.contains(Point::new(9, 20)));
        assert!(!rect.contains(Point::new(10, 19)));

        // Zero-width and zero-height rects
        let zero_width = Rect::new(Point::new(10, 20), 0, 50);
        let zero_height = Rect::new(Point::new(10, 20), 100, 0);
        assert!(!zero_width.contains(Point::new(10, 20)));
        assert!(!zero_height.contains(Point::new(10, 20)));

        // Negative-origin rect
        let neg_rect = Rect::new(Point::new(-50, -30), 20, 10);
        assert!(neg_rect.contains(Point::new(-50, -30)));
        assert!(neg_rect.contains(Point::new(-31, -21)));
        assert!(!neg_rect.contains(Point::new(-30, -20)));
        assert!(!neg_rect.contains(Point::new(0, 0)));
    }

    #[test]
    fn rect_contains_does_not_overflow_near_i32_max() {
        let rect = Rect::new(Point::new(i32::MAX - 5, 0), 10, 10);
        assert!(!rect.contains(Point::new(-2_147_483_640, 5)));
        assert!(rect.contains(Point::new(i32::MAX - 1, 5)));
    }
}
