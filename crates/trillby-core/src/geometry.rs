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
        point.x >= self.top_left.x
            && point.x < self.top_left.x + self.width as i32
            && point.y >= self.top_left.y
            && point.y < self.top_left.y + self.height as i32
    }
}
