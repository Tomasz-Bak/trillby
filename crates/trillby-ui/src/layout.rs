use embedded_graphics::{
    geometry::{Point, Size},
    primitives::Rectangle,
};

pub const KEYBOARD_HEIGHT: u32 = 180;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutZones {
    pub content_area: Rectangle,
    pub keyboard_area: Option<Rectangle>,
}

impl LayoutZones {
    /// Split the screen into content + keyboard. Only visibility affects
    /// geometry; the active keyboard layer never changes the layout.
    pub fn compute(screen_bounds: Rectangle, keyboard_visible: bool) -> Self {
        if !keyboard_visible {
            return Self {
                content_area: screen_bounds,
                keyboard_area: None,
            };
        }

        let top_height = screen_bounds.size.height.saturating_sub(KEYBOARD_HEIGHT);
        Self {
            content_area: Rectangle::new(
                screen_bounds.top_left,
                Size::new(screen_bounds.size.width, top_height),
            ),
            keyboard_area: Some(Rectangle::new(
                screen_bounds.top_left + Point::new(0, top_height as i32),
                Size::new(screen_bounds.size.width, KEYBOARD_HEIGHT),
            )),
        }
    }
}
