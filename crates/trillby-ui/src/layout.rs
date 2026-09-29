use embedded_graphics::{
    geometry::{Point, Size},
    primitives::Rectangle,
};
use trillby_core::keyboard_types::KeyboardMode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LayoutZones {
    pub content_area: Rectangle,
    pub keyboard_area: Option<Rectangle>,
}

impl LayoutZones {
    pub fn compute(screen_bounds: Rectangle, mode: KeyboardMode) -> Self {
        match mode {
            KeyboardMode::Hidden => Self {
                content_area: screen_bounds,
                keyboard_area: None,
            },
            KeyboardMode::Standard | KeyboardMode::Extended => {
                let kb_height = 180;
                let top_height = screen_bounds.size.height.saturating_sub(kb_height);

                Self {
                    content_area: Rectangle::new(
                        screen_bounds.top_left,
                        Size::new(screen_bounds.size.width, top_height),
                    ),
                    keyboard_area: Some(Rectangle::new(
                        Point::new(
                            screen_bounds.top_left.x,
                            screen_bounds.top_left.y + top_height as i32,
                        ),
                        Size::new(screen_bounds.size.width, kb_height),
                    )),
                }
            }
        }
    }
}
