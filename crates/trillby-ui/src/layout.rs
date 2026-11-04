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
        let keyboard_height = KEYBOARD_HEIGHT.min(screen_bounds.size.height);
        let top_height = screen_bounds.size.height - keyboard_height;
        Self {
            content_area: Rectangle::new(
                screen_bounds.top_left,
                Size::new(screen_bounds.size.width, top_height),
            ),
            keyboard_area: Some(Rectangle::new(
                screen_bounds.top_left + Point::new(0, top_height as i32),
                Size::new(screen_bounds.size.width, keyboard_height),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_zones_standard_and_offset_origins() {
        let screen = Rectangle::new(Point::zero(), Size::new(800, 480));

        let zones_hidden = LayoutZones::compute(screen, false);
        assert_eq!(
            zones_hidden.content_area,
            Rectangle::new(Point::zero(), Size::new(800, 480))
        );
        assert_eq!(zones_hidden.keyboard_area, None);

        let zones_visible = LayoutZones::compute(screen, true);
        assert_eq!(
            zones_visible.content_area,
            Rectangle::new(Point::zero(), Size::new(800, 300))
        );
        assert_eq!(
            zones_visible.keyboard_area,
            Some(Rectangle::new(Point::new(0, 300), Size::new(800, 180)))
        );

        let offset_screen = Rectangle::new(Point::new(10, 20), Size::new(800, 480));
        let offset_zones = LayoutZones::compute(offset_screen, true);
        assert_eq!(offset_zones.content_area.top_left, Point::new(10, 20));
        assert_eq!(
            offset_zones.keyboard_area.unwrap().top_left,
            Point::new(10, 320)
        );
        assert_eq!(offset_zones.content_area.size, Size::new(800, 300));
        assert_eq!(offset_zones.keyboard_area.unwrap().size, Size::new(800, 180));
    }

    #[test]
    fn layout_zones_short_screen_clamps_keyboard_height_within_screen_bounds() {
        let screen = Rectangle::new(Point::zero(), Size::new(800, 120));
        let zones = LayoutZones::compute(screen, true);
        assert_eq!(zones.content_area.size.height, 0);
        let kb = zones.keyboard_area.unwrap();
        assert!(
            kb.size.height <= 120,
            "keyboard height {} should not exceed screen height 120",
            kb.size.height
        );
    }
}
