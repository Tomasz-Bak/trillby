use embedded_graphics::{
    geometry::{Point, Size},
    primitives::Rectangle,
};

pub const SCREEN_WIDTH: u32 = 800;
pub const SCREEN_HEIGHT: u32 = 480;
pub const KEYBOARD_HEIGHT: u32 = 180;
pub const SCREEN_PIXELS: usize = (SCREEN_WIDTH * SCREEN_HEIGHT) as usize;
pub type ScreenPixels = [embedded_graphics::pixelcolor::Rgb565; SCREEN_PIXELS];

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

pub fn dispatch_touch<const N: usize>(
    state: &mut trillby_core::UiState<N>,
    zones: &LayoutZones,
    event: trillby_core::UiEvent,
) {
    let core_kb_bounds = zones.keyboard_area.map(crate::view::eg_rect_to_core);
    let resolved_key = match &event {
        trillby_core::UiEvent::TouchDown { scaled, .. }
        | trillby_core::UiEvent::TouchUp { scaled, .. }
        | trillby_core::UiEvent::TouchMove { scaled, .. } => {
            let eg_pt = crate::view::core_point_to_eg(*scaled);
            zones
                .keyboard_area
                .and_then(|kb| crate::keyboard_grid::KeyboardGrid::resolve_key(kb, eg_pt, state.keyboard_layer))
        }
        _ => None,
    };
    state.handle_event(event, core_kb_bounds, resolved_key);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn layout_zones_standard_and_offset_origins() {
        let screen = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));

        let zones_hidden = LayoutZones::compute(screen, false);
        assert_eq!(
            zones_hidden.content_area,
            Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT))
        );
        assert_eq!(zones_hidden.keyboard_area, None);

        let zones_visible = LayoutZones::compute(screen, true);
        assert_eq!(
            zones_visible.content_area,
            Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, 300))
        );
        assert_eq!(
            zones_visible.keyboard_area,
            Some(Rectangle::new(Point::new(0, 300), Size::new(SCREEN_WIDTH, 180)))
        );

        let offset_screen = Rectangle::new(Point::new(10, 20), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let offset_zones = LayoutZones::compute(offset_screen, true);
        assert_eq!(offset_zones.content_area.top_left, Point::new(10, 20));
        assert_eq!(
            offset_zones.keyboard_area.unwrap().top_left,
            Point::new(10, 320)
        );
        assert_eq!(offset_zones.content_area.size, Size::new(SCREEN_WIDTH, 300));
        assert_eq!(offset_zones.keyboard_area.unwrap().size, Size::new(SCREEN_WIDTH, 180));
    }

    #[test]
    fn layout_zones_short_screen_clamps_keyboard_height_within_screen_bounds() {
        let screen = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, 120));
        let zones = LayoutZones::compute(screen, true);
        assert_eq!(zones.content_area.size.height, 0);
        let kb = zones.keyboard_area.unwrap();
        assert!(
            kb.size.height <= 120,
            "keyboard height {} should not exceed screen height 120",
            kb.size.height
        );
    }

    #[test]
    fn dispatch_touch_resolves_virtual_keyboard_key() {
        let screen = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let mut state: trillby_core::UiState<32> = trillby_core::UiState::new();
        state.keyboard_visible = true;
        let zones = LayoutZones::compute(screen, state.keyboard_visible);

        let touch_pt = trillby_core::Point::new(40, 320);
        dispatch_touch(
            &mut state,
            &zones,
            trillby_core::UiEvent::TouchDown {
                scaled: touch_pt,
                raw: (40, 320),
            },
        );
        assert_eq!(state.active_touch_key, Some(trillby_core::Key::Char('Q')));
        assert_eq!(state.touch_count, 1);
        assert_eq!(state.last_touch_scaled, Some(touch_pt));
    }
}
