use crate::keyboard_grid::KeyboardGrid;
use crate::layout::LayoutZones;
use crate::theme::{DarkFloorTheme, Theme};
use crate::widgets::{Badge, BadgeVariant, Button, ButtonVariant, Card, TextField};
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_6X12, ascii::FONT_9X18_BOLD, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, StyledDrawable},
    text::Text,
};
use trillby_core::header::{HeaderButton, HEADER_HEIGHT};
use trillby_core::keyboard_types::Key;
use trillby_core::state::UiState;

pub fn core_point_to_eg(pt: trillby_core::geometry::Point) -> Point {
    Point::new(pt.x, pt.y)
}

pub fn eg_point_to_core(pt: Point) -> trillby_core::geometry::Point {
    trillby_core::geometry::Point::new(pt.x, pt.y)
}

pub fn eg_rect_to_core(rect: Rectangle) -> trillby_core::geometry::Rect {
    trillby_core::geometry::Rect::new(
        trillby_core::geometry::Point::new(rect.top_left.x, rect.top_left.y),
        rect.size.width,
        rect.size.height,
    )
}

pub fn core_rect_to_eg(rect: trillby_core::geometry::Rect) -> Rectangle {
    Rectangle::new(
        Point::new(rect.top_left.x, rect.top_left.y),
        Size::new(rect.width, rect.height),
    )
}

pub struct UiRenderer {
    theme: DarkFloorTheme,
    screen_bounds: Rectangle,
}

impl UiRenderer {
    pub fn new(screen_bounds: Rectangle) -> Self {
        Self {
            theme: DarkFloorTheme,
            screen_bounds,
        }
    }

    pub fn render<D, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        // Compute 2-State Responsive Layout Zones (Keyboard Hidden vs Active)
        let zones = LayoutZones::compute(self.screen_bounds, state.keyboard_visible);

        // 1. Draw Root Screen Background
        let bg_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.background())
            .build();
        self.screen_bounds.draw_styled(&bg_style, target)?;

        // 2. Navigation Header Bar (36px high)
        let header_rect = Rectangle::new(Point::zero(), Size::new(self.screen_bounds.size.width, HEADER_HEIGHT));
        let header_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.surface())
            .stroke_color(self.theme.border())
            .stroke_width(1)
            .build();
        header_rect.draw_styled(&header_style, target)?;

        let title_style = MonoTextStyle::new(&FONT_9X18_BOLD, self.theme.primary());
        Text::new("TRILLBY | SCANNER CLIENT", Point::new(12, 24), title_style).draw(target)?;

        // Header Status Badge
        Badge::new(Point::new(260, 9), "ONLINE")
            .variant(BadgeVariant::Success)
            .draw(target, &self.theme)?;

        // Header Action Buttons (rects shared with UiState hit-testing)
        Button::new(core_rect_to_eg(HeaderButton::Keyboard.rect()), "KEYBOARD")
            .variant(if state.keyboard_visible { ButtonVariant::Primary } else { ButtonVariant::Secondary })
            .pressed(state.pressed_header == Some(HeaderButton::Keyboard))
            .draw(target, &self.theme)?;

        Button::new(core_rect_to_eg(HeaderButton::Clear.rect()), "CLEAR")
            .variant(ButtonVariant::Outline)
            .pressed(state.pressed_header == Some(HeaderButton::Clear))
            .draw(target, &self.theme)?;

        // 3. Responsive Content Viewport
        let content_y = 48;
        let available_h = zones.content_area.size.height.saturating_sub(content_y);

        // Responsive Text Field Input Component
        let is_input_focused = state.keyboard_visible;
        TextField::new(Rectangle::new(Point::new(12, content_y as i32), Size::new(776, 40)))
            .value(state.input_buffer.as_str())
            .placeholder("<SCAN BARCODE OR RFID>")
            .focused(is_input_focused)
            .draw(target, &self.theme)?;

        // Telemetry Cards Section (Adjusts height based on responsive mode)
        let cards_y = content_y + 48;
        let cards_h = available_h.saturating_sub(56).min(320);

        if cards_h >= 60 {
            let card_w = 250;

            // Card 1: Touch Metrics Component
            let card1_bounds = Rectangle::new(Point::new(12, cards_y as i32), Size::new(card_w, cards_h));
            Card::new(card1_bounds).title("TOUCH METRICS").draw(target, &self.theme)?;

            let text_muted = MonoTextStyle::new(&FONT_6X12, self.theme.text_muted());
            use core::fmt::Write;

            let mut t1: heapless::String<64> = heapless::String::new();
            let _ = write!(t1, "Events Count: {}", state.touch_count);
            Text::new(&t1, Point::new(24, cards_y as i32 + 42), text_muted).draw(target)?;

            let mut t2: heapless::String<64> = heapless::String::new();
            let _ = write!(t2, "Raw Touch: ({}, {})", state.last_touch_raw.0, state.last_touch_raw.1);
            Text::new(&t2, Point::new(24, cards_y as i32 + 58), text_muted).draw(target)?;

            if cards_h >= 100 {
                let mut t3: heapless::String<64> = heapless::String::new();
                if let Some(s) = state.last_touch_scaled {
                    let _ = write!(t3, "Scaled: ({}, {})", s.x, s.y);
                } else {
                    let _ = write!(t3, "Scaled: N/A");
                }
                Text::new(&t3, Point::new(24, cards_y as i32 + 74), text_muted).draw(target)?;
            }

            // Card 2: Hardware Telemetry Component
            let card2_bounds = Rectangle::new(Point::new(275, cards_y as i32), Size::new(card_w, cards_h));
            Card::new(card2_bounds).title("HARDWARE TELEMETRY").draw(target, &self.theme)?;

            let mut h1: heapless::String<64> = heapless::String::new();
            let _ = write!(h1, "RFID Scans: {}", state.rfid_count);
            Text::new(&h1, Point::new(287, cards_y as i32 + 42), text_muted).draw(target)?;

            let mut h2: heapless::String<64> = heapless::String::new();
            let _ = write!(h2, "Barcodes:   {}", state.barcode_count);
            Text::new(&h2, Point::new(287, cards_y as i32 + 58), text_muted).draw(target)?;

            if cards_h >= 100 {
                let mut h3: heapless::String<64> = heapless::String::new();
                let _ = write!(h3, "Keys Typed: {}", state.key_count);
                Text::new(&h3, Point::new(287, cards_y as i32 + 74), text_muted).draw(target)?;
            }

            // Card 3: System Event History Component
            let card3_bounds = Rectangle::new(Point::new(538, cards_y as i32), Size::new(250, cards_h));
            Card::new(card3_bounds).title("SYSTEM EVENT STREAM").draw(target, &self.theme)?;

            let max_log_items = (cards_h.saturating_sub(40) / 14) as usize;
            for (i, entry) in state.event_history.iter().enumerate().take(max_log_items.min(6)) {
                if !entry.is_empty() {
                    let y_pos = cards_y as i32 + 42 + (i as i32 * 14);
                    Text::new(entry.as_str(), Point::new(550, y_pos), text_muted).draw(target)?;
                }
            }
        }

        // 4. Virtual keyboard: one pass over the shared slot table.
        if let Some(kb_rect) = zones.keyboard_area {
            let kb_bg = PrimitiveStyleBuilder::new()
                .fill_color(self.theme.surface())
                .stroke_color(self.theme.border())
                .stroke_width(2)
                .build();
            kb_rect.draw_styled(&kb_bg, target)?;

            for (cell, slot) in KeyboardGrid::slots(kb_rect, state.keyboard_layer) {
                let key_rect = Rectangle::new(
                    cell.top_left + Point::new(2, 2),
                    cell.size.saturating_sub(Size::new(4, 4)),
                );
                let is_pressed = state.active_touch_key.is_some() && state.active_touch_key == slot.resolved();
                let variant = match slot.key {
                    Key::Backspace => ButtonVariant::Danger,
                    Key::Enter => ButtonVariant::Primary,
                    Key::LayerToggle => ButtonVariant::Outline,
                    _ if is_pressed => ButtonVariant::Primary,
                    _ => ButtonVariant::Secondary,
                };

                let mut label_buf = [0u8; 4];
                Button::new(key_rect, slot.label(state.keyboard_layer, &mut label_buf))
                    .variant(variant)
                    .pressed(is_pressed)
                    .draw(target, &self.theme)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::mock_display::MockDisplay;

    #[test]
    fn test_in_memory_render_pass() {
        let mut display: MockDisplay<Rgb565> = MockDisplay::new();
        display.set_allow_overdraw(true);
        display.set_allow_out_of_bounds_drawing(true);

        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let renderer = UiRenderer::new(screen_bounds);
        let state: UiState<256> = UiState::new();

        let result = renderer.render(&mut display, &state);
        assert!(result.is_ok());
    }
}
