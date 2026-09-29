use crate::keyboard_grid::KeyboardGrid;
use crate::layout::LayoutZones;
use crate::theme::{ColorScheme, DarkFloorTheme};
use crate::widgets::{Badge, BadgeVariant, Button, ButtonVariant, Card, TextField};
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_6X12, ascii::FONT_9X18_BOLD, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, StyledDrawable},
    text::Text,
};
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
        let zones = LayoutZones::compute(self.screen_bounds, state.keyboard_mode);

        // 1. Draw Root Screen Background
        let bg_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.background())
            .build();
        self.screen_bounds.draw_styled(&bg_style, target)?;

        // 2. Navigation Header Bar (36px high)
        let header_rect = Rectangle::new(Point::zero(), Size::new(self.screen_bounds.size.width, 36));
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

        // Header Action Buttons
        let is_kb_pressed = state.active_touch_key.is_some() && state.last_touch_raw.1 <= 36;
        Button::new(Rectangle::new(Point::new(510, 4), Size::new(130, 28)), "KEYBOARD")
            .variant(if state.keyboard_mode != trillby_core::KeyboardMode::Hidden { ButtonVariant::Primary } else { ButtonVariant::Secondary })
            .pressed(is_kb_pressed)
            .draw(target, &self.theme)?;

        Button::new(Rectangle::new(Point::new(650, 4), Size::new(130, 28)), "CLEAR")
            .variant(ButtonVariant::Outline)
            .draw(target, &self.theme)?;

        // 3. Responsive Content Viewport
        let content_y = 48;
        let available_h = zones.content_area.size.height.saturating_sub(content_y);

        // Responsive Text Field Input Component
        let is_input_focused = state.keyboard_mode != trillby_core::KeyboardMode::Hidden;
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

        // 4. State 2: Virtual Keyboard Component (when active)
        if let Some(kb_rect) = zones.keyboard_area {
            let kb_bg = PrimitiveStyleBuilder::new()
                .fill_color(self.theme.surface())
                .stroke_color(self.theme.border())
                .stroke_width(2)
                .build();
            kb_rect.draw_styled(&kb_bg, target)?;

            let key_w = kb_rect.size.width as i32 / KeyboardGrid::COLS as i32;
            let key_h = kb_rect.size.height as i32 / KeyboardGrid::ROWS as i32;

            // Render Rows 0..3: Character Keys
            for r in 0..3 {
                for c in 0..KeyboardGrid::COLS {
                    let kx = kb_rect.top_left.x + (c as i32 * key_w);
                    let ky = kb_rect.top_left.y + (r as i32 * key_h);
                    let krect = Rectangle::new(Point::new(kx + 2, ky + 2), Size::new((key_w - 4) as u32, (key_h - 4) as u32));

                    let resolved_key = KeyboardGrid::resolve_key(kb_rect, Point::new(kx + key_w / 2, ky + key_h / 2), state.keyboard_mode);
                    let is_pressed = state.active_touch_key.is_some() && state.active_touch_key == resolved_key;

                    let key_variant = if is_pressed {
                        ButtonVariant::Primary
                    } else {
                        ButtonVariant::Secondary
                    };

                    if let Some(ch) = KeyboardGrid::get_key_char(r, c, state.keyboard_mode) {
                        let mut buf = [0u8; 4];
                        let label_str: &str = ch.encode_utf8(&mut buf);
                        Button::new(krect, label_str)
                            .variant(key_variant)
                            .pressed(is_pressed)
                            .draw(target, &self.theme)?;
                    } else {
                        Button::new(krect, "")
                            .variant(key_variant)
                            .pressed(is_pressed)
                            .draw(target, &self.theme)?;
                    }
                }
            }

            // Render Row 3: Control Buttons Row (MODE, SPACE, DEL, ENTER)
            let r3_y = kb_rect.top_left.y + (3 * key_h);
            let unit_w = kb_rect.size.width as i32 / 10;

            // 1. MODE Switch
            let mode_rect = Rectangle::new(Point::new(kb_rect.top_left.x + 2, r3_y + 2), Size::new((unit_w * 2 - 4) as u32, (key_h - 4) as u32));
            let mode_label = if state.keyboard_mode == trillby_core::KeyboardMode::Standard { "?123" } else { "ABC" };
            let is_mode_pressed = state.active_touch_key == Some(trillby_core::Key::ModeSwitch);
            Button::new(mode_rect, mode_label)
                .variant(ButtonVariant::Outline)
                .pressed(is_mode_pressed)
                .draw(target, &self.theme)?;

            // 2. SPACE Bar
            let space_rect = Rectangle::new(Point::new(kb_rect.top_left.x + unit_w * 2 + 2, r3_y + 2), Size::new((unit_w * 4 - 4) as u32, (key_h - 4) as u32));
            let is_space_pressed = state.active_touch_key == Some(trillby_core::Key::Space);
            Button::new(space_rect, "SPACE")
                .variant(if is_space_pressed { ButtonVariant::Primary } else { ButtonVariant::Secondary })
                .pressed(is_space_pressed)
                .draw(target, &self.theme)?;

            // 3. BACKSPACE (DEL) Key
            let bk_rect = Rectangle::new(Point::new(kb_rect.top_left.x + unit_w * 6 + 2, r3_y + 2), Size::new((unit_w * 2 - 4) as u32, (key_h - 4) as u32));
            let is_bk_pressed = state.active_touch_key == Some(trillby_core::Key::Backspace);
            Button::new(bk_rect, "DEL")
                .variant(ButtonVariant::Danger)
                .pressed(is_bk_pressed)
                .draw(target, &self.theme)?;

            // 4. ENTER Key
            let enter_rect = Rectangle::new(Point::new(kb_rect.top_left.x + unit_w * 8 + 2, r3_y + 2), Size::new((unit_w * 2 - 4) as u32, (key_h - 4) as u32));
            let is_enter_pressed = state.active_touch_key == Some(trillby_core::Key::Enter);
            Button::new(enter_rect, "ENTER")
                .variant(ButtonVariant::Primary)
                .pressed(is_enter_pressed)
                .draw(target, &self.theme)?;
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
