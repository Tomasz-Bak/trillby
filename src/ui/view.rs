use super::keyboard::{Key, KeyboardGrid, KeyboardMode};
use super::state::UiState;
use super::theme::{ColorScheme, DarkFloorTheme};
use core::fmt::Write;
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{Point, Size},
    mono_font::{ascii::FONT_8X13, ascii::FONT_10X20, MonoTextStyle},
    pixelcolor::Rgb565,
    primitives::{Circle, Line, Primitive, PrimitiveStyle, PrimitiveStyleBuilder, Rectangle, RoundedRectangle},
    text::Text,
    Drawable,
};

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

pub struct UiRenderer {
    theme: DarkFloorTheme,
    screen_bounds: Rectangle,
}

impl UiRenderer {
    pub const fn new(screen_bounds: Rectangle) -> Self {
        Self {
            theme: DarkFloorTheme,
            screen_bounds,
        }
    }

    pub fn render<D, const N: usize>(&self, target: &mut D, state: &UiState<N>) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let zones = LayoutZones::compute(self.screen_bounds, state.keyboard_mode);

        // Fill background
        let bg_style = PrimitiveStyle::with_fill(self.theme.background());
        self.screen_bounds.into_styled(bg_style).draw(target)?;

        // Top Status Bar
        self.render_top_bar(target, state)?;

        // Content Scaffolding
        self.render_debug_scaffolding(target, zones.content_area, state)?;

        // Virtual Keyboard
        if let Some(kb_bounds) = zones.keyboard_area {
            self.render_keyboard(target, kb_bounds, state)?;
        }

        // Draw Touch Crosshair marker
        if let Some(pt) = state.last_touch_scaled {
            self.render_touch_marker(target, pt)?;
        }

        Ok(())
    }

    fn render_top_bar<D, const N: usize>(&self, target: &mut D, state: &UiState<N>) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let bar_bounds = Rectangle::new(Point::zero(), Size::new(self.screen_bounds.size.width, 36));
        let style = PrimitiveStyle::with_fill(self.theme.surface());
        bar_bounds.into_styled(style).draw(target)?;

        let text_style = MonoTextStyle::new(&FONT_8X13, self.theme.text());
        let mut title_buf: heapless::String<64> = heapless::String::new();
        let _ = write!(title_buf, "TRILLBY SCAFFOLDING | Uptime: {}s", state.tick_count / 20);
        Text::new(&title_buf, Point::new(12, 22), text_style).draw(target)?;

        // Keyboard Mode Switcher Button
        let kb_btn = Rectangle::new(Point::new(500, 4), Size::new(140, 28));
        let kb_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.surface_active())
            .stroke_color(self.theme.border())
            .stroke_width(1)
            .build();
        kb_btn.into_styled(kb_style).draw(target)?;

        let mut kb_label: heapless::String<32> = heapless::String::new();
        let _ = match state.keyboard_mode {
            KeyboardMode::Standard => write!(kb_label, "KB: QWERTY"),
            KeyboardMode::Extended => write!(kb_label, "KB: SYMBOLS"),
            KeyboardMode::Hidden => write!(kb_label, "KB: HIDDEN"),
        };
        let txt_style = MonoTextStyle::new(&FONT_8X13, self.theme.primary_text());
        Text::new(&kb_label, Point::new(510, 22), txt_style).draw(target)?;

        // Clear Log Button
        let clr_btn = Rectangle::new(Point::new(650, 4), Size::new(130, 28));
        let clr_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.primary())
            .stroke_color(self.theme.border())
            .stroke_width(1)
            .build();
        clr_btn.into_styled(clr_style).draw(target)?;
        Text::new("CLEAR LOG", Point::new(665, 22), txt_style).draw(target)?;

        Ok(())
    }

    fn render_debug_scaffolding<D, const N: usize>(
        &self,
        target: &mut D,
        area: Rectangle,
        state: &UiState<N>,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let label_style = MonoTextStyle::new(&FONT_8X13, self.theme.text_muted());
        let val_style = MonoTextStyle::new(&FONT_10X20, self.theme.primary_text());
        let text_style = MonoTextStyle::new(&FONT_10X20, self.theme.text());
        let code_style = MonoTextStyle::new(&FONT_8X13, self.theme.text_muted());

        let max_content_y = area.top_left.y + area.size.height as i32;

        // Card 1: Live Input Sandbox (y: 45, height: 65)
        let card1_h = 65;
        if 45 + card1_h <= max_content_y {
            let card1 = Rectangle::new(Point::new(15, 45), Size::new(770, card1_h as u32));
            let card_style = PrimitiveStyleBuilder::new()
                .fill_color(self.theme.surface())
                .stroke_color(self.theme.primary())
                .stroke_width(1)
                .build();
            card1.into_styled(card_style).draw(target)?;

            Text::new("INPUT BUFFER SANDBOX (Virtual Keyboard / RFID / Barcode):", Point::new(25, 60), label_style).draw(target)?;

            let mut display_buf: heapless::String<128> = heapless::String::new();
            if state.input_buffer.is_empty() {
                let _ = write!(display_buf, "<Type on keyboard or scan card/barcode...>");
                Text::new(&display_buf, Point::new(25, 92), MonoTextStyle::new(&FONT_10X20, self.theme.text_muted())).draw(target)?;
            } else {
                let _ = write!(display_buf, "{}", state.input_buffer);
                Text::new(&display_buf, Point::new(25, 92), val_style).draw(target)?;
            }
        }

        // Card 2: Telemetry Counters & Coordinate Dump (y: 118, height: 75)
        let card2_y = 118;
        let card2_h = 75;
        if card2_y + card2_h <= max_content_y {
            let card2 = Rectangle::new(Point::new(15, card2_y), Size::new(770, card2_h as u32));
            let card_style = PrimitiveStyleBuilder::new()
                .fill_color(self.theme.surface())
                .stroke_color(self.theme.border())
                .stroke_width(1)
                .build();
            card2.into_styled(card_style).draw(target)?;

            // Column 1: Touch Position
            let mut pt_buf: heapless::String<64> = heapless::String::new();
            if let Some(pt) = state.last_touch_scaled {
                let _ = write!(pt_buf, "TOUCH SCALED: ({}, {})", pt.x, pt.y);
            } else {
                let _ = write!(pt_buf, "TOUCH SCALED: None");
            }
            Text::new(&pt_buf, Point::new(25, card2_y + 25), text_style).draw(target)?;

            let mut raw_buf: heapless::String<64> = heapless::String::new();
            let _ = write!(raw_buf, "RAW EVDEV: ({}, {})", state.last_touch_raw.0, state.last_touch_raw.1);
            Text::new(&raw_buf, Point::new(25, card2_y + 55), code_style).draw(target)?;

            // Column 2: Event Counters
            let col2_x = 420;
            let mut cnt_buf1: heapless::String<64> = heapless::String::new();
            let _ = write!(cnt_buf1, "Touch: {} | Keys: {}", state.touch_count, state.key_count);
            Text::new(&cnt_buf1, Point::new(col2_x, card2_y + 25), text_style).draw(target)?;

            let mut cnt_buf2: heapless::String<64> = heapless::String::new();
            let _ = write!(cnt_buf2, "RFID: {} | Barcode: {}", state.rfid_count, state.barcode_count);
            Text::new(&cnt_buf2, Point::new(col2_x, card2_y + 55), code_style).draw(target)?;
        }

        // Card 3: Rolling Event Log (y: 200)
        let card3_y = 200;
        let card3_h = max_content_y.saturating_sub(card3_y + 5);
        if card3_h >= 40 {
            let card3 = Rectangle::new(Point::new(15, card3_y), Size::new(770, card3_h as u32));
            let card_style = PrimitiveStyleBuilder::new()
                .fill_color(self.theme.surface())
                .stroke_color(self.theme.border())
                .stroke_width(1)
                .build();
            card3.into_styled(card_style).draw(target)?;

            Text::new("RECENT EVENT STREAM LOG:", Point::new(25, card3_y + 18), label_style).draw(target)?;

            let max_lines = (card3_h as usize).saturating_sub(25) / 16;
            for i in 0..state.event_history.len().min(max_lines) {
                let entry = &state.event_history[i];
                if !entry.is_empty() {
                    let y_pos = card3_y + 38 + (i as i32 * 16);
                    let line_style = if i == 0 {
                        MonoTextStyle::new(&FONT_8X13, self.theme.primary_text())
                    } else {
                        MonoTextStyle::new(&FONT_8X13, self.theme.text_muted())
                    };
                    Text::new(entry, Point::new(25, y_pos), line_style).draw(target)?;
                }
            }
        }

        Ok(())
    }

    fn render_touch_marker<D>(&self, target: &mut D, pt: Point) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let color = self.theme.primary();
        let stroke = PrimitiveStyle::with_stroke(color, 2);

        // Draw crosshair ring
        let radius = 12;
        Circle::new(Point::new(pt.x - radius, pt.y - radius), (radius * 2) as u32)
            .into_styled(stroke)
            .draw(target)?;

        // Draw crosshair lines
        Line::new(Point::new(pt.x - 18, pt.y), Point::new(pt.x + 18, pt.y))
            .into_styled(stroke)
            .draw(target)?;

        Line::new(Point::new(pt.x, pt.y - 18), Point::new(pt.x, pt.y + 18))
            .into_styled(stroke)
            .draw(target)?;

        Ok(())
    }

    fn render_keyboard<D, const N: usize>(
        &self,
        target: &mut D,
        bounds: Rectangle,
        state: &UiState<N>,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        // Keyboard background container
        bounds.into_styled(PrimitiveStyle::with_fill(self.theme.surface())).draw(target)?;

        let col_w = bounds.size.width as i32 / KeyboardGrid::COLS as i32;
        let row_h = bounds.size.height as i32 / KeyboardGrid::ROWS as i32;

        let font = MonoTextStyle::new(&FONT_8X13, self.theme.text());

        // Render Rows 1-3
        for r in 0..3 {
            for c in 0..KeyboardGrid::COLS {
                let p = Point::new(
                    bounds.top_left.x + c as i32 * col_w + col_w / 2,
                    bounds.top_left.y + r as i32 * row_h + row_h / 2,
                );
                let key = KeyboardGrid::resolve_key(bounds, p, state.keyboard_mode);

                let key_rect = Rectangle::new(
                    Point::new(bounds.top_left.x + c as i32 * col_w + 2, bounds.top_left.y + r as i32 * row_h + 2),
                    Size::new((col_w - 4) as u32, (row_h - 4) as u32),
                );

                let is_pressed = state.active_touch_key == key && key.is_some();
                let bg_color = if is_pressed { self.theme.primary() } else { self.theme.background() };

                RoundedRectangle::with_equal_corners(key_rect, Size::new(4, 4))
                    .into_styled(PrimitiveStyle::with_fill(bg_color))
                    .draw(target)?;

                if let Some(Key::Char(ch)) = key {
                    let mut s: heapless::String<4> = heapless::String::new();
                    let _ = s.push(ch);
                    Text::new(&s, Point::new(key_rect.top_left.x + col_w / 2 - 4, key_rect.top_left.y + row_h / 2 + 4), font).draw(target)?;
                }
            }
        }

        // Render Row 4 control buttons
        let r4_y = bounds.top_left.y + 3 * row_h + 2;
        let unit = bounds.size.width as i32 / 10;

        let ctrl_keys = [
            (0, 2, "MODE", Key::ModeSwitch),
            (2, 6, "SPACE", Key::Space),
            (6, 8, "DEL", Key::Backspace),
            (8, 10, "ENTER", Key::Enter),
        ];

        for (start_u, end_u, label, key) in ctrl_keys {
            let x = bounds.top_left.x + start_u * unit + 2;
            let w = (end_u - start_u) * unit - 4;
            let rect = Rectangle::new(Point::new(x, r4_y), Size::new(w as u32, (row_h - 4) as u32));

            let is_pressed = state.active_touch_key == Some(key);
            let fill = if is_pressed { self.theme.primary() } else { self.theme.background() };

            RoundedRectangle::with_equal_corners(rect, Size::new(4, 4))
                .into_styled(PrimitiveStyle::with_fill(fill))
                .draw(target)?;

            Text::new(label, Point::new(x + w / 2 - (label.len() as i32 * 4), r4_y + row_h / 2 + 4), font).draw(target)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics_framebuf::FrameBuf;

    #[test]
    fn test_in_memory_render_pass() {
        let mut buffer = [Rgb565::new(0, 0, 0); 800 * 480];
        let mut framebuffer = FrameBuf::new(&mut buffer, 800, 480);

        let renderer = UiRenderer::new(Rectangle::new(Point::zero(), Size::new(800, 480)));
        let state: UiState<256> = UiState::new();

        let res = renderer.render(&mut framebuffer, &state);
        assert!(res.is_ok());
    }
}
