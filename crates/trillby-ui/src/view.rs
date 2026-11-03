use crate::keyboard_grid::KeyboardGrid;
use crate::layout::LayoutZones;
use crate::theme::{DarkFloorTheme, Theme};
use crate::widgets::{Badge, BadgeVariant, Button, ButtonVariant, Card, TextField};
use core::fmt::Write;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_6X12, ascii::FONT_9X18_BOLD, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, StyledDrawable},
    text::Text,
};
use trillby_core::header::{DebugButton, HeaderButton, HEADER_HEIGHT};
use trillby_core::keyboard_types::Key;
use trillby_core::session::SessionState;
use trillby_core::state::{Screen, UiState};
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

        // Header Network Status Badge
        let (badge_label, badge_variant) = match state.network_status {
            trillby_core::net_types::NetworkStatus::Online => ("ONLINE", BadgeVariant::Success),
            trillby_core::net_types::NetworkStatus::Offline => ("OFFLINE", BadgeVariant::Danger),
            trillby_core::net_types::NetworkStatus::Connecting => ("LINKING", BadgeVariant::Warning),
            trillby_core::net_types::NetworkStatus::Handshaking => ("AUTH", BadgeVariant::Warning),
            trillby_core::net_types::NetworkStatus::Syncing(_) => ("SYNC", BadgeVariant::Info),
        };
        Badge::new(Point::new(248, 9), badge_label)
            .variant(badge_variant)
            .draw(target, &self.theme)?;

        // Header Session State Badge
        let (session_label, session_variant) = match state.session.state() {
            SessionState::Idle => ("IDLE", BadgeVariant::Info),
            SessionState::Authenticated { .. } => ("READY", BadgeVariant::Success),
            SessionState::Working { .. } => ("WORKING", BadgeVariant::Warning),
        };
        Badge::new(Point::new(322, 9), session_label)
            .variant(session_variant)
            .draw(target, &self.theme)?;

        // Header Action Buttons (rects shared with UiState hit-testing)
        Button::new(core_rect_to_eg(HeaderButton::Debug.rect()), "DEBUG")
            .variant(if state.current_screen == Screen::Debug {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            })
            .pressed(state.pressed_header == Some(HeaderButton::Debug))
            .draw(target, &self.theme)?;

        Button::new(core_rect_to_eg(HeaderButton::Keyboard.rect()), "KEYBOARD")
            .variant(if state.keyboard_visible {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            })
            .pressed(state.pressed_header == Some(HeaderButton::Keyboard))
            .draw(target, &self.theme)?;

        Button::new(core_rect_to_eg(HeaderButton::Clear.rect()), "CLEAR")
            .variant(ButtonVariant::Outline)
            .pressed(state.pressed_header == Some(HeaderButton::Clear))
            .draw(target, &self.theme)?;

        // 3. Responsive Content Viewport
        let content_y = 48;
        let available_h = zones.content_area.size.height.saturating_sub(content_y);
        let text_muted = MonoTextStyle::new(&FONT_6X12, self.theme.text_muted());
        let text_bold = MonoTextStyle::new(&FONT_9X18_BOLD, self.theme.text());

        match state.current_screen {
            Screen::Operator => match state.session.state() {
                SessionState::Idle => {
                    let card_h = available_h.saturating_sub(12);
                    let left_bounds = Rectangle::new(Point::new(12, 48), Size::new(514, card_h));
                    Card::new(left_bounds)
                        .title("OPERATOR AUTHENTICATION")
                        .draw(target, &self.theme)?;

                    Text::new(
                        "STATUS: LOCKED - AWAITING OPERATOR",
                        Point::new(32, 98),
                        text_bold,
                    )
                    .draw(target)?;

                    let prompt_box = Rectangle::new(Point::new(32, 120), Size::new(474, 100));
                    let prompt_style = PrimitiveStyleBuilder::new()
                        .fill_color(self.theme.surface_active())
                        .stroke_color(self.theme.primary())
                        .stroke_width(2)
                        .build();
                    prompt_box.draw_styled(&prompt_style, target)?;

                    let primary_bold = MonoTextStyle::new(&FONT_9X18_BOLD, self.theme.primary());
                    Text::new(
                        "SCAN OPERATOR RFID BADGE",
                        Point::new(161, 162),
                        primary_bold,
                    )
                    .draw(target)?;
                    Text::new(
                        "Hold RFID badge near reader to log in",
                        Point::new(158, 186),
                        text_muted,
                    )
                    .draw(target)?;

                    let mut f1: heapless::String<64> = heapless::String::new();
                    let _ = write!(f1, "Pending Outbox Events: {}", state.pending_outbox_count);
                    Text::new(&f1, Point::new(32, 248), text_muted).draw(target)?;

                    let mut f2: heapless::String<64> = heapless::String::new();
                    let _ = write!(
                        f2,
                        "RFID Scans: {} | Barcodes: {}",
                        state.rfid_count, state.barcode_count
                    );
                    Text::new(&f2, Point::new(32, 266), text_muted).draw(target)?;

                    let right_bounds = Rectangle::new(Point::new(538, 48), Size::new(250, card_h));
                    self.draw_event_stream_card(target, state, right_bounds)?;
                }
                SessionState::Authenticated { operator_id } => {
                    let card_h = available_h.saturating_sub(12);
                    let left_bounds = Rectangle::new(Point::new(12, 48), Size::new(514, card_h));
                    Card::new(left_bounds)
                        .title("OPERATOR READY - SCAN WORK ORDER")
                        .draw(target, &self.theme)?;

                    let success_bold = MonoTextStyle::new(&FONT_9X18_BOLD, self.theme.success());
                    let mut op_line: heapless::String<64> = heapless::String::new();
                    let _ = write!(op_line, "OPERATOR: {}", operator_id.as_str());
                    Text::new(&op_line, Point::new(32, 98), success_bold).draw(target)?;

                    let prompt_box = Rectangle::new(Point::new(32, 130), Size::new(474, 100));
                    let prompt_style = PrimitiveStyleBuilder::new()
                        .fill_color(self.theme.surface_active())
                        .stroke_color(self.theme.success())
                        .stroke_width(2)
                        .build();
                    prompt_box.draw_styled(&prompt_style, target)?;

                    Text::new(
                        "SCAN JOB BARCODE TO START",
                        Point::new(156, 172),
                        text_bold,
                    )
                    .draw(target)?;
                    Text::new(
                        "Scan work order barcode to begin job timing",
                        Point::new(140, 196),
                        text_muted,
                    )
                    .draw(target)?;

                    Text::new(
                        "Re-scan same RFID badge to log out",
                        Point::new(32, 254),
                        text_muted,
                    )
                    .draw(target)?;
                    Text::new(
                        "Scan another operator RFID badge to switch",
                        Point::new(32, 272),
                        text_muted,
                    )
                    .draw(target)?;

                    let right_bounds = Rectangle::new(Point::new(538, 48), Size::new(250, card_h));
                    self.draw_event_stream_card(target, state, right_bounds)?;
                }
                SessionState::Working {
                    operator_id,
                    job_id,
                    started_at_tick,
                } => {
                    TextField::new(Rectangle::new(Point::new(12, 48), Size::new(776, 40)))
                        .value(state.input_buffer.as_str())
                        .placeholder("<TYPE QA NOTES OR RE-SCAN JOB BARCODE TO STOP>")
                        .focused(state.keyboard_visible)
                        .draw(target, &self.theme)?;

                    let cards_y = 96;
                    let cards_h = available_h.saturating_sub(56).min(320);

                    if cards_h >= 60 {
                        let left_bounds =
                            Rectangle::new(Point::new(12, cards_y as i32), Size::new(514, cards_h));
                        Card::new(left_bounds)
                            .title("ACTIVE WORK SESSION")
                            .draw(target, &self.theme)?;

                        let mut op_line: heapless::String<64> = heapless::String::new();
                        let _ = write!(op_line, "OPERATOR: {}", operator_id.as_str());
                        Text::new(&op_line, Point::new(24, cards_y as i32 + 42), text_muted)
                            .draw(target)?;

                        let mut job_line: heapless::String<80> = heapless::String::new();
                        let _ = write!(job_line, "JOB ID:   {}", job_id.as_str());
                        Text::new(&job_line, Point::new(24, cards_y as i32 + 64), text_bold)
                            .draw(target)?;

                        let elapsed_s = state
                            .tick_count
                            .saturating_sub(*started_at_tick)
                            .saturating_mul(trillby_core::POLL_TIMEOUT_MS as u64)
                            / 1000;
                        let mut elapsed_line: heapless::String<64> = heapless::String::new();
                        let _ = write!(
                            elapsed_line,
                            "ELAPSED:  {:02}:{:02}:{:02}",
                            elapsed_s / 3600,
                            (elapsed_s % 3600) / 60,
                            elapsed_s % 60
                        );
                        let warning_bold =
                            MonoTextStyle::new(&FONT_9X18_BOLD, self.theme.warning());
                        Text::new(
                            &elapsed_line,
                            Point::new(24, cards_y as i32 + 92),
                            warning_bold,
                        )
                        .draw(target)?;

                        if cards_h >= 120 {
                            let mut hint_line: heapless::String<96> = heapless::String::new();
                            let _ = write!(
                                hint_line,
                                "Re-scan job barcode '{}' to finish",
                                job_id.as_str()
                            );
                            Text::new(&hint_line, Point::new(24, cards_y as i32 + 120), text_muted)
                                .draw(target)?;
                        }

                        let right_bounds =
                            Rectangle::new(Point::new(538, cards_y as i32), Size::new(250, cards_h));
                        self.draw_event_stream_card(target, state, right_bounds)?;
                    }
                }
            },
            Screen::Debug => {
                let is_input_focused = state.keyboard_visible;
                TextField::new(Rectangle::new(
                    Point::new(12, content_y as i32),
                    Size::new(776, 40),
                ))
                .value(state.input_buffer.as_str())
                .placeholder("<SCAN BARCODE OR RFID>")
                .focused(is_input_focused)
                .draw(target, &self.theme)?;

                let cards_y = content_y + 48;
                let cards_h = available_h.saturating_sub(56).min(320);

                if cards_h >= 60 {
                    let card_w = 250;

                    // Card 1: Touch Metrics Component
                    let card1_bounds =
                        Rectangle::new(Point::new(12, cards_y as i32), Size::new(card_w, cards_h));
                    Card::new(card1_bounds)
                        .title("TOUCH METRICS")
                        .draw(target, &self.theme)?;

                    let mut t1: heapless::String<64> = heapless::String::new();
                    let _ = write!(t1, "Events Count: {}", state.touch_count);
                    Text::new(&t1, Point::new(24, cards_y as i32 + 42), text_muted).draw(target)?;

                    let mut t2: heapless::String<64> = heapless::String::new();
                    let _ = write!(
                        t2,
                        "Raw Touch: ({}, {})",
                        state.last_touch_raw.0, state.last_touch_raw.1
                    );
                    Text::new(&t2, Point::new(24, cards_y as i32 + 58), text_muted).draw(target)?;

                    if cards_h >= 100 {
                        let mut t3: heapless::String<64> = heapless::String::new();
                        if let Some(s) = state.last_touch_scaled {
                            let _ = write!(t3, "Scaled: ({}, {})", s.x, s.y);
                        } else {
                            let _ = write!(t3, "Scaled: N/A");
                        }
                        Text::new(&t3, Point::new(24, cards_y as i32 + 74), text_muted)
                            .draw(target)?;
                    }

                    // Card 2: Hardware Telemetry Component
                    let card2_bounds =
                        Rectangle::new(Point::new(275, cards_y as i32), Size::new(card_w, cards_h));
                    Card::new(card2_bounds)
                        .title("HARDWARE TELEMETRY")
                        .draw(target, &self.theme)?;

                    let mut h1: heapless::String<64> = heapless::String::new();
                    let _ = write!(h1, "RFID Scans: {}", state.rfid_count);
                    Text::new(&h1, Point::new(287, cards_y as i32 + 42), text_muted)
                        .draw(target)?;

                    let mut h2: heapless::String<64> = heapless::String::new();
                    let _ = write!(h2, "Barcodes:   {}", state.barcode_count);
                    Text::new(&h2, Point::new(287, cards_y as i32 + 58), text_muted)
                        .draw(target)?;

                    if cards_h >= 100 {
                        let mut h3: heapless::String<64> = heapless::String::new();
                        let _ = write!(h3, "Keys Typed: {}", state.key_count);
                        Text::new(&h3, Point::new(287, cards_y as i32 + 74), text_muted)
                            .draw(target)?;
                    }

                    if cards_h >= 180 {
                        Button::new(core_rect_to_eg(DebugButton::StopJob.rect()), "STOP JOB")
                            .variant(
                                if matches!(state.session.state(), SessionState::Working { .. }) {
                                    ButtonVariant::Primary
                                } else {
                                    ButtonVariant::Secondary
                                },
                            )
                            .pressed(state.pressed_debug == Some(DebugButton::StopJob))
                            .draw(target, &self.theme)?;

                        Button::new(core_rect_to_eg(DebugButton::Logout.rect()), "LOGOUT")
                            .variant(
                                if !matches!(state.session.state(), SessionState::Idle) {
                                    ButtonVariant::Danger
                                } else {
                                    ButtonVariant::Secondary
                                },
                            )
                            .pressed(state.pressed_debug == Some(DebugButton::Logout))
                            .draw(target, &self.theme)?;
                    }

                    // Card 3: System Event History Component
                    let card3_bounds =
                        Rectangle::new(Point::new(538, cards_y as i32), Size::new(250, cards_h));
                    self.draw_event_stream_card(target, state, card3_bounds)?;
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

    fn draw_event_stream_card<D, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        bounds: Rectangle,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        Card::new(bounds)
            .title("SYSTEM EVENT STREAM")
            .draw(target, &self.theme)?;

        let text_muted = MonoTextStyle::new(&FONT_6X12, self.theme.text_muted());
        let max_log_items = (bounds.size.height.saturating_sub(40) / 14) as usize;
        for (i, entry) in state.event_history.iter().enumerate().take(max_log_items.min(6)) {
            if !entry.is_empty() {
                let y_pos = bounds.top_left.y + 42 + (i as i32 * 14);
                Text::new(
                    entry.as_str(),
                    Point::new(bounds.top_left.x + 12, y_pos),
                    text_muted,
                )
                .draw(target)?;
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

    #[test]
    fn test_render_all_operator_states_and_debug_screen() {
        let mut display: MockDisplay<Rgb565> = MockDisplay::new();
        display.set_allow_overdraw(true);
        display.set_allow_out_of_bounds_drawing(true);

        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let core_screen_bounds = eg_rect_to_core(screen_bounds);
        let renderer = UiRenderer::new(screen_bounds);
        let mut state: UiState<256> = UiState::new();

        // 1. Screen::Operator in SessionState::Idle
        assert_eq!(state.current_screen, Screen::Operator);
        assert_eq!(state.session.state(), &SessionState::Idle);
        assert!(renderer.render(&mut display, &state).is_ok());

        // 2. Screen::Operator in SessionState::Authenticated
        let op = heapless::String::try_from("OP-42").unwrap();
        state.handle_event(
            trillby_core::UiEvent::RfidScanned(op),
            core_screen_bounds,
            None,
            None,
        );
        assert!(matches!(
            state.session.state(),
            SessionState::Authenticated { .. }
        ));
        assert!(renderer.render(&mut display, &state).is_ok());

        // 3. Screen::Operator in SessionState::Working
        let job = heapless::String::try_from("JOB-9000").unwrap();
        state.handle_event(
            trillby_core::UiEvent::BarcodeScanned(job),
            core_screen_bounds,
            None,
            None,
        );
        state.tick_count = 1500;
        assert!(matches!(state.session.state(), SessionState::Working { .. }));
        assert!(renderer.render(&mut display, &state).is_ok());

        // 4. Screen::Debug in Working state and Idle state
        state.current_screen = Screen::Debug;
        assert!(renderer.render(&mut display, &state).is_ok());

        state.keyboard_visible = false;
        assert!(renderer.render(&mut display, &state).is_ok());
    }
}
