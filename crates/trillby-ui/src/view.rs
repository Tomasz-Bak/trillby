use crate::keyboard_grid::KeyboardGrid;
use crate::layout::LayoutZones;
use crate::theme::{DarkFloorTheme, Theme};
use crate::widgets::{Badge, BadgeVariant, Button, ButtonVariant, Card, TextField};
use core::fmt::Write;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::MonoTextStyle,
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

const SECS_PER_HOUR: u64 = 3600;
const SECS_PER_MIN: u64 = 60;

fn write_hms(out: &mut impl core::fmt::Write, secs: u64) -> core::fmt::Result {
    let h = secs / SECS_PER_HOUR;
    let m = (secs % SECS_PER_HOUR) / SECS_PER_MIN;
    let s = secs % SECS_PER_MIN;
    write!(out, "{:02}:{:02}:{:02}", h, m, s)
}
const LINE_CAP: usize = 96;

fn draw_fmt<D>(
    target: &mut D,
    pos: Point,
    style: MonoTextStyle<Rgb565>,
    args: core::fmt::Arguments,
) -> Result<(), D::Error>
where
    D: DrawTarget<Color = Rgb565>,
{
    use core::fmt::Write;
    let mut buf: heapless::String<LINE_CAP> = heapless::String::new();
    let _ = trillby_core::Truncating(&mut buf).write_fmt(args);
    Text::new(&buf, pos, style).draw(target)?;
    Ok(())
}

const HEADER_BUTTONS: [(HeaderButton, &str); 3] = [
    (HeaderButton::Debug, "DEBUG"),
    (HeaderButton::Keyboard, "KEYBOARD"),
    (HeaderButton::Clear, "CLEAR"),
];

fn header_button_variant<const N: usize>(btn: HeaderButton, state: &UiState<N>) -> ButtonVariant {
    match btn {
        HeaderButton::Debug => {
            if state.current_screen == Screen::Debug {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            }
        }
        HeaderButton::Keyboard => {
            if state.keyboard_visible {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            }
        }
        HeaderButton::Clear => ButtonVariant::Outline,
    }
}

const DEBUG_BUTTONS: [(DebugButton, &str); 4] = [
    (DebugButton::AuthUser, "AUTH USER"),
    (DebugButton::StartJob, "START JOB"),
    (DebugButton::StopJob, "STOP JOB"),
    (DebugButton::Logout, "LOGOUT"),
];

const DEBUG_BUTTONS_MIN_H: u32 = (trillby_core::header::DEBUG_LOGOUT_BUTTON.top_left.y
    + trillby_core::header::DEBUG_LOGOUT_BUTTON.height as i32
    - trillby_core::header::DEBUG_PANEL.top_left.y
    + 6) as u32;

fn debug_button_variant(btn: DebugButton, s: &SessionState) -> ButtonVariant {
    match btn {
        DebugButton::AuthUser => {
            if matches!(s, SessionState::Idle) {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            }
        }
        DebugButton::StartJob => {
            if !matches!(s, SessionState::Working { .. }) {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            }
        }
        DebugButton::StopJob => {
            if matches!(s, SessionState::Working { .. }) {
                ButtonVariant::Primary
            } else {
                ButtonVariant::Secondary
            }
        }
        DebugButton::Logout => {
            if !matches!(s, SessionState::Idle) {
                ButtonVariant::Danger
            } else {
                ButtonVariant::Secondary
            }
        }
    }
}
const MARGIN: u32 = 12;
const RIGHT_COL_W: u32 = 250;
const FIELD_H: u32 = 40;
const CONTENT_TOP: i32 = trillby_core::header::HEADER_HEIGHT as i32 + MARGIN as i32;
const BADGE_NET_X: i32 = 248;
const BADGE_SESSION_X: i32 = 322;
const CARD_BODY_TOP: i32 = 42;
const LINE_H: i32 = 16;
const LOG_LINE_H: i32 = 14;

const PROMPT_RFID_TITLE_X: i32 = 161;
const PROMPT_RFID_SUB_X: i32 = 158;
const PROMPT_JOB_TITLE_X: i32 = 156;
const PROMPT_JOB_SUB_X: i32 = 140;

#[inline]
fn row_y(card_top: i32, row: i32) -> i32 {
    card_top + CARD_BODY_TOP + row * LINE_H
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
    fn columns(&self, top: i32, height: u32) -> (Rectangle, Rectangle) {
        let left_w = self.screen_bounds.size.width.saturating_sub(3 * MARGIN + RIGHT_COL_W);
        let left = Rectangle::new(
            Point::new(self.screen_bounds.top_left.x + MARGIN as i32, top),
            Size::new(left_w, height),
        );
        let right_x = left.top_left.x + left_w as i32 + MARGIN as i32;
        let right = Rectangle::new(
            Point::new(right_x, top),
            Size::new(RIGHT_COL_W, height),
        );
        (left, right)
    }
    fn cards_height(available_h: u32) -> u32 {
        available_h.saturating_sub(56).min(320)
    }

    fn draw_prompt_box<D: DrawTarget<Color = Rgb565>>(
        &self,
        target: &mut D,
        rect: Rectangle,
        accent: Rgb565,
    ) -> Result<(), D::Error> {
        let prompt_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.surface_active())
            .stroke_color(accent)
            .stroke_width(2)
            .build();
        rect.draw_styled(&prompt_style, target)
    }

    fn draw_input_field<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        placeholder: &str,
    ) -> Result<(), D::Error> {
        let field_w = self.screen_bounds.size.width.saturating_sub(2 * MARGIN);
        TextField::new(Rectangle::new(
            Point::new(self.screen_bounds.top_left.x + MARGIN as i32, CONTENT_TOP),
            Size::new(field_w, FIELD_H),
        ))
        .value(state.input_buffer.as_str())
        .placeholder(placeholder)
        .focused(state.keyboard_visible)
        .draw(target, &self.theme)
    }


    fn draw_header<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
    ) -> Result<(), D::Error> {
        // 1. Draw Root Screen Background
        let bg_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.background())
            .build();
        self.screen_bounds.draw_styled(&bg_style, target)?;

        // 2. Navigation Header Bar (36px high)
        let header_rect = Rectangle::new(
            Point::zero(),
            Size::new(self.screen_bounds.size.width, HEADER_HEIGHT),
        );
        let header_style = PrimitiveStyleBuilder::new()
            .fill_color(self.theme.surface())
            .stroke_color(self.theme.border())
            .stroke_width(1)
            .build();
        header_rect.draw_styled(&header_style, target)?;

        let title_style = MonoTextStyle::new(self.theme.font_large(), self.theme.primary());
        Text::new(
            "TRILLBY | SCANNER CLIENT",
            Point::new(self.screen_bounds.top_left.x + MARGIN as i32, 24),
            title_style,
        )
        .draw(target)?;

        // Header Network Status Badge
        let (badge_label, badge_variant) = match state.network_status {
            trillby_core::net_types::NetworkStatus::Online => ("ONLINE", BadgeVariant::Success),
            trillby_core::net_types::NetworkStatus::Offline => ("OFFLINE", BadgeVariant::Warning),
            trillby_core::net_types::NetworkStatus::Connecting => ("LINKING", BadgeVariant::Warning),
            trillby_core::net_types::NetworkStatus::Handshaking => ("AUTH", BadgeVariant::Warning),
            trillby_core::net_types::NetworkStatus::Syncing(_) => ("SYNC", BadgeVariant::Info),
        };
        Badge::new(Point::new(BADGE_NET_X, 9), badge_label)
            .variant(badge_variant)
            .draw(target, &self.theme)?;

        // Header Session State Badge
        let (session_label, session_variant) = match state.session_state() {
            SessionState::Idle => ("IDLE", BadgeVariant::Info),
            SessionState::Authenticated { .. } => ("READY", BadgeVariant::Success),
            SessionState::Working { .. } => ("WORKING", BadgeVariant::Warning),
        };
        Badge::new(Point::new(BADGE_SESSION_X, 9), session_label)
            .variant(session_variant)
            .draw(target, &self.theme)?;

        // Header Action Buttons (rects shared with UiState hit-testing)
        for (btn, label) in HEADER_BUTTONS {
            Button::new(core_rect_to_eg(btn.rect()), label)
                .variant(header_button_variant(btn, state))
                .pressed(state.pressed_header == Some(btn))
                .draw(target, &self.theme)?;
        }

        Ok(())
    }

    fn draw_operator_idle<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        available_h: u32,
        text_muted: MonoTextStyle<Rgb565>,
        text_bold: MonoTextStyle<Rgb565>,
    ) -> Result<(), D::Error> {
        let card_h = available_h.saturating_sub(MARGIN);
        let (left_bounds, right_bounds) = self.columns(CONTENT_TOP, card_h);
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
        self.draw_prompt_box(target, prompt_box, self.theme.primary())?;

        let primary_bold = MonoTextStyle::new(self.theme.font_large(), self.theme.primary());
        Text::new(
            "SCAN OPERATOR RFID BADGE",
            Point::new(PROMPT_RFID_TITLE_X, 162),
            primary_bold,
        )
        .draw(target)?;
        Text::new(
            "Hold RFID badge near reader to log in",
            Point::new(PROMPT_RFID_SUB_X, 186),
            text_muted,
        )
        .draw(target)?;

        draw_fmt(
            target,
            Point::new(32, 248),
            text_muted,
            format_args!("Pending Outbox Events: {}", state.pending_outbox_count),
        )?;

        draw_fmt(
            target,
            Point::new(32, 266),
            text_muted,
            format_args!(
                "RFID Scans: {} | Barcodes: {}",
                state.rfid_count, state.barcode_count
            ),
        )?;

        self.draw_event_stream_card(target, state, right_bounds, text_muted)?;
        Ok(())
    }

    fn draw_operator_authenticated<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        operator_id: &str,
        available_h: u32,
        text_muted: MonoTextStyle<Rgb565>,
        text_bold: MonoTextStyle<Rgb565>,
    ) -> Result<(), D::Error> {
        let card_h = available_h.saturating_sub(MARGIN);
        let (left_bounds, right_bounds) = self.columns(CONTENT_TOP, card_h);
        Card::new(left_bounds)
            .title("OPERATOR READY - SCAN WORK ORDER")
            .draw(target, &self.theme)?;

        let success_bold = MonoTextStyle::new(self.theme.font_large(), self.theme.success());
        draw_fmt(
            target,
            Point::new(32, 98),
            success_bold,
            format_args!("OPERATOR: {}", operator_id),
        )?;

        let prompt_box = Rectangle::new(Point::new(32, 130), Size::new(474, 100));
        self.draw_prompt_box(target, prompt_box, self.theme.success())?;

        Text::new(
            "SCAN JOB BARCODE TO START",
            Point::new(PROMPT_JOB_TITLE_X, 172),
            text_bold,
        )
        .draw(target)?;
        Text::new(
            "Scan work order barcode to begin job timing",
            Point::new(PROMPT_JOB_SUB_X, 196),
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

        self.draw_event_stream_card(target, state, right_bounds, text_muted)?;
        Ok(())
    }
    #[allow(clippy::too_many_arguments)]
    fn draw_operator_working<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        operator_id: &str,
        job_id: &str,
        started_at_ms: u64,
        available_h: u32,
        text_muted: MonoTextStyle<Rgb565>,
        text_bold: MonoTextStyle<Rgb565>,
    ) -> Result<(), D::Error> {
        self.draw_input_field(
            target,
            state,
            "<TYPE QA NOTES OR RE-SCAN JOB BARCODE TO STOP>",
        )?;

        let cards_y = CONTENT_TOP + FIELD_H as i32 + 8;
        let cards_h = Self::cards_height(available_h);

        if cards_h >= 60 {
            let (left_bounds, right_bounds) = self.columns(cards_y, cards_h);
            Card::new(left_bounds)
                .title("ACTIVE WORK SESSION")
                .draw(target, &self.theme)?;

            draw_fmt(
                target,
                Point::new(24, cards_y + 42),
                text_muted,
                format_args!("OPERATOR: {}", operator_id),
            )?;

            draw_fmt(
                target,
                Point::new(24, cards_y + 64),
                text_bold,
                format_args!("JOB ID:   {}", job_id),
            )?;

            let elapsed_s = state.now_ms().saturating_sub(started_at_ms) / 1000;
            let mut elapsed_line: heapless::String<LINE_CAP> = heapless::String::new();
            let _ = write!(trillby_core::Truncating(&mut elapsed_line), "ELAPSED:  ");
            let _ = write_hms(&mut trillby_core::Truncating(&mut elapsed_line), elapsed_s);
            let warning_bold =
                MonoTextStyle::new(self.theme.font_large(), self.theme.warning());
            Text::new(
                &elapsed_line,
                Point::new(24, cards_y + 92),
                warning_bold,
            )
            .draw(target)?;

            if cards_h >= 120 {
                draw_fmt(
                    target,
                    Point::new(24, cards_y + 120),
                    text_muted,
                    format_args!(
                        "Re-scan job barcode '{}' to finish",
                        job_id
                    ),
                )?;
            }

            self.draw_event_stream_card(target, state, right_bounds, text_muted)?;
        }
        Ok(())
    }

    fn draw_debug<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        available_h: u32,
        text_muted: MonoTextStyle<Rgb565>,
    ) -> Result<(), D::Error> {
        self.draw_input_field(target, state, "<SCAN BARCODE OR RFID>")?;

        let cards_y = CONTENT_TOP + FIELD_H as i32 + 8;
        let cards_h = Self::cards_height(available_h);

        if cards_h >= 60 {
            let card_w = 250;

            // Card 1: Touch Metrics Component
            let card1_bounds = Rectangle::new(
                Point::new(self.screen_bounds.top_left.x + MARGIN as i32, cards_y),
                Size::new(card_w, cards_h),
            );
            Card::new(card1_bounds)
                .title("TOUCH METRICS")
                .draw(target, &self.theme)?;

            draw_fmt(
                target,
                Point::new(24, row_y(cards_y, 0)),
                text_muted,
                format_args!("Events Count: {}", state.touch_count),
            )?;

            draw_fmt(
                target,
                Point::new(24, row_y(cards_y, 1)),
                text_muted,
                format_args!(
                    "Raw Touch: ({}, {})",
                    state.last_touch_raw.0, state.last_touch_raw.1
                ),
            )?;

            if cards_h >= 100 {
                if let Some(s) = state.last_touch_scaled {
                    draw_fmt(
                        target,
                        Point::new(24, row_y(cards_y, 2)),
                        text_muted,
                        format_args!("Scaled: ({}, {})", s.x, s.y),
                    )?;
                } else {
                    Text::new("Scaled: N/A", Point::new(24, row_y(cards_y, 2)), text_muted)
                        .draw(target)?;
                }
            }

            // Card 2: Hardware Telemetry Component
            let card2_bounds = Rectangle::new(
                Point::new(trillby_core::header::DEBUG_PANEL.top_left.x, cards_y),
                Size::new(card_w, cards_h),
            );
            Card::new(card2_bounds)
                .title("HARDWARE TELEMETRY")
                .draw(target, &self.theme)?;

            draw_fmt(
                target,
                Point::new(287, row_y(cards_y, 0)),
                text_muted,
                format_args!("RFID Scans: {}", state.rfid_count),
            )?;

            draw_fmt(
                target,
                Point::new(287, row_y(cards_y, 1)),
                text_muted,
                format_args!("Barcodes:   {}", state.barcode_count),
            )?;

            if cards_h >= 100 {
                draw_fmt(
                    target,
                    Point::new(287, row_y(cards_y, 2)),
                    text_muted,
                    format_args!("Keys Typed: {}", state.key_count),
                )?;
            }

            if cards_h >= DEBUG_BUTTONS_MIN_H {
                for (btn, label) in DEBUG_BUTTONS {
                    Button::new(core_rect_to_eg(btn.rect()), label)
                        .variant(debug_button_variant(btn, state.session_state()))
                        .pressed(state.pressed_debug == Some(btn))
                        .draw(target, &self.theme)?;
                }
            }

            // Card 3: System Event History Component
            let (_, card3_bounds) = self.columns(cards_y, cards_h);
            self.draw_event_stream_card(target, state, card3_bounds, text_muted)?;
        }

        Ok(())
    }

    fn draw_keyboard<D: DrawTarget<Color = Rgb565>, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        kb_rect: Rectangle,
    ) -> Result<(), D::Error> {
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

        Ok(())
    }

    pub fn render<D, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        let target = &mut target.clipped(&self.screen_bounds);
        // Compute 2-State Responsive Layout Zones (Keyboard Hidden vs Active)
        let zones = LayoutZones::compute(self.screen_bounds, state.keyboard_visible);

        self.draw_header(target, state)?;

        // 3. Responsive Content Viewport
        let available_h = zones.content_area.size.height.saturating_sub(CONTENT_TOP as u32);
        let text_muted = MonoTextStyle::new(self.theme.font_small(), self.theme.text_muted());
        let text_bold = MonoTextStyle::new(self.theme.font_large(), self.theme.text());

        match state.current_screen {
            Screen::Operator => match state.session_state() {
                SessionState::Idle => {
                    self.draw_operator_idle(target, state, available_h, text_muted, text_bold)?;
                }
                SessionState::Authenticated { operator_id } => {
                    self.draw_operator_authenticated(
                        target,
                        state,
                        operator_id.as_str(),
                        available_h,
                        text_muted,
                        text_bold,
                    )?;
                }
                SessionState::Working {
                    operator_id,
                    job_id,
                    started_at_ms,
                } => {
                    self.draw_operator_working(
                        target,
                        state,
                        operator_id.as_str(),
                        job_id.as_str(),
                        *started_at_ms,
                        available_h,
                        text_muted,
                        text_bold,
                    )?;
                }
            },
            Screen::Debug => {
                self.draw_debug(target, state, available_h, text_muted)?;
            }
        }

        // 4. Virtual keyboard: one pass over the shared slot table.
        if let Some(kb_rect) = zones.keyboard_area {
            self.draw_keyboard(target, state, kb_rect)?;
        }

        Ok(())
    }

    fn draw_event_stream_card<D, const N: usize>(
        &self,
        target: &mut D,
        state: &UiState<N>,
        bounds: Rectangle,
        text_muted: MonoTextStyle<Rgb565>,
    ) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
    {
        Card::new(bounds)
            .title("SYSTEM EVENT STREAM")
            .draw(target, &self.theme)?;

        let mut content = target.clipped(&bounds);
        let max_log_items = (bounds.size.height.saturating_sub(40) / LOG_LINE_H as u32) as usize;
        for (i, entry) in state.event_history.iter().enumerate().take(max_log_items.min(state.event_history.len())) {
            if !entry.is_empty() {
                let y_pos = bounds.top_left.y + CARD_BODY_TOP + (i as i32 * LOG_LINE_H);
                Text::new(
                    entry.as_str(),
                    Point::new(bounds.top_left.x + MARGIN as i32, y_pos),
                    text_muted,
                )
                .draw(&mut content)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        first_alpha_key_cell, login, region_equals, render_to_canvas, start_job, BADGE_REGION,
        TestCanvas,
    };
    use crate::{SCREEN_HEIGHT, SCREEN_WIDTH};

    #[test]
    fn test_render_never_draws_out_of_bounds_across_all_screens_and_states() {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let renderer = UiRenderer::new(screen_bounds);

        // 1. Screen::Operator - Idle
        let mut canvas = TestCanvas::new(true);
        let mut state: UiState<256> = UiState::new();
        assert_eq!(state.current_screen, Screen::Operator);
        assert_eq!(state.session_state(), &SessionState::Idle);
        assert!(renderer.render(&mut canvas, &state).is_ok());

        // 2. Screen::Operator - Authenticated
        login(&mut state, "OP_42");
        assert!(matches!(
            state.session_state(),
            SessionState::Authenticated { .. }
        ));
        assert!(renderer.render(&mut canvas, &state).is_ok());

        // 3. Screen::Operator - Working with 64-char job_id and now_ms = 360_000_000
        let mut long_job: heapless::String<64> = heapless::String::new();
        for _ in 0..64 {
            let _ = long_job.push('J');
        }
        state.handle_event(
            trillby_core::UiEvent::BarcodeScanned(long_job),
            None,
            None,
        );
        state.set_now_ms(360_000_000);
        assert!(matches!(state.session_state(), SessionState::Working { .. }));
        assert!(renderer.render(&mut canvas, &state).is_ok());

        // 4. Screen::Debug with keyboard_visible = true and false
        state.current_screen = Screen::Debug;
        state.keyboard_visible = true;
        assert!(renderer.render(&mut canvas, &state).is_ok());

        state.keyboard_visible = false;
        assert!(renderer.render(&mut canvas, &state).is_ok());
    }

    #[test]
    fn test_render_pixel_regions_change_on_state_keyboard_key_and_network_transitions() {
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));
        let renderer = UiRenderer::new(screen_bounds);

        // 1. Content card region (x: 20..500, y: 100..260) between Idle, Authenticated, and Working
        let state_idle: UiState<256> = UiState::new();
        let canvas_idle = render_to_canvas(&renderer, &state_idle);

        let mut state_auth: UiState<256> = UiState::new();
        login(&mut state_auth, "OP_42");
        let canvas_auth = render_to_canvas(&renderer, &state_auth);

        let mut state_working: UiState<256> = UiState::new();
        start_job(&mut state_working, "OP_1", "JOB_1");
        let canvas_working = render_to_canvas(&renderer, &state_working);

        let card_x = 20..500;
        let card_y = 100..260;
        assert!(!region_equals(&canvas_idle, &canvas_auth, card_x.clone(), card_y.clone()));
        assert!(!region_equals(&canvas_auth, &canvas_working, card_x.clone(), card_y.clone()));
        assert!(!region_equals(&canvas_idle, &canvas_working, card_x, card_y));

        // 2. Keyboard region (x: 0..800, y: 300..480) between keyboard_visible = false and true
        let mut state_kb_hidden: UiState<256> = UiState::new();
        state_kb_hidden.keyboard_visible = false;
        let canvas_kb_hidden = render_to_canvas(&renderer, &state_kb_hidden);

        let mut state_kb_visible: UiState<256> = UiState::new();
        state_kb_visible.keyboard_visible = true;
        let canvas_kb_visible = render_to_canvas(&renderer, &state_kb_visible);

        assert!(!region_equals(
            &canvas_kb_hidden,
            &canvas_kb_visible,
            0..SCREEN_WIDTH as i32,
            300..SCREEN_HEIGHT as i32,
        ));

        let mut has_surface = false;
        let mut has_border = false;
        for y in 300..(SCREEN_HEIGHT as i32) {
            for x in 0..(SCREEN_WIDTH as i32) {
                let p = canvas_kb_visible.px(x, y);
                if p == renderer.theme.surface() {
                    has_surface = true;
                }
                if p == renderer.theme.border() {
                    has_border = true;
                }
            }
        }
        assert!(has_surface);
        assert!(has_border);

        // 3. Key 'Q' interior region when active_touch_key = Some(Key::Char('Q')) vs None
        let mut state_unpressed: UiState<256> = UiState::new();
        state_unpressed.keyboard_visible = true;
        state_unpressed.active_touch_key = None;
        let canvas_unpressed = render_to_canvas(&renderer, &state_unpressed);

        let mut state_pressed: UiState<256> = UiState::new();
        state_pressed.keyboard_visible = true;
        state_pressed.active_touch_key = Some(Key::Char('Q'));
        let canvas_pressed = render_to_canvas(&renderer, &state_pressed);

        let first_key = first_alpha_key_cell();
        assert!(!region_equals(
            &canvas_unpressed,
            &canvas_pressed,
            first_key.columns(),
            first_key.rows(),
        ));
        let probe = first_key.top_left + Point::new(20, 2);
        assert_eq!(canvas_unpressed.px(probe.x, probe.y), renderer.theme.border());
        assert_eq!(canvas_pressed.px(probe.x, probe.y), renderer.theme.primary());

        // 4. Header network status badge region (x: 180..360, y: 6..30)
        let mut state_offline: UiState<256> = UiState::new();
        state_offline.network_status = trillby_core::net_types::NetworkStatus::Offline;
        let canvas_offline = render_to_canvas(&renderer, &state_offline);

        let mut state_online: UiState<256> = UiState::new();
        state_online.network_status = trillby_core::net_types::NetworkStatus::Online;
        let canvas_online = render_to_canvas(&renderer, &state_online);

        assert!(!region_equals(
            &canvas_offline,
            &canvas_online,
            BADGE_REGION.columns(),
            BADGE_REGION.rows(),
        ));

        let mut offline_has_warning = false;
        let mut online_has_success = false;
        for y in BADGE_REGION.rows() {
            for x in BADGE_REGION.columns() {
                if canvas_offline.px(x, y) == renderer.theme.warning() {
                    offline_has_warning = true;
                }
                if canvas_online.px(x, y) == renderer.theme.success() {
                    online_has_success = true;
                }
            }
        }
        assert!(offline_has_warning);
        assert!(online_has_success);
    }

    #[test]
    fn test_write_hms() {
        let mut s: heapless::String<16> = heapless::String::new();
        write_hms(&mut s, 0).unwrap();
        assert_eq!(s.as_str(), "00:00:00");

        s.clear();
        write_hms(&mut s, 3661).unwrap();
        assert_eq!(s.as_str(), "01:01:01");

        s.clear();
        write_hms(&mut s, 36000).unwrap();
        assert_eq!(s.as_str(), "10:00:00");
    }

    #[test]
    fn test_columns_layout() {
        let renderer = UiRenderer::new(Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT)));
        let (left, right) = renderer.columns(CONTENT_TOP, 300);

        assert_eq!(left, Rectangle::new(Point::new(12, 48), Size::new(514, 300)));
        assert_eq!(right, Rectangle::new(Point::new(538, 48), Size::new(250, 300)));

        let offset_renderer = UiRenderer::new(Rectangle::new(Point::new(10, 20), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT)));
        let (offset_left, offset_right) = offset_renderer.columns(CONTENT_TOP, 300);
        assert_eq!(offset_left, Rectangle::new(Point::new(22, 48), Size::new(514, 300)));
        assert_eq!(offset_right, Rectangle::new(Point::new(548, 48), Size::new(250, 300)));
    }
}
