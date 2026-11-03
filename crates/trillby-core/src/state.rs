use crate::event::UiEvent;
use crate::geometry::{Point, Rect};
use crate::header::{DebugButton, HeaderButton};
use crate::keyboard_types::{Key, KeyboardLayer};
use crate::net_types::NetworkStatus;
use crate::session::{OperatorSession, SessionEvent, SessionRejectReason, SessionState};
use heapless::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Operator,
    Debug,
}

pub struct UiState<const N: usize> {
    pub current_screen: Screen,
    /// Auto-managed on session transitions (`true` in `Working`, `false` in
    /// `Idle`/`Authenticated`) and manually toggleable via the header KEYBOARD button.
    pub keyboard_visible: bool,
    /// Toggled only by `Key::LayerToggle`; survives hide/show (it's one byte
    /// inline in this struct, no allocation involved).
    pub keyboard_layer: KeyboardLayer,
    /// Header button currently held down (for pressed-state rendering).
    pub pressed_header: Option<HeaderButton>,
    /// Debug action button currently held down (for pressed-state rendering).
    pub pressed_debug: Option<DebugButton>,
    pub input_buffer: String<N>,
    pub last_touch_raw: (i32, i32),
    pub last_touch_scaled: Option<Point>,
    pub last_event_desc: String<64>,
    pub event_history: [String<64>; 6],
    pub history_count: usize,
    pub touch_count: u32,
    pub rfid_count: u32,
    pub barcode_count: u32,
    pub key_count: u32,
    pub tick_count: u64,
    pub dirty: bool,
    pub network_status: NetworkStatus,
    pub pending_outbox_count: u16,
    pub active_touch_key: Option<Key>,
    pub last_key_pressed: Option<Key>,
    pub session: OperatorSession,
}

impl<const N: usize> Default for UiState<N> {
    fn default() -> Self {
        let mut boot_msg = String::new();
        let _ = boot_msg.push_str("Boot Complete");

        let mut init_history: [String<64>; 6] = [
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
            String::new(),
        ];
        let _ = init_history[0].push_str("System initialized (Bare Framework Scaffolding)");

        Self {
            current_screen: Screen::Operator,
            keyboard_visible: false,
            keyboard_layer: KeyboardLayer::Alpha,
            pressed_header: None,
            pressed_debug: None,
            input_buffer: String::new(),
            last_touch_raw: (0, 0),
            last_touch_scaled: None,
            last_event_desc: boot_msg,
            event_history: init_history,
            history_count: 1,
            touch_count: 0,
            rfid_count: 0,
            barcode_count: 0,
            key_count: 0,
            tick_count: 0,
            dirty: true,
            network_status: NetworkStatus::Offline,
            pending_outbox_count: 0,
            active_touch_key: None,
            last_key_pressed: None,
            session: OperatorSession::new(),
        }
    }
}

impl<const N: usize> UiState<N> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn session_state(&self) -> &SessionState {
        self.session.state()
    }

    pub fn pop_session_event(&mut self) -> Option<SessionEvent> {
        self.session.pop_event()
    }


    pub fn push_event_log(&mut self, msg: &str) {
        self.last_event_desc.clear();
        let _ = self.last_event_desc.push_str(msg);

        // Shift history ring buffer
        for i in (1..6).rev() {
            self.event_history[i] = self.event_history[i - 1].clone();
        }
        self.event_history[0].clear();
        let _ = self.event_history[0].push_str(msg);
        if self.history_count < 6 {
            self.history_count += 1;
        }
    }

    /// Process an incoming UI event.
    pub fn handle_event(&mut self, event: UiEvent, _screen_bounds: Rect, kb_bounds: Option<Rect>, resolved_key: Option<Key>) {
        match event {
            UiEvent::Tick => {
                self.tick_count = self.tick_count.saturating_add(1);
                // Trigger 1Hz periodic UI refresh based on centralized poll frequency
                if self.tick_count.is_multiple_of(crate::POLL_FREQ_HZ as u64) {
                    self.dirty = true;
                }
            }
            UiEvent::TouchDown { scaled, raw } => {
                self.touch_count = self.touch_count.saturating_add(1);
                self.last_touch_raw = raw;
                self.last_touch_scaled = Some(scaled);
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "TouchDown s:({}, {}) r:({}, {})", scaled.x, scaled.y, raw.0, raw.1);
                self.push_event_log(&log_buf);

                if let Some(button) = HeaderButton::at(scaled) {
                    self.pressed_header = Some(button);
                    self.press_header(button);
                    return;
                }

                let in_kb = self.keyboard_visible && kb_bounds.is_some_and(|b| b.contains(scaled));
                if in_kb {
                    self.active_touch_key = resolved_key;
                } else if self.current_screen == Screen::Debug {
                    if let Some(dbg_btn) = DebugButton::at(scaled) {
                        self.pressed_debug = Some(dbg_btn);
                    }
                }
            }
            UiEvent::TouchMove { scaled, raw } => {
                self.last_touch_raw = raw;
                self.last_touch_scaled = Some(scaled);
                self.dirty = true;
                if self.keyboard_visible {
                    if let Some(bounds) = kb_bounds {
                        if bounds.contains(scaled) {
                            self.active_touch_key = resolved_key;
                        } else {
                            self.active_touch_key = None;
                        }
                    }
                }
            }
            UiEvent::TouchUp { scaled, raw } => {
                self.last_touch_raw = raw;
                self.last_touch_scaled = Some(scaled);
                self.pressed_header = None;
                self.pressed_debug = None;
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "TouchUp s:({}, {})", scaled.x, scaled.y);
                self.push_event_log(&log_buf);

                self.active_touch_key = None;

                let in_kb = self.keyboard_visible && kb_bounds.is_some_and(|b| b.contains(scaled));
                if let Some(key) = resolved_key {
                    if let Some(bounds) = kb_bounds {
                        if bounds.contains(scaled) {
                            self.apply_key(key);
                            self.key_count = self.key_count.saturating_add(1);
                            self.last_key_pressed = Some(key);

                            let mut key_msg: String<64> = String::new();
                            let _ = write!(key_msg, "Key Pressed: {:?}", key);
                            self.push_event_log(&key_msg);
                        }
                    }
                }

                if !in_kb && self.current_screen == Screen::Debug {
                    if let Some(dbg_btn) = DebugButton::at(scaled) {
                        match dbg_btn {
                            DebugButton::AuthUser => {
                                if self.session.force_authenticate(
                                    crate::session::DUMMY_OPERATOR_ID,
                                    self.tick_count,
                                ) {
                                    self.keyboard_visible = false;
                                    self.input_buffer.clear();
                                    let _ = self
                                        .input_buffer
                                        .push_str(crate::session::DUMMY_OPERATOR_ID);
                                    self.push_event_log("Debug: Authenticated Dummy User");
                                }
                            }
                            DebugButton::StartJob => {
                                if self.session.force_start_job(
                                    crate::session::DUMMY_OPERATOR_ID,
                                    crate::session::DUMMY_JOB_ID,
                                    self.tick_count,
                                ) {
                                    self.keyboard_visible = true;
                                    self.input_buffer.clear();
                                    self.push_event_log("Debug: Started Dummy Job");
                                }
                            }
                            DebugButton::StopJob => {
                                if self.session.force_stop_job(self.tick_count) {
                                    self.keyboard_visible = false;
                                    self.input_buffer.clear();
                                    self.push_event_log("Debug: Stopped Active Job");
                                }
                            }
                            DebugButton::Logout => {
                                if self.session.force_logout(self.tick_count) {
                                    self.keyboard_visible = false;
                                    self.input_buffer.clear();
                                    self.push_event_log("Debug: Operator Logged Out");
                                }
                            }
                        }
                    }
                }
            }
            UiEvent::RfidScanned(card_id) => {
                self.rfid_count = self.rfid_count.saturating_add(1);
                self.session.handle_rfid(&card_id, self.tick_count);
                self.keyboard_visible = matches!(self.session.state(), SessionState::Working { .. });
                self.input_buffer.clear();
                if !matches!(self.session.state(), SessionState::Idle) {
                    let _ = self.input_buffer.push_str(&card_id);
                }
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "RFID Scanned: {}", card_id);
                self.push_event_log(&log_buf);
            }
            UiEvent::BarcodeScanned(code) => {
                self.barcode_count = self.barcode_count.saturating_add(1);
                self.dirty = true;

                match self.session.handle_barcode(&code, self.tick_count) {
                    Ok(()) => {
                        self.keyboard_visible =
                            matches!(self.session.state(), SessionState::Working { .. });
                        self.input_buffer.clear();
                        use core::fmt::Write;
                        let mut log_buf: String<64> = String::new();
                        let _ = write!(log_buf, "Barcode Scanned: {}", code);
                        self.push_event_log(&log_buf);
                    }
                    Err(SessionRejectReason::NotAuthenticated) => {
                        self.push_event_log("Barcode Rejected: Not Authenticated");
                    }
                    Err(SessionRejectReason::JobMismatch) => {
                        self.push_event_log("Barcode Rejected: Active Job Mismatch");
                    }
                }
            }
            UiEvent::NetworkStatusChanged(status) => {
                if self.network_status != status {
                    self.network_status = status;
                    self.dirty = true;
                    use core::fmt::Write;
                    let mut log_buf: String<64> = String::new();
                    let _ = write!(log_buf, "Net Status: {:?}", status);
                    self.push_event_log(&log_buf);
                }
            }
        }
    }

    fn press_header(&mut self, button: HeaderButton) {
        match button {
            HeaderButton::Debug => {
                self.current_screen = match self.current_screen {
                    Screen::Operator => Screen::Debug,
                    Screen::Debug => Screen::Operator,
                };
                self.push_event_log(match self.current_screen {
                    Screen::Operator => "Screen: Operator",
                    Screen::Debug => "Screen: Debug",
                });
            }
            HeaderButton::Keyboard => {
                self.keyboard_visible = !self.keyboard_visible;
                self.push_event_log(if self.keyboard_visible {
                    "Keyboard: shown"
                } else {
                    "Keyboard: hidden"
                });
            }
            HeaderButton::Clear => {
                self.input_buffer.clear();
                self.history_count = 0;
                for slot in self.event_history.iter_mut() {
                    slot.clear();
                }
                self.push_event_log("Cleared Buffer & Event Log");
            }
        }
    }

    /// Apply a resolved virtual keypress.
    pub fn apply_key(&mut self, key: Key) {
        match key {
            Key::Char(c) => {
                let _ = self.input_buffer.push(c);
            }
            Key::Backspace => {
                let _ = self.input_buffer.pop();
            }
            Key::Space => {
                let _ = self.input_buffer.push(' ');
            }
            Key::LayerToggle => {
                self.keyboard_layer = self.keyboard_layer.toggled();
            }
            Key::Enter => {
                self.push_event_log("Submitted Buffer via ENTER");
            }
            // The UI resolves Special slots to their bound key before
            // dispatch; an unresolved one here is unbound, so ignore it.
            Key::Special(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{
        DEBUG_AUTH_USER_BUTTON, DEBUG_BUTTON, DEBUG_LOGOUT_BUTTON, DEBUG_START_JOB_BUTTON,
        DEBUG_STOP_JOB_BUTTON, KEYBOARD_BUTTON,
    };
    use crate::session::{DUMMY_JOB_ID, DUMMY_OPERATOR_ID};

    fn tap(state: &mut UiState<64>, p: Point) {
        let screen = Rect::new(Point::zero(), 800, 480);
        state.handle_event(UiEvent::TouchDown { scaled: p, raw: (0, 0) }, screen, None, None);
        state.handle_event(UiEvent::TouchUp { scaled: p, raw: (0, 0) }, screen, None, None);
    }

    #[test]
    fn keyboard_button_only_toggles_visibility() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_layer = KeyboardLayer::Symbols;
        let btn = Point::new(KEYBOARD_BUTTON.top_left.x + 5, 10);

        assert!(!s.keyboard_visible);
        tap(&mut s, btn);
        assert!(s.keyboard_visible);
        tap(&mut s, btn);
        assert!(!s.keyboard_visible);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Symbols);
        assert_eq!(s.pressed_header, None);
    }

    #[test]
    fn layer_toggle_never_hides_keyboard() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_visible = true;
        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Symbols);
        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Alpha);
        assert!(s.keyboard_visible);
    }

    #[test]
    fn debug_header_button_toggles_screen() {
        let mut s: UiState<64> = UiState::new();
        let dbg_btn = Point::new(DEBUG_BUTTON.top_left.x + 5, 10);

        assert_eq!(s.current_screen, Screen::Operator);
        tap(&mut s, dbg_btn);
        assert_eq!(s.current_screen, Screen::Debug);

        tap(&mut s, dbg_btn);
        assert_eq!(s.current_screen, Screen::Operator);
    }

    #[test]
    fn ui_state_session_workflow_and_rejections() {
        let mut s: UiState<64> = UiState::new();
        let screen = Rect::new(Point::zero(), 800, 480);

        // 1. Barcode scan while Idle -> rejected
        let job1: String<64> = String::try_from("JOB-101").unwrap();
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), screen, None, None);
        assert_eq!(s.barcode_count, 1);
        assert_eq!(s.input_buffer.as_str(), "");
        assert!(!s.keyboard_visible);
        assert_eq!(s.last_event_desc.as_str(), "Barcode Rejected: Not Authenticated");
        assert_eq!(s.session_state(), &SessionState::Idle);
        assert_eq!(s.pop_session_event(), None);

        // 2. Advance tick to 10 and scan RFID -> Authenticated
        for _ in 0..10 {
            s.handle_event(UiEvent::Tick, screen, None, None);
        }
        let badge: String<32> = String::try_from("BADGE-7").unwrap();
        s.handle_event(UiEvent::RfidScanned(badge.clone()), screen, None, None);
        assert_eq!(s.rfid_count, 1);
        assert_eq!(s.input_buffer.as_str(), "BADGE-7");
        assert!(!s.keyboard_visible);
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: badge.clone(),
                tick: 10
            })
        );

        // 3. Scan barcode while Authenticated -> Working (keyboard auto-shows, buffer cleared for notes)
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), screen, None, None);
        assert_eq!(s.barcode_count, 2);
        assert_eq!(s.input_buffer.as_str(), "");
        assert!(s.keyboard_visible);
        assert_eq!(s.last_event_desc.as_str(), "Barcode Scanned: JOB-101");
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStart {
                operator_id: badge.clone(),
                job_id: job1.clone(),
                started_at_tick: 10
            })
        );

        // Type QA notes while working
        s.apply_key(Key::Char('O'));
        s.apply_key(Key::Char('K'));
        assert_eq!(s.input_buffer.as_str(), "OK");

        // 4. Scan different barcode while Working -> rejected (notes preserved)
        let job2: String<64> = String::try_from("JOB-202").unwrap();
        s.handle_event(UiEvent::BarcodeScanned(job2), screen, None, None);
        assert_eq!(s.barcode_count, 3);
        assert_eq!(s.input_buffer.as_str(), "OK");
        assert!(s.keyboard_visible);
        assert_eq!(s.last_event_desc.as_str(), "Barcode Rejected: Active Job Mismatch");
        assert_eq!(s.pop_session_event(), None);

        // 5. Advance tick by 4 and scan matching barcode -> WorkStop (keyboard auto-hides, buffer cleared)
        for _ in 0..4 {
            s.handle_event(UiEvent::Tick, screen, None, None);
        }
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), screen, None, None);
        assert!(!s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), "");
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStop {
                operator_id: badge,
                job_id: job1,
                started_at_tick: 10,
                stopped_at_tick: 14,
                duration_ms: 4 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
    }

    #[test]
    fn debug_screen_stop_job_and_logout_buttons() {
        let mut s: UiState<64> = UiState::new();
        let screen = Rect::new(Point::zero(), 800, 480);
        let badge: String<32> = String::try_from("OP-9").unwrap();
        let job: String<64> = String::try_from("JOB-900").unwrap();

        s.handle_event(UiEvent::RfidScanned(badge.clone()), screen, None, None);
        s.handle_event(UiEvent::BarcodeScanned(job.clone()), screen, None, None);
        let _ = s.pop_session_event();
        let _ = s.pop_session_event();
        assert!(s.keyboard_visible);

        // Switch to Debug screen and hide keyboard so debug buttons are accessible
        tap(&mut s, Point::new(DEBUG_BUTTON.top_left.x + 5, 10));
        assert_eq!(s.current_screen, Screen::Debug);
        tap(&mut s, Point::new(KEYBOARD_BUTTON.top_left.x + 5, 10));
        assert!(!s.keyboard_visible);

        for _ in 0..6 {
            s.handle_event(UiEvent::Tick, screen, None, None);
        }

        // Tap STOP JOB
        let stop_pt = Point::new(
            DEBUG_STOP_JOB_BUTTON.top_left.x + 10,
            DEBUG_STOP_JOB_BUTTON.top_left.y + 10,
        );
        s.handle_event(UiEvent::TouchDown { scaled: stop_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::StopJob));
        s.handle_event(UiEvent::TouchUp { scaled: stop_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, None);
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStop {
                operator_id: badge.clone(),
                job_id: job,
                started_at_tick: 0,
                stopped_at_tick: 6,
                duration_ms: 6 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );

        // Tap LOGOUT
        let logout_pt = Point::new(
            DEBUG_LOGOUT_BUTTON.top_left.x + 10,
            DEBUG_LOGOUT_BUTTON.top_left.y + 10,
        );
        tap(&mut s, logout_pt);
        assert_eq!(s.session_state(), &SessionState::Idle);
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: badge,
                tick: 6,
            })
        );
    }

    #[test]
    fn debug_screen_auth_user_and_start_job_buttons() {
        let mut s: UiState<64> = UiState::new();
        let screen = Rect::new(Point::zero(), 800, 480);
        let dummy_op: String<32> = String::try_from(DUMMY_OPERATOR_ID).unwrap();
        let dummy_job: String<64> = String::try_from(DUMMY_JOB_ID).unwrap();

        // Switch to Debug screen
        tap(&mut s, Point::new(DEBUG_BUTTON.top_left.x + 5, 10));
        assert_eq!(s.current_screen, Screen::Debug);

        // 1. Tap AUTH USER from Idle -> Authenticated with DUMMY_OPERATOR_ID
        let auth_pt = Point::new(
            DEBUG_AUTH_USER_BUTTON.top_left.x + 10,
            DEBUG_AUTH_USER_BUTTON.top_left.y + 10,
        );
        s.handle_event(UiEvent::TouchDown { scaled: auth_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::AuthUser));
        s.handle_event(UiEvent::TouchUp { scaled: auth_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, None);
        assert!(!s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), DUMMY_OPERATOR_ID);
        assert_eq!(s.last_event_desc.as_str(), "Debug: Authenticated Dummy User");
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: dummy_op.clone()
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: dummy_op.clone(),
                tick: 0,
            })
        );

        // 2. Tap START JOB -> Working with DUMMY_JOB_ID
        let start_pt = Point::new(
            DEBUG_START_JOB_BUTTON.top_left.x + 10,
            DEBUG_START_JOB_BUTTON.top_left.y + 10,
        );
        s.handle_event(UiEvent::TouchDown { scaled: start_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::StartJob));
        s.handle_event(UiEvent::TouchUp { scaled: start_pt, raw: (0, 0) }, screen, None, None);
        assert_eq!(s.pressed_debug, None);
        assert!(s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), "");
        assert_eq!(s.last_event_desc.as_str(), "Debug: Started Dummy Job");
        assert_eq!(
            s.session_state(),
            &SessionState::Working {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_tick: 0,
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStart {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_tick: 0,
            })
        );

        // 3. Hide keyboard, tap AUTH USER while Working -> transitions back to Authenticated
        tap(&mut s, Point::new(KEYBOARD_BUTTON.top_left.x + 5, 10));
        assert!(!s.keyboard_visible);
        tap(&mut s, auth_pt);
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: dummy_op.clone()
            }
        );
        assert_eq!(s.input_buffer.as_str(), DUMMY_OPERATOR_ID);
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStop {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_tick: 0,
                stopped_at_tick: 0,
                duration_ms: 0,
            })
        );

        // 4. Logout, then tap START JOB directly from Idle -> auto-authenticates and starts job
        let logout_pt = Point::new(
            DEBUG_LOGOUT_BUTTON.top_left.x + 10,
            DEBUG_LOGOUT_BUTTON.top_left.y + 10,
        );
        tap(&mut s, logout_pt);
        let _ = s.pop_session_event();
        assert_eq!(s.session_state(), &SessionState::Idle);

        tap(&mut s, start_pt);
        assert!(s.keyboard_visible);
        assert_eq!(
            s.session_state(),
            &SessionState::Working {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_tick: 0,
            }
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: dummy_op.clone(),
                tick: 0,
            })
        );
        assert_eq!(
            s.pop_session_event(),
            Some(SessionEvent::WorkStart {
                operator_id: dummy_op,
                job_id: dummy_job,
                started_at_tick: 0,
            })
        );
    }
}
