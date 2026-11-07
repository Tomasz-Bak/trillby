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

pub const EVENT_LOG_LINE_CAP: usize = 64;
pub const EVENT_HISTORY_LEN: usize = 6;

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
    pub event_history: [String<EVENT_LOG_LINE_CAP>; EVENT_HISTORY_LEN],
    pub touch_count: u32,
    pub rfid_count: u32,
    pub barcode_count: u32,
    pub key_count: u32,
    now_ms: u64,
    pub dirty: bool,
    pub network_status: NetworkStatus,
    pub pending_outbox_count: u16,
    pub active_touch_key: Option<Key>,
    session: OperatorSession,
}

impl<const N: usize> Default for UiState<N> {
    fn default() -> Self {
        let mut init_history: [String<EVENT_LOG_LINE_CAP>; EVENT_HISTORY_LEN] =
            core::array::from_fn(|_| String::new());
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
            event_history: init_history,
            touch_count: 0,
            rfid_count: 0,
            barcode_count: 0,
            key_count: 0,
            now_ms: 0,
            dirty: true,
            network_status: NetworkStatus::Offline,
            pending_outbox_count: 0,
            active_touch_key: None,
            session: OperatorSession::new(),
        }
    }
}

/// `fmt::Write` adapter that appends whole chars until full, then stops
/// formatting (heapless' own `write_str` drops an overflowing piece entirely).
pub struct Truncating<'a, const CAP: usize>(pub &'a mut String<CAP>);

impl<const CAP: usize> core::fmt::Write for Truncating<'_, CAP> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        if crate::push_truncated(self.0, s) {
            Ok(())
        } else {
            Err(core::fmt::Error)
        }
    }
}

impl<const N: usize> UiState<N> {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn now_ms(&self) -> u64 {
        self.now_ms
    }

    pub fn set_now_ms(&mut self, now_ms: u64) {
        if now_ms / 1000 != self.now_ms / 1000 {
            self.dirty = true;
        }
        self.now_ms = now_ms;
    }
    pub fn session_state(&self) -> &SessionState {
        self.session.state()
    }

    pub fn pop_session_event(&mut self) -> Option<SessionEvent> {
        self.session.pop_event()
    }

    fn set_keyboard_visible(&mut self, visible: bool) {
        self.keyboard_visible = visible;
        if !visible {
            self.active_touch_key = None;
        }
    }

    fn sync_after_session_change(&mut self, log: &str) {
        self.set_keyboard_visible(matches!(self.session.state(), SessionState::Working { .. }));
        self.input_buffer.clear();
        if !log.is_empty() {
            self.push_event_log(log);
        }
    }

    fn log_fmt(&mut self, args: core::fmt::Arguments<'_>) {
        use core::fmt::Write;
        self.event_history.rotate_right(1);
        self.event_history[0].clear();
        let _ = Truncating(&mut self.event_history[0]).write_fmt(args);
    }

    pub fn push_event_log(&mut self, msg: &str) {
        self.log_fmt(format_args!("{}", msg));
    }
    fn update_touch_position(&mut self, scaled: Point, raw: (i32, i32)) {
        self.last_touch_raw = raw;
        self.last_touch_scaled = Some(scaled);
        self.dirty = true;
    }

    fn is_in_kb(&self, scaled: Point, kb_bounds: Option<Rect>) -> bool {
        self.keyboard_visible && kb_bounds.is_some_and(|b| b.contains(scaled))
    }

    /// Process an incoming UI event.
    pub fn handle_event(&mut self, event: UiEvent, kb_bounds: Option<Rect>, resolved_key: Option<Key>) {
        match event {
            UiEvent::TouchDown { scaled, raw } => {
                self.touch_count = self.touch_count.saturating_add(1);
                self.update_touch_position(scaled, raw);

                self.log_fmt(format_args!("TouchDown s:({}, {}) r:({}, {})", scaled.x, scaled.y, raw.0, raw.1));
                if let Some(button) = HeaderButton::at(scaled) {
                    self.pressed_header = Some(button);
                    self.press_header(button);
                    return;
                }

                if self.is_in_kb(scaled, kb_bounds) {
                    self.active_touch_key = resolved_key;
                } else if self.current_screen == Screen::Debug {
                    if let Some(dbg_btn) = DebugButton::at(scaled) {
                        self.pressed_debug = Some(dbg_btn);
                    }
                }
            }
            UiEvent::TouchMove { scaled, raw } => {
                self.update_touch_position(scaled, raw);
                if self.is_in_kb(scaled, kb_bounds) {
                    self.active_touch_key = resolved_key;
                } else if self.keyboard_visible && kb_bounds.is_some() {
                    self.active_touch_key = None;
                }
                if self.pressed_debug.is_some_and(|b| !b.rect().contains(scaled)) {
                    self.pressed_debug = None;
                }
            }
            UiEvent::TouchUp { scaled, raw } => {
                self.update_touch_position(scaled, raw);
                self.pressed_header = None;
                let armed_debug = self.pressed_debug.take();

                self.log_fmt(format_args!("TouchUp s:({}, {})", scaled.x, scaled.y));

                self.active_touch_key = None;

                if self.is_in_kb(scaled, kb_bounds) {
                    if let Some(key) = resolved_key {
                        self.apply_key(key);
                        self.key_count = self.key_count.saturating_add(1);

                        self.log_fmt(format_args!("Key Pressed: {:?}", key));
                    }
                } else if self.current_screen == Screen::Debug {
                    if let Some(dbg_btn) = DebugButton::at(scaled).filter(|b| Some(*b) == armed_debug) {
                        match dbg_btn {
                            DebugButton::AuthUser => {
                                if self.session.force_authenticate(
                                    crate::session::DUMMY_OPERATOR_ID,
                                    self.now_ms,
                                ) {
                                    self.sync_after_session_change("Debug: Authenticated Dummy User");
                                    let _ = self
                                        .input_buffer
                                        .push_str(crate::session::DUMMY_OPERATOR_ID);
                                }
                            }
                            DebugButton::StartJob => {
                                if self.session.force_start_job(
                                    crate::session::DUMMY_OPERATOR_ID,
                                    crate::session::DUMMY_JOB_ID,
                                    self.now_ms,
                                ) {
                                    self.sync_after_session_change("Debug: Started Dummy Job");
                                }
                            }
                            DebugButton::StopJob => {
                                if self.session.stop_work(self.now_ms).is_some() {
                                    self.sync_after_session_change("Debug: Stopped Active Job");
                                }
                            }
                            DebugButton::Logout => {
                                if self.session.logout(self.now_ms) {
                                    self.sync_after_session_change("Debug: Operator Logged Out");
                                }
                            }
                        }
                    }
                }
            }
            UiEvent::RfidScanned(card_id) => {
                self.rfid_count = self.rfid_count.saturating_add(1);
                self.session.login(&card_id, self.now_ms);
                self.sync_after_session_change("");
                if !matches!(self.session.state(), SessionState::Idle) {
                    let _ = self.input_buffer.push_str(&card_id);
                }
                self.dirty = true;

                self.log_fmt(format_args!("RFID Scanned: {}", card_id));
            }
            UiEvent::BarcodeScanned(code) => {
                self.barcode_count = self.barcode_count.saturating_add(1);
                self.dirty = true;

                match self.session.handle_barcode(&code, self.now_ms) {
                    Ok(()) => {
                        self.sync_after_session_change("");
                        self.log_fmt(format_args!("Barcode Scanned: {}", code));
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
                    self.log_fmt(format_args!("Net Status: {:?}", status));
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
                self.set_keyboard_visible(!self.keyboard_visible);
                self.push_event_log(if self.keyboard_visible {
                    "Keyboard: shown"
                } else {
                    "Keyboard: hidden"
                });
            }
            HeaderButton::Clear => {
                self.input_buffer.clear();
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
    use crate::session::tests::{login, logout, s32, s64, start, stop};
    use crate::session::{DUMMY_JOB_ID, DUMMY_OPERATOR_ID};

    const KB: Rect = Rect::new(Point::new(0, 300), 800, 180);

    fn down<const N: usize>(s: &mut UiState<N>, p: Point, kb: Option<Rect>, key: Option<Key>) {
        s.handle_event(UiEvent::TouchDown { scaled: p, raw: (0, 0) }, kb, key);
    }

    fn up<const N: usize>(s: &mut UiState<N>, p: Point, kb: Option<Rect>, key: Option<Key>) {
        s.handle_event(UiEvent::TouchUp { scaled: p, raw: (0, 0) }, kb, key);
    }

    fn moved<const N: usize>(s: &mut UiState<N>, p: Point, kb: Option<Rect>, key: Option<Key>) {
        s.handle_event(UiEvent::TouchMove { scaled: p, raw: (0, 0) }, kb, key);
    }

    fn tap<const N: usize>(state: &mut UiState<N>, p: Point) {
        down(state, p, None, None);
        up(state, p, None, None);
    }

    fn inside(r: Rect) -> Point {
        Point::new(
            r.top_left.x + (r.width / 2) as i32,
            r.top_left.y + (r.height / 2) as i32,
        )
    }

    fn drain_ui<const N: usize>(s: &mut UiState<N>) -> heapless::Vec<SessionEvent, 8> {
        let mut events = heapless::Vec::new();
        while let Some(ev) = s.pop_session_event() {
            let _ = events.push(ev);
        }
        events
    }

    #[test]
    fn keyboard_button_only_toggles_visibility() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_layer = KeyboardLayer::Symbols;
        let btn = inside(KEYBOARD_BUTTON);

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
        let dbg_btn = inside(DEBUG_BUTTON);

        assert_eq!(s.current_screen, Screen::Operator);
        tap(&mut s, dbg_btn);
        assert_eq!(s.current_screen, Screen::Debug);

        tap(&mut s, dbg_btn);
        assert_eq!(s.current_screen, Screen::Operator);
    }

    #[test]
    fn ui_state_session_workflow_and_rejections() {
        let mut s: UiState<64> = UiState::new();
        // 1. Barcode scan while Idle -> rejected
        let job1: String<64> = s64("JOB-101");
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), None, None);
        assert_eq!(s.barcode_count, 1);
        assert_eq!(s.input_buffer.as_str(), "");
        assert!(!s.keyboard_visible);
        assert_eq!(s.event_history[0].as_str(), "Barcode Rejected: Not Authenticated");
        assert_eq!(s.session_state(), &SessionState::Idle);
        assert_eq!(drain_ui(&mut s), []);

        // 2. Set now_ms to 500 and scan RFID -> Authenticated
        s.set_now_ms(500);
        let badge: String<32> = s32("BADGE-7");
        s.handle_event(UiEvent::RfidScanned(badge.clone()), None, None);
        assert_eq!(s.rfid_count, 1);
        assert_eq!(s.input_buffer.as_str(), "BADGE-7");
        assert!(!s.keyboard_visible);
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(drain_ui(&mut s), [login("BADGE-7", 500)]);

        // 3. Scan barcode while Authenticated -> Working (keyboard auto-shows, buffer cleared for notes)
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), None, None);
        assert_eq!(s.barcode_count, 2);
        assert_eq!(s.input_buffer.as_str(), "");
        assert!(s.keyboard_visible);
        assert_eq!(s.event_history[0].as_str(), "Barcode Scanned: JOB-101");
        assert_eq!(drain_ui(&mut s), [start("BADGE-7", "JOB-101", 500)]);

        // Type QA notes while working
        s.apply_key(Key::Char('O'));
        s.apply_key(Key::Char('K'));
        assert_eq!(s.input_buffer.as_str(), "OK");

        // 4. Scan different barcode while Working -> rejected (notes preserved)
        let job2: String<64> = s64("JOB-202");
        s.handle_event(UiEvent::BarcodeScanned(job2), None, None);
        assert_eq!(s.barcode_count, 3);
        assert_eq!(s.input_buffer.as_str(), "OK");
        assert!(s.keyboard_visible);
        assert_eq!(s.event_history[0].as_str(), "Barcode Rejected: Active Job Mismatch");
        assert_eq!(drain_ui(&mut s), []);

        // 5. Advance now_ms by 200 and scan matching barcode -> WorkStop (keyboard auto-hides, buffer cleared)
        s.set_now_ms(700);
        s.handle_event(UiEvent::BarcodeScanned(job1.clone()), None, None);
        assert!(!s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), "");
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(drain_ui(&mut s), [stop("BADGE-7", "JOB-101", 500, 700)]);
    }

    #[test]
    fn debug_screen_stop_job_and_logout_buttons() {
        let mut s: UiState<64> = UiState::new();
        let badge = s32("OP-9");
        let job = s64("JOB-900");

        s.handle_event(UiEvent::RfidScanned(badge.clone()), None, None);
        s.handle_event(UiEvent::BarcodeScanned(job), None, None);
        let _ = drain_ui(&mut s);
        assert!(s.keyboard_visible);

        // Switch to Debug screen and hide keyboard so debug buttons are accessible
        tap(&mut s, inside(DEBUG_BUTTON));
        assert_eq!(s.current_screen, Screen::Debug);
        tap(&mut s, inside(KEYBOARD_BUTTON));
        assert!(!s.keyboard_visible);

        s.set_now_ms(300);

        // Tap STOP JOB
        let stop_pt = inside(DEBUG_STOP_JOB_BUTTON);
        down(&mut s, stop_pt, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::StopJob));
        up(&mut s, stop_pt, None, None);
        assert_eq!(s.pressed_debug, None);
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: badge.clone()
            }
        );
        assert_eq!(drain_ui(&mut s), [stop("OP-9", "JOB-900", 0, 300)]);

        // Tap LOGOUT
        let logout_pt = inside(DEBUG_LOGOUT_BUTTON);
        tap(&mut s, logout_pt);
        assert_eq!(s.session_state(), &SessionState::Idle);
        assert_eq!(drain_ui(&mut s), [logout("OP-9", 300)]);
    }

    #[test]
    fn debug_screen_auth_user_and_start_job_buttons() {
        let mut s: UiState<64> = UiState::new();
        let dummy_op = s32(DUMMY_OPERATOR_ID);
        let dummy_job = s64(DUMMY_JOB_ID);

        // Switch to Debug screen
        tap(&mut s, inside(DEBUG_BUTTON));
        assert_eq!(s.current_screen, Screen::Debug);

        // 1. Tap AUTH USER from Idle -> Authenticated with DUMMY_OPERATOR_ID
        let auth_pt = inside(DEBUG_AUTH_USER_BUTTON);
        down(&mut s, auth_pt, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::AuthUser));
        up(&mut s, auth_pt, None, None);
        assert_eq!(s.pressed_debug, None);
        assert!(!s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), DUMMY_OPERATOR_ID);
        assert_eq!(s.event_history[0].as_str(), "Debug: Authenticated Dummy User");
        assert_eq!(
            s.session_state(),
            &SessionState::Authenticated {
                operator_id: dummy_op.clone()
            }
        );
        assert_eq!(drain_ui(&mut s), [login(DUMMY_OPERATOR_ID, 0)]);

        // 2. Tap START JOB -> Working with DUMMY_JOB_ID
        let start_pt = inside(DEBUG_START_JOB_BUTTON);
        down(&mut s, start_pt, None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::StartJob));
        up(&mut s, start_pt, None, None);
        assert_eq!(s.pressed_debug, None);
        assert!(s.keyboard_visible);
        assert_eq!(s.input_buffer.as_str(), "");
        assert_eq!(s.event_history[0].as_str(), "Debug: Started Dummy Job");
        assert_eq!(
            s.session_state(),
            &SessionState::Working {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_ms: 0,
            }
        );
        assert_eq!(drain_ui(&mut s), [start(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 0)]);

        // 3. Hide keyboard, tap AUTH USER while Working -> transitions back to Authenticated
        tap(&mut s, inside(KEYBOARD_BUTTON));
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
            drain_ui(&mut s),
            [stop(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 0, 0)]
        );

        // 4. Logout, then tap START JOB directly from Idle -> auto-authenticates and starts job
        let logout_pt = inside(DEBUG_LOGOUT_BUTTON);
        tap(&mut s, logout_pt);
        let _ = drain_ui(&mut s);
        assert_eq!(s.session_state(), &SessionState::Idle);

        tap(&mut s, start_pt);
        assert!(s.keyboard_visible);
        assert_eq!(
            s.session_state(),
            &SessionState::Working {
                operator_id: dummy_op.clone(),
                job_id: dummy_job.clone(),
                started_at_ms: 0,
            }
        );
        assert_eq!(
            drain_ui(&mut s),
            [
                login(DUMMY_OPERATOR_ID, 0),
                start(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 0),
            ]
        );
    }
    #[test]
    fn clear_header_button_resets_input_buffer_and_event_history() {
        let mut s: UiState<64> = UiState::new();
        let _ = s.input_buffer.push_str("ABC");
        for i in 1..=6 {
            let mut msg: String<64> = String::new();
            use core::fmt::Write;
            let _ = write!(msg, "Log message {}", i);
            s.push_event_log(&msg);
        }
        assert_eq!(s.event_history.iter().filter(|s| !s.is_empty()).count(), 6);
        assert_eq!(s.input_buffer.as_str(), "ABC");

        // Tap HeaderButton::Clear
        down(&mut s, inside(HeaderButton::Clear.rect()), None, None);
        assert!(s.input_buffer.is_empty());
        assert_eq!(s.event_history.iter().filter(|s| !s.is_empty()).count(), 1);
        assert_eq!(s.event_history[0].as_str(), "Cleared Buffer & Event Log");
        for slot in &s.event_history[1..6] {
            assert_eq!(slot.as_str(), "");
        }
    }

    #[test]
    fn now_ms_1hz_dirty_refresh_and_network_status_deduplication() {
        let mut s: UiState<64> = UiState::new();
        s.dirty = false;
        for ms in [100, 250, 500, 750, 999] {
            s.set_now_ms(ms);
            assert_eq!(s.now_ms(), ms);
            assert!(!s.dirty);
        }

        s.set_now_ms(1000);
        assert_eq!(s.now_ms(), 1000);
        assert!(s.dirty);

        s.handle_event(
            UiEvent::NetworkStatusChanged(NetworkStatus::Syncing(4)),
            None,
            None,
        );
        assert!(s.dirty);
        assert_eq!(s.event_history[0].as_str(), "Net Status: Syncing(4)");
        s.dirty = false;
        s.handle_event(
            UiEvent::NetworkStatusChanged(NetworkStatus::Syncing(4)),
            None,
            None,
        );
        assert!(!s.dirty);

        s.handle_event(
            UiEvent::NetworkStatusChanged(NetworkStatus::Online),
            None,
            None,
        );
        assert!(s.dirty);
    }
    #[test]
    fn session_duration_ms_regression_wall_clock() {
        let mut s: UiState<64> = UiState::new();
        s.set_now_ms(1_000);
        let badge = s32("OP_1");
        s.handle_event(UiEvent::RfidScanned(badge), None, None);
        let job = s64("JOB_1");
        s.handle_event(UiEvent::BarcodeScanned(job.clone()), None, None);

        // Send several TouchDown/TouchUp events with no time change
        let pt = Point::new(100, 100);
        for _ in 0..5 {
            down(&mut s, pt, None, None);
            up(&mut s, pt, None, None);
        }

        s.set_now_ms(4_500);
        s.handle_event(UiEvent::BarcodeScanned(job), None, None);

        assert_eq!(
            drain_ui(&mut s),
            [
                login("OP_1", 1_000),
                start("OP_1", "JOB_1", 1_000),
                stop("OP_1", "JOB_1", 1_000, 4_500),
            ]
        );
    }


    #[test]
    fn keyboard_touch_move_switches_active_key_and_drag_out_cancels_keypress() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_visible = true;
        let kb_bounds = Some(KB);

        down(&mut s, Point::new(40, 320), kb_bounds, Some(Key::Char('Q')));
        assert_eq!(s.active_touch_key, Some(Key::Char('Q')));

        moved(&mut s, Point::new(120, 320), kb_bounds, Some(Key::Char('W')));
        assert_eq!(s.active_touch_key, Some(Key::Char('W')));

        moved(&mut s, Point::new(120, 200), kb_bounds, None);
        assert_eq!(s.active_touch_key, None);

        up(&mut s, Point::new(120, 200), kb_bounds, None);
        assert!(s.input_buffer.is_empty());
        assert_eq!(s.key_count, 0);
    }

    #[test]
    fn key_release_marks_state_dirty_even_after_frame_was_drawn() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_visible = true;
        let kb_bounds = Some(KB);
        let q = Point::new(40, 320);

        down(&mut s, q, kb_bounds, Some(Key::Char('Q')));
        // Renderer consumed the TouchDown frame.
        s.dirty = false;

        up(&mut s, q, kb_bounds, Some(Key::Char('Q')));
        assert_eq!(s.input_buffer.as_str(), "Q");
        assert!(s.dirty, "typed key must trigger a repaint on release");
    }

    #[test]
    fn scanner_event_hiding_keyboard_clears_active_touch_key() {
        let mut s: UiState<64> = UiState::new();
        let kb_bounds = Some(KB);

        // Enter Working state
        let op = s32("OP_1");
        s.handle_event(UiEvent::RfidScanned(op), kb_bounds, None);
        let job = s64("JOB_1");
        s.handle_event(UiEvent::BarcodeScanned(job.clone()), kb_bounds, None);
        assert!(matches!(s.session_state(), SessionState::Working { .. }));
        assert!(s.keyboard_visible);

        // TouchDown on 'Q'
        down(&mut s, Point::new(40, 320), kb_bounds, Some(Key::Char('Q')));
        assert_eq!(s.active_touch_key, Some(Key::Char('Q')));

        // Stop job via matching barcode -> hides keyboard
        s.handle_event(UiEvent::BarcodeScanned(job), kb_bounds, None);
        assert!(!s.keyboard_visible);
        assert_eq!(
            s.active_touch_key, None,
            "stopping job and hiding keyboard must clear stale active_touch_key"
        );
    }

    #[test]
    fn debug_button_requires_matching_touch_down_and_clears_on_drag_off() {
        let mut s: UiState<64> = UiState::new();
        // 1. On Screen::Operator, TouchDown on HeaderButton::Debug switches screen
        assert_eq!(s.current_screen, Screen::Operator);
        down(&mut s, inside(DEBUG_BUTTON), None, None);
        assert_eq!(s.current_screen, Screen::Debug);

        up(&mut s, inside(DEBUG_AUTH_USER_BUTTON), None, None);
        assert_eq!(
            s.session_state(),
            &SessionState::Idle,
            "must not trigger AuthUser without a matching TouchDown on AuthUser"
        );

        // 2. On Screen::Debug in SessionState::Idle:
        down(&mut s, inside(DEBUG_AUTH_USER_BUTTON), None, None);
        assert_eq!(s.pressed_debug, Some(DebugButton::AuthUser));

        moved(&mut s, Point::new(50, 100), None, None);
        assert_eq!(
            s.pressed_debug, None,
            "dragging touch off debug button must clear pressed_debug"
        );

        up(&mut s, inside(DEBUG_START_JOB_BUTTON), None, None);
        assert_eq!(
            s.session_state(),
            &SessionState::Idle,
            "dragging touch across debug buttons must not trigger destination button"
        );
    }

    #[test]
    fn debug_buttons_noop_when_rejected_or_covered_by_keyboard() {
        let mut s: UiState<64> = UiState::new();
        s.current_screen = Screen::Debug;
        let _ = s.input_buffer.push_str("KEEP");

        tap(&mut s, inside(DEBUG_STOP_JOB_BUTTON));
        assert_eq!(s.input_buffer.as_str(), "KEEP");
        assert_eq!(s.session_state(), &SessionState::Idle);

        tap(&mut s, inside(DEBUG_LOGOUT_BUTTON));
        assert_eq!(s.input_buffer.as_str(), "KEEP");
        assert_eq!(s.session_state(), &SessionState::Idle);

        // Covering keyboard
        s.keyboard_visible = true;
        let kb_bounds = Some(Rect::new(Point::new(0, 180), 800, 300));
        let auth_pt = inside(DEBUG_AUTH_USER_BUTTON);
        down(&mut s, auth_pt, kb_bounds, None);
        up(&mut s, auth_pt, kb_bounds, None);
        assert_eq!(
            s.session_state(),
            &SessionState::Idle,
            "DebugButton::AuthUser must not fire when covered by keyboard"
        );
    }

    #[test]
    fn overlong_event_log_and_barcode_messages_truncate_to_64_bytes_instead_of_dropping() {
        let mut s: UiState<64> = UiState::new();
        // Authenticate operator
        let op = s32("OP_99");
        s.handle_event(UiEvent::RfidScanned(op), None, None);
        assert!(matches!(s.session_state(), SessionState::Authenticated { .. }));

        // 60-char barcode
        let barcode_str = "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB";
        assert_eq!(barcode_str.len(), 60);
        let barcode_60: String<64> = String::try_from(barcode_str).unwrap();

        s.handle_event(UiEvent::BarcodeScanned(barcode_60), None, None);

        assert!(
            !s.event_history[0].is_empty(),
            "overlong barcode log message was completely dropped instead of truncated"
        );
        assert!(
            s.event_history[0].as_str().starts_with("Barcode Scanned: BBB"),
            "expected log message to start with 'Barcode Scanned: BBB', got: {:?}",
            s.event_history[0].as_str()
        );
    }

    #[test]
    fn touch_up_with_stale_keyboard_bounds_after_hide_does_not_type_key() {
        let mut s: UiState<64> = UiState::new();
        s.handle_event(
            UiEvent::RfidScanned(s32("OP_1")),
            None,
            None,
        );
        s.handle_event(
            UiEvent::BarcodeScanned(s64("JOB_1")),
            None,
            None,
        );
        assert!(s.keyboard_visible);

        let kb = KB;
        s.handle_event(
            UiEvent::BarcodeScanned(s64("JOB_1")),
            Some(kb),
            None,
        );
        assert!(!s.keyboard_visible);

        up(
            &mut s,
            Point::new(40, 320),
            Some(kb),
            Some(Key::Char('A')),
        );

        assert!(s.input_buffer.is_empty());
        assert_eq!(s.key_count, 0);
    }

    #[test]
    fn test_truncating_fmt_write() {
        use core::fmt::Write;
        let mut buf: heapless::String<10> = heapless::String::new();
        let res = write!(Truncating(&mut buf), "hello world");
        assert!(res.is_err());
        assert_eq!(buf.as_str(), "hello worl");
    }

    #[test]
    fn event_history_push_rotates_and_retains_latest_entries() {
        let mut s: UiState<64> = UiState::new();
        assert_eq!(s.event_history.iter().filter(|s| !s.is_empty()).count(), 1);

        for msg in [
            "event 1", "event 2", "event 3", "event 4",
            "event 5", "event 6", "event 7", "event 8",
        ] {
            s.push_event_log(msg);
        }

        assert_eq!(s.event_history.iter().filter(|s| !s.is_empty()).count(), 6);
        assert_eq!(s.event_history[0].as_str(), "event 8");
        assert_eq!(s.event_history[1].as_str(), "event 7");
        assert_eq!(s.event_history[2].as_str(), "event 6");
        assert_eq!(s.event_history[3].as_str(), "event 5");
        assert_eq!(s.event_history[4].as_str(), "event 4");
        assert_eq!(s.event_history[5].as_str(), "event 3");
    }

    #[test]
    fn apply_key_editing_keys() {
        let mut s = UiState::<256>::new();
        s.apply_key(Key::Char('A'));
        s.apply_key(Key::Char('B'));
        s.apply_key(Key::Backspace);
        assert_eq!(s.input_buffer.as_str(), "A");

        s.apply_key(Key::Backspace);
        s.apply_key(Key::Backspace);
        assert!(s.input_buffer.is_empty());

        s.apply_key(Key::Space);
        assert_eq!(s.input_buffer.as_str(), " ");

        s.apply_key(Key::Enter);
        assert_eq!(s.input_buffer.as_str(), " ");
        assert_eq!(s.event_history[0].as_str(), "Submitted Buffer via ENTER");

        s.apply_key(Key::Special(0));
        assert_eq!(s.input_buffer.as_str(), " ");
        assert_eq!(s.keyboard_layer, KeyboardLayer::Alpha);

        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Symbols);

        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Alpha);
    }
}
