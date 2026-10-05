use crate::event::UiEvent;
use crate::geometry::{Point, Rect};
use crate::header::HeaderButton;
use crate::keyboard_types::{Key, KeyboardLayer};
use heapless::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Debug,
}

pub struct UiState<const N: usize> {
    pub current_screen: Screen,
    /// Toggled only by the header KEYBOARD button.
    pub keyboard_visible: bool,
    /// Toggled only by `Key::LayerToggle`; survives hide/show (it's one byte
    /// inline in this struct, no allocation involved).
    pub keyboard_layer: KeyboardLayer,
    /// Header button currently held down (for pressed-state rendering).
    pub pressed_header: Option<HeaderButton>,
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
    pub active_touch_key: Option<Key>,
    pub last_key_pressed: Option<Key>,
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
            current_screen: Screen::Debug,
            keyboard_visible: true,
            keyboard_layer: KeyboardLayer::Alpha,
            pressed_header: None,
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
            active_touch_key: None,
            last_key_pressed: None,
        }
    }
}

impl<const N: usize> UiState<N> {
    pub fn new() -> Self {
        Self::default()
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
                // Trigger 1Hz clock repaint
                if self.tick_count % 20 == 0 {
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

                if self.keyboard_visible {
                    if let Some(bounds) = kb_bounds {
                        if bounds.contains(scaled) {
                            self.active_touch_key = resolved_key;
                        }
                    }
                }
            }
            UiEvent::TouchMove { scaled, raw } => {
                self.last_touch_raw = raw;
                self.last_touch_scaled = Some(scaled);
                self.dirty = true;
            }
            UiEvent::TouchUp { scaled, raw } => {
                self.last_touch_raw = raw;
                self.last_touch_scaled = Some(scaled);
                self.pressed_header = None;
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "TouchUp s:({}, {})", scaled.x, scaled.y);
                self.push_event_log(&log_buf);

                if let Some(key) = self.active_touch_key.take() {
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
            }
            UiEvent::RfidScanned(card_id) => {
                self.rfid_count = self.rfid_count.saturating_add(1);
                self.input_buffer.clear();
                let _ = self.input_buffer.push_str(&card_id);
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "RFID Scanned: {}", card_id);
                self.push_event_log(&log_buf);
            }
            UiEvent::BarcodeScanned(code) => {
                self.barcode_count = self.barcode_count.saturating_add(1);
                let _ = self.input_buffer.push_str(&code);
                self.dirty = true;

                use core::fmt::Write;
                let mut log_buf: String<64> = String::new();
                let _ = write!(log_buf, "Barcode Scanned: {}", code);
                self.push_event_log(&log_buf);
            }
        }
    }

    fn press_header(&mut self, button: HeaderButton) {
        match button {
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
    use crate::header::KEYBOARD_BUTTON;

    fn tap_header(state: &mut UiState<64>, p: Point) {
        let screen = Rect::new(Point::zero(), 800, 480);
        state.handle_event(UiEvent::TouchDown { scaled: p, raw: (0, 0) }, screen, None, None);
        state.handle_event(UiEvent::TouchUp { scaled: p, raw: (0, 0) }, screen, None, None);
    }

    #[test]
    fn keyboard_button_only_toggles_visibility() {
        let mut s: UiState<64> = UiState::new();
        s.keyboard_layer = KeyboardLayer::Symbols;
        let btn = Point::new(KEYBOARD_BUTTON.top_left.x + 5, 10);

        assert!(s.keyboard_visible);
        tap_header(&mut s, btn);
        assert!(!s.keyboard_visible);
        tap_header(&mut s, btn);
        assert!(s.keyboard_visible);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Symbols);
        assert_eq!(s.pressed_header, None);
    }

    #[test]
    fn layer_toggle_never_hides_keyboard() {
        let mut s: UiState<64> = UiState::new();
        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Symbols);
        s.apply_key(Key::LayerToggle);
        assert_eq!(s.keyboard_layer, KeyboardLayer::Alpha);
        assert!(s.keyboard_visible);
    }
}
