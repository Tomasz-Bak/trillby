use super::keyboard::{Key, KeyboardGrid, KeyboardMode};
use embedded_graphics::geometry::Point;
use embedded_graphics::primitives::Rectangle;
use heapless::String;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Screen {
    #[default]
    Debug,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    TouchDown { scaled: Point, raw: (i32, i32) },
    TouchUp { scaled: Point, raw: (i32, i32) },
    TouchMove { scaled: Point, raw: (i32, i32) },
    RfidScanned(String<32>),
    BarcodeScanned(String<64>),
    Tick,
}

pub struct UiState<const N: usize> {
    pub current_screen: Screen,
    pub keyboard_mode: KeyboardMode,
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
            String::new(), String::new(), String::new(),
            String::new(), String::new(), String::new(),
        ];
        let _ = init_history[0].push_str("System initialized (Bare Framework Scaffolding)");

        Self {
            current_screen: Screen::Debug,
            keyboard_mode: KeyboardMode::Standard,
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
    pub fn handle_event(&mut self, event: UiEvent, _screen_bounds: Rectangle, kb_bounds: Option<Rectangle>) {
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

                // Top bar control buttons (y <= 36)
                if scaled.y <= 36 {
                    if scaled.x >= 500 && scaled.x <= 640 {
                        self.keyboard_mode = match self.keyboard_mode {
                            KeyboardMode::Standard => KeyboardMode::Extended,
                            KeyboardMode::Extended => KeyboardMode::Hidden,
                            KeyboardMode::Hidden => KeyboardMode::Standard,
                        };
                        let mut kb_msg: String<64> = String::new();
                        let _ = write!(kb_msg, "Keyboard Mode: {:?}", self.keyboard_mode);
                        self.push_event_log(&kb_msg);
                        return;
                    } else if scaled.x >= 650 && scaled.x <= 780 {
                        self.input_buffer.clear();
                        self.history_count = 0;
                        for slot in self.event_history.iter_mut() {
                            slot.clear();
                        }
                        self.push_event_log("Cleared Buffer & Event Log");
                        return;
                    }
                }

                // Check keyboard hit
                if self.keyboard_mode != KeyboardMode::Hidden {
                    if let Some(bounds) = kb_bounds {
                        if bounds.contains(scaled) {
                            self.active_touch_key = KeyboardGrid::resolve_key(bounds, scaled, self.keyboard_mode);
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
            Key::ModeSwitch => {
                self.keyboard_mode = match self.keyboard_mode {
                    KeyboardMode::Standard => KeyboardMode::Extended,
                    KeyboardMode::Extended => KeyboardMode::Standard,
                    KeyboardMode::Hidden => KeyboardMode::Standard,
                };
            }
            Key::Enter => {
                self.push_event_log("Submitted Buffer via ENTER");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use embedded_graphics::geometry::Size;

    #[test]
    fn test_scaffolding_touch_and_key() {
        let mut state: UiState<256> = UiState::new();
        let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
        let kb_bounds = Rectangle::new(Point::new(0, 300), Size::new(800, 180));

        // TouchDown on Q key (10, 310)
        state.handle_event(
            UiEvent::TouchDown {
                scaled: Point::new(10, 310),
                raw: (400, 20000),
            },
            screen_bounds,
            Some(kb_bounds),
        );
        assert_eq!(state.active_touch_key, Some(Key::Char('Q')));
        assert_eq!(state.touch_count, 1);

        // TouchUp on Q key
        state.handle_event(
            UiEvent::TouchUp {
                scaled: Point::new(10, 310),
                raw: (400, 20000),
            },
            screen_bounds,
            Some(kb_bounds),
        );
        assert_eq!(state.input_buffer.as_str(), "Q");
        assert_eq!(state.key_count, 1);
        assert_eq!(state.last_key_pressed, Some(Key::Char('Q')));
    }

    #[test]
    fn test_barcode_and_rfid_in_scaffolding() {
        let mut state: UiState<256> = UiState::new();
        let bounds = Rectangle::new(Point::zero(), Size::new(800, 480));

        let rfid: String<32> = String::try_from("OP_9901").unwrap();
        state.handle_event(UiEvent::RfidScanned(rfid), bounds, None);
        assert_eq!(state.input_buffer.as_str(), "OP_9901");
        assert_eq!(state.rfid_count, 1);

        let barcode: String<64> = String::try_from("ITEM-12345").unwrap();
        state.handle_event(UiEvent::BarcodeScanned(barcode), bounds, None);
        assert_eq!(state.input_buffer.as_str(), "OP_9901ITEM-12345");
        assert_eq!(state.barcode_count, 1);
    }
}

