use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use trillby_core::{
    Key, Point as CorePoint, UiEvent, UiState,
};
use trillby_ui::{eg_rect_to_core, KeyboardGrid, LayoutZones, UiRenderer};

#[test]
fn test_ui_full_interaction_lifecycle() {
    // 1. Initialize 800x480 screen bounds and target pixel buffer
    let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
    let core_screen_bounds = eg_rect_to_core(screen_bounds);
    let mut pixels = [Rgb565::new(0, 0, 0); 800 * 480];

    let mut state: UiState<256> = UiState::new();
    let renderer = UiRenderer::new(screen_bounds);

    // Initial render pass
    {
        let mut framebuffer = FrameBuf::new(&mut pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }

    // 2. Dispatch RFID Card scan event
    let card_id = heapless::String::try_from("OP_CARD_9921").unwrap();
    state.handle_event(UiEvent::RfidScanned(card_id), core_screen_bounds, None, None);

    assert_eq!(state.input_buffer.as_str(), "OP_CARD_9921");
    assert_eq!(state.rfid_count, 1);
    assert!(state.dirty);

    // 3. Resolve virtual keyboard key touch (Q key at x=40, y=320)
    let touch_point = Point::new(40, 320);
    let core_touch_point = CorePoint::new(40, 320);

    let zones = LayoutZones::compute(screen_bounds, state.keyboard_mode);
    let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

    let key_hit = zones.keyboard_area.and_then(|kb| {
        KeyboardGrid::resolve_key(kb, touch_point, state.keyboard_mode)
    });
    assert_eq!(key_hit, Some(Key::Char('Q')));

    // Dispatch TouchDown
    state.handle_event(
        UiEvent::TouchDown {
            scaled: core_touch_point,
            raw: (1600, 21000),
        },
        core_screen_bounds,
        core_kb_bounds,
        key_hit,
    );

    assert_eq!(state.active_touch_key, Some(Key::Char('Q')));
    assert_eq!(state.touch_count, 1);

    // Dispatch TouchUp
    state.handle_event(
        UiEvent::TouchUp {
            scaled: core_touch_point,
            raw: (1600, 21000),
        },
        core_screen_bounds,
        core_kb_bounds,
        None,
    );

    assert_eq!(state.input_buffer.as_str(), "OP_CARD_9921Q");
    assert_eq!(state.key_count, 1);
    assert_eq!(state.last_key_pressed, Some(Key::Char('Q')));
    assert!(state.dirty);

    // 4. Repaint dirty framebuffer
    if state.dirty {
        let mut framebuffer = FrameBuf::new(&mut pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
        state.dirty = false;
    }

    assert!(!state.dirty);
}
