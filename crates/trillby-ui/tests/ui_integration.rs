use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::Rgb565,
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use trillby_core::{
    HeaderButton, Key, Point as CorePoint, Screen, SessionState, UiEvent, UiState,
};
use trillby_ui::{eg_rect_to_core, DarkFloorTheme, KeyboardGrid, LayoutZones, Theme, UiRenderer};

#[test]
fn test_ui_full_interaction_lifecycle() {
    // 1. Initialize 800x480 screen bounds and target pixel buffer (Idle state)
    let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
    let core_screen_bounds = eg_rect_to_core(screen_bounds);
    let mut pixels: std::boxed::Box<[Rgb565; 800 * 480]> =
        std::vec![Rgb565::new(0, 0, 0); 800 * 480].into_boxed_slice().try_into().unwrap();
    let mut prev_pixels: std::boxed::Box<[Rgb565; 800 * 480]> =
        std::vec![Rgb565::new(0, 0, 0); 800 * 480].into_boxed_slice().try_into().unwrap();
    let theme = DarkFloorTheme;

    let mut state: UiState<256> = UiState::new();
    let renderer = UiRenderer::new(screen_bounds);

    assert_eq!(state.current_screen, Screen::Operator);
    assert_eq!(state.session.state(), &SessionState::Idle);
    assert!(!state.keyboard_visible);

    // Render Idle state
    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_eq!(pixels[350 * 800 + 530], theme.background());
    assert_eq!(pixels[475 * 800 + 400], theme.background());
    prev_pixels.copy_from_slice(&pixels[..]);
    // 2. Dispatch RFID Card scan event -> Authenticated, auto-hidden keyboard
    let card_id = heapless::String::try_from("OP_CARD_9921").unwrap();
    state.handle_event(UiEvent::RfidScanned(card_id), core_screen_bounds, None, None);

    assert!(matches!(
        state.session.state(),
        SessionState::Authenticated { operator_id } if operator_id.as_str() == "OP_CARD_9921"
    ));
    assert!(!state.keyboard_visible);
    assert_eq!(state.rfid_count, 1);
    assert!(state.dirty);

    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_ne!(pixels, prev_pixels);
    assert_eq!(pixels[350 * 800 + 530], theme.background());
    prev_pixels.copy_from_slice(&pixels[..]);
    // 3. Dispatch Barcode scan event -> Working, auto-shown keyboard
    let job_id = heapless::String::try_from("JOB_404").unwrap();
    state.handle_event(
        UiEvent::BarcodeScanned(job_id.clone()),
        core_screen_bounds,
        None,
        None,
    );

    assert!(matches!(
        state.session.state(),
        SessionState::Working { operator_id, job_id, .. }
            if operator_id.as_str() == "OP_CARD_9921" && job_id.as_str() == "JOB_404"
    ));
    assert!(state.keyboard_visible);
    assert_eq!(state.barcode_count, 1);
    assert_eq!(state.input_buffer.as_str(), "");

    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_ne!(pixels, prev_pixels);
    assert_eq!(pixels[350 * 800 + 530], theme.surface());
    assert_eq!(pixels[302 * 800 + 20], theme.border());
    prev_pixels.copy_from_slice(&pixels[..]);
    // 4. Touch 'Q' key on virtual keyboard (x=40, y=320) -> input_buffer == "Q"
    let touch_point = Point::new(40, 320);
    let core_touch_point = CorePoint::new(40, 320);

    let zones = LayoutZones::compute(screen_bounds, state.keyboard_visible);
    let core_kb_bounds = zones.keyboard_area.map(eg_rect_to_core);

    let key_hit = zones.keyboard_area.and_then(|kb| {
        KeyboardGrid::resolve_key(kb, touch_point, state.keyboard_layer)
    });
    assert_eq!(key_hit, Some(Key::Char('Q')));

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

    // Render TouchDown state: 'Q' key highlighted
    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_ne!(pixels, prev_pixels);
    assert_eq!(pixels[302 * 800 + 20], theme.primary());
    prev_pixels.copy_from_slice(&pixels[..]);

    state.handle_event(
        UiEvent::TouchUp {
            scaled: core_touch_point,
            raw: (1600, 21000),
        },
        core_screen_bounds,
        core_kb_bounds,
        key_hit,
    );

    assert_eq!(state.input_buffer.as_str(), "Q");
    assert_eq!(state.key_count, 1);
    assert_eq!(state.last_key_pressed, Some(Key::Char('Q')));
    assert!(state.dirty);

    // Render TouchUp state: 'Q' key unhighlighted
    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_ne!(pixels, prev_pixels);
    assert_eq!(pixels[302 * 800 + 20], theme.border());
    prev_pixels.copy_from_slice(&pixels[..]);
    // 5. Matching BarcodeScanned -> Authenticated, auto-hidden keyboard
    state.handle_event(
        UiEvent::BarcodeScanned(job_id),
        core_screen_bounds,
        None,
        None,
    );
    assert!(matches!(
        state.session.state(),
        SessionState::Authenticated { operator_id } if operator_id.as_str() == "OP_CARD_9921"
    ));
    assert!(!state.keyboard_visible);
    assert_eq!(state.barcode_count, 2);

    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
    }
    assert_ne!(pixels, prev_pixels);
    assert_eq!(pixels[350 * 800 + 530], theme.background());
    prev_pixels.copy_from_slice(&pixels[..]);
    // 6. Tap HeaderButton::Debug -> Screen::Debug and render cleanly
    let debug_rect = HeaderButton::Debug.rect();
    let debug_point = CorePoint::new(debug_rect.top_left.x + 10, debug_rect.top_left.y + 10);
    state.handle_event(
        UiEvent::TouchDown {
            scaled: debug_point,
            raw: (20000, 2000),
        },
        core_screen_bounds,
        None,
        None,
    );
    state.handle_event(
        UiEvent::TouchUp {
            scaled: debug_point,
            raw: (20000, 2000),
        },
        core_screen_bounds,
        None,
        None,
    );
    assert_eq!(state.current_screen, Screen::Debug);
    assert!(state.dirty);

    {
        let mut framebuffer = FrameBuf::new(&mut *pixels, 800, 480);
        assert!(renderer.render(&mut framebuffer, &state).is_ok());
        state.dirty = false;
    }
    assert_ne!(pixels, prev_pixels);
    assert!(!state.dirty);
}
