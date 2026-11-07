mod support;

use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::{Rgb565, RgbColor},
    primitives::Rectangle,
};
use trillby_core::{
    HeaderButton, Key, Point as CorePoint, Screen, SessionState, UiEvent, UiState,
};
use trillby_ui::{
    eg_rect_to_core, DarkFloorTheme, KeyboardGrid, LayoutZones, Theme, UiRenderer,
    SCREEN_PIXELS,
};

fn render_changed(
    renderer: &UiRenderer,
    state: &UiState<256>,
    canvas: &mut support::TestCanvas,
    prev: &mut Vec<Rgb565>,
) {
    renderer.render(canvas, state).expect("render succeeds");
    assert_ne!(canvas.pixels, *prev, "render did not produce visual change");
    prev.copy_from_slice(&canvas.pixels);
}

#[test]
fn test_ui_full_interaction_lifecycle() {
    // 1. Initialize 800x480 screen bounds and target pixel buffer (Idle state)
    let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
    let mut canvas = support::TestCanvas::new(false);
    let mut prev_pixels = vec![Rgb565::BLACK; SCREEN_PIXELS];
    let theme = DarkFloorTheme;

    let mut state: UiState<256> = UiState::new();
    let renderer = UiRenderer::new(screen_bounds);

    assert_eq!(state.current_screen, Screen::Operator);
    assert_eq!(state.session_state(), &SessionState::Idle);
    assert!(!state.keyboard_visible);

    // Render Idle state
    renderer.render(&mut canvas, &state).unwrap();
    prev_pixels.copy_from_slice(&canvas.pixels);

    let key_cell = support::first_alpha_key_cell();
    let key_border_probe = key_cell.top_left + Point::new(20, 2);

    assert_eq!(
        canvas.px(support::CARD_GAP_PROBE.x, support::CARD_GAP_PROBE.y),
        theme.background()
    );
    assert_eq!(canvas.px(400, 475), theme.background());
    // 2. Dispatch RFID Card scan event -> Authenticated, auto-hidden keyboard
    support::login(&mut state, "OP_CARD_9921");
    assert!(matches!(
        state.session_state(),
        SessionState::Authenticated { operator_id } if operator_id.as_str() == "OP_CARD_9921"
    ));
    assert!(!state.keyboard_visible);
    assert_eq!(state.rfid_count, 1);
    assert!(state.dirty);

    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    assert_eq!(
        canvas.px(support::CARD_GAP_PROBE.x, support::CARD_GAP_PROBE.y),
        theme.background()
    );
    // 3. Dispatch Barcode scan event -> Working, auto-shown keyboard
    let job_id = heapless::String::try_from("JOB_404").unwrap();
    state.handle_event(
        UiEvent::BarcodeScanned(job_id.clone()),
        None,
        None,
    );

    assert!(matches!(
        state.session_state(),
        SessionState::Working { operator_id, job_id, .. }
            if operator_id.as_str() == "OP_CARD_9921" && job_id.as_str() == "JOB_404"
    ));
    assert!(state.keyboard_visible);
    assert_eq!(state.barcode_count, 1);
    assert_eq!(state.input_buffer.as_str(), "");

    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    assert_eq!(
        canvas.px(support::CARD_GAP_PROBE.x, support::CARD_GAP_PROBE.y),
        theme.surface()
    );
    assert_eq!(
        canvas.px(key_border_probe.x, key_border_probe.y),
        theme.border()
    );
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
        core_kb_bounds,
        key_hit,
    );

    assert_eq!(state.active_touch_key, Some(Key::Char('Q')));
    assert_eq!(state.touch_count, 1);

    // Render TouchDown state: 'Q' key highlighted
    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    assert_eq!(
        canvas.px(key_border_probe.x, key_border_probe.y),
        theme.primary()
    );

    state.handle_event(
        UiEvent::TouchUp {
            scaled: core_touch_point,
            raw: (1600, 21000),
        },
        core_kb_bounds,
        key_hit,
    );

    assert_eq!(state.input_buffer.as_str(), "Q");
    assert_eq!(state.key_count, 1);
    assert_eq!(state.input_buffer.as_str(), "Q");
    assert!(state.dirty);

    // Render TouchUp state: 'Q' key unhighlighted
    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    assert_eq!(
        canvas.px(key_border_probe.x, key_border_probe.y),
        theme.border()
    );
    // 5. Matching BarcodeScanned -> Authenticated, auto-hidden keyboard
    state.handle_event(
        UiEvent::BarcodeScanned(job_id),
        None,
        None,
    );
    assert!(matches!(
        state.session_state(),
        SessionState::Authenticated { operator_id } if operator_id.as_str() == "OP_CARD_9921"
    ));
    assert!(!state.keyboard_visible);
    assert_eq!(state.barcode_count, 2);

    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    assert_eq!(
        canvas.px(support::CARD_GAP_PROBE.x, support::CARD_GAP_PROBE.y),
        theme.background()
    );
    // 6. Tap HeaderButton::Debug -> Screen::Debug and render cleanly
    let debug_rect = HeaderButton::Debug.rect();
    let debug_point = CorePoint::new(debug_rect.top_left.x + 10, debug_rect.top_left.y + 10);
    state.handle_event(
        UiEvent::TouchDown {
            scaled: debug_point,
            raw: (20000, 2000),
        },
        None,
        None,
    );
    state.handle_event(
        UiEvent::TouchUp {
            scaled: debug_point,
            raw: (20000, 2000),
        },
        None,
        None,
    );
    assert_eq!(state.current_screen, Screen::Debug);
    assert!(state.dirty);

    render_changed(&renderer, &state, &mut canvas, &mut prev_pixels);
    state.dirty = false;
    assert!(!state.dirty);
}
