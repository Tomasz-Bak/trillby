#[path = "../tests/support/mod.rs"]
mod support;

use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::{Rgb565, RgbColor},
    primitives::Rectangle,
};
use std::fs::File;
use std::io::{BufWriter, Write};
use trillby_core::{
    KeyboardLayer, Point as CorePoint, UiEvent, UiState,
};
use trillby_ui::{UiRenderer, SCREEN_HEIGHT, SCREEN_WIDTH};

/// Dump RGB565 framebuffer slice to a Netpbm PPM (P6 binary) image file with 8-bit color scaling.
fn save_ppm_image(path: &str, pixels: &[Rgb565], width: usize, height: usize) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    writeln!(writer, "P6")?;
    writeln!(writer, "{} {}", width, height)?;
    writeln!(writer, "255")?;

    // Scale 5-bit (0..31) and 6-bit (0..63) channels to 8-bit (0..255)
    for pixel in pixels.iter() {
        let r8 = ((pixel.r() as u32 * 255) / 31) as u8;
        let g8 = ((pixel.g() as u32 * 255) / 63) as u8;
        let b8 = ((pixel.b() as u32 * 255) / 31) as u8;
        writer.write_all(&[r8, g8, b8])?;
    }

    writer.flush()?;
    Ok(())
}

fn dump_ui_state(visible: bool, layer: KeyboardLayer, filename_base: &str) -> std::io::Result<()> {
    let width = SCREEN_WIDTH as usize;
    let height = SCREEN_HEIGHT as usize;

    let screen_bounds = Rectangle::new(Point::zero(), Size::new(SCREEN_WIDTH, SCREEN_HEIGHT));

    let mut state: UiState<256> = UiState::new();
    let renderer = UiRenderer::new(screen_bounds);

    // Populate static demonstration telemetry data
    support::start_job(&mut state, "OPERATOR_CARD_9021", "ITEM-UNIT-448102");

    state.handle_event(
        UiEvent::TouchDown {
            scaled: CorePoint::new(120, 340),
            raw: (4800, 22000),
        },
        None,
        None,
    );

    state.keyboard_visible = visible;
    state.keyboard_layer = layer;
    // Render UI frame onto target FrameBuf
    let canvas = support::render_to_canvas(&renderer, &state);

    let ppm_path = format!("{}.ppm", filename_base);
    save_ppm_image(&ppm_path, &canvas.pixels, width, height)?;
    println!("Exported Layout Dump -> '{}' (visible: {}, layer: {:?}, {}x{} PPM)", ppm_path, visible, layer, width, height);

    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("====================================================");
    println!(" Trillby UI Engine — Multi-State Responsive Image Dumper");
    println!("====================================================");

    // State 1: Fullscreen Layout (Keyboard Hidden)
    dump_ui_state(false, KeyboardLayer::Alpha, "layout_fullscreen")?;

    // State 2: Alphabetic QWERTY layer
    dump_ui_state(true, KeyboardLayer::Alpha, "layout_keyboard_alpha")?;

    // State 3: Numeric & Symbols layer
    dump_ui_state(true, KeyboardLayer::Symbols, "layout_keyboard_numeric")?;

    println!("====================================================");
    Ok(())
}
