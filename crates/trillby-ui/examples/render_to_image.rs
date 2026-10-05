use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::{Rgb565, RgbColor},
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use std::fs::File;
use std::io::{BufWriter, Write};
use trillby_core::{
    KeyboardLayer, Point as CorePoint, UiEvent, UiState,
};
use trillby_ui::{eg_rect_to_core, UiRenderer};

/// Dump RGB565 framebuffer slice to a Netpbm PPM (P6 binary) image file with 8-bit color scaling.
fn save_ppm_image(path: &str, pixels: &[Rgb565; 800 * 480], width: usize, height: usize) -> std::io::Result<()> {
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
    let width = 800;
    let height = 480;

    let screen_bounds = Rectangle::new(Point::zero(), Size::new(width as u32, height as u32));
    let core_screen_bounds = eg_rect_to_core(screen_bounds);
    let mut pixels = [Rgb565::new(0, 0, 0); 800 * 480];

    let mut state: UiState<256> = UiState::new();
    state.keyboard_visible = visible;
    state.keyboard_layer = layer;
    let renderer = UiRenderer::new(screen_bounds);

    // Populate static demonstration telemetry data
    let card_id = heapless::String::try_from("OPERATOR_CARD_9021").unwrap();
    state.handle_event(UiEvent::RfidScanned(card_id), core_screen_bounds, None, None);

    let barcode_id = heapless::String::try_from("ITEM-UNIT-448102").unwrap();
    state.handle_event(UiEvent::BarcodeScanned(barcode_id), core_screen_bounds, None, None);

    state.handle_event(
        UiEvent::TouchDown {
            scaled: CorePoint::new(120, 340),
            raw: (4800, 22000),
        },
        core_screen_bounds,
        None,
        None,
    );

    // Render UI frame onto target FrameBuf
    let mut framebuffer = FrameBuf::new(&mut pixels, width, height);
    renderer.render(&mut framebuffer, &state).expect("Failed to render UI frame");

    let ppm_path = format!("{}.ppm", filename_base);
    save_ppm_image(&ppm_path, &pixels, width, height)?;
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
