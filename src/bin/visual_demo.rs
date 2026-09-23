use std::fs::File;
use std::io::{BufWriter, Write};
use embedded_graphics::{
    geometry::{Point, Size},
    pixelcolor::{Rgb565, RgbColor},
    primitives::Rectangle,
};
use embedded_graphics_framebuf::FrameBuf;
use trillby::ui::{
    keyboard::Key,
    state::{UiEvent, UiState},
    view::UiRenderer,
};

/// Export an RGB565 framebuffer to a Netpbm PPM (P6 binary) file.
fn export_ppm(path: &str, buffer: &[Rgb565], width: usize, height: usize) -> std::io::Result<()> {
    let file = File::create(path)?;
    let mut writer = BufWriter::new(file);

    // Write PPM header
    writeln!(writer, "P6")?;
    writeln!(writer, "{} {}", width, height)?;
    writeln!(writer, "255")?;

    // Write RGB888 pixel bytes obtained via RgbColor trait
    for pixel in buffer {
        let r = pixel.r();
        let g = pixel.g();
        let b = pixel.b();
        writer.write_all(&[r, g, b])?;
    }

    writer.flush()?;
    Ok(())
}

fn main() -> std::io::Result<()> {
    println!("Generating visual UI demo frames (800x480 RGB565)...");

    let screen_bounds = Rectangle::new(Point::zero(), Size::new(800, 480));
    let renderer = UiRenderer::new(screen_bounds);
    let mut buffer = [Rgb565::new(0, 0, 0); 800 * 480];

    // Frame 1: Initial Scaffolding View
    let mut state: UiState<256> = UiState::new();
    let mut fb = FrameBuf::new(&mut buffer, 800, 480);
    renderer.render(&mut fb, &state).unwrap();
    export_ppm("demo_frame_1_scaffold.ppm", &buffer, 800, 480)?;

    // Frame 2: Touch & Typed Characters
    state.handle_event(
        UiEvent::TouchDown { scaled: Point::new(100, 320), raw: (4000, 20000) },
        screen_bounds,
        Some(Rectangle::new(Point::new(0, 300), Size::new(800, 180))),
    );
    state.handle_event(
        UiEvent::TouchUp { scaled: Point::new(100, 320), raw: (4000, 20000) },
        screen_bounds,
        Some(Rectangle::new(Point::new(0, 300), Size::new(800, 180))),
    );
    state.apply_key(Key::Char('E'));
    state.apply_key(Key::Char('S'));
    state.apply_key(Key::Char('T'));

    let mut fb = FrameBuf::new(&mut buffer, 800, 480);
    renderer.render(&mut fb, &state).unwrap();
    export_ppm("demo_frame_2_keyboard.ppm", &buffer, 800, 480)?;

    // Frame 3: RFID Scan
    let card = heapless::String::try_from("RFID_CARD_8819").unwrap();
    state.handle_event(UiEvent::RfidScanned(card), screen_bounds, None);
    let mut fb = FrameBuf::new(&mut buffer, 800, 480);
    renderer.render(&mut fb, &state).unwrap();
    export_ppm("demo_frame_3_rfid.ppm", &buffer, 800, 480)?;

    println!("Visual UI demo frame generation complete!");
    Ok(())
}

