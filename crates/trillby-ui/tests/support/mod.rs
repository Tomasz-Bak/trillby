#![allow(dead_code)]

use core::ops::Range;
use embedded_graphics::{
    draw_target::DrawTarget,
    geometry::{OriginDimensions, Size},
    pixelcolor::Rgb565,
    prelude::RgbColor,
    Pixel,
};
use std::vec;
use std::vec::Vec;
use trillby_ui::{SCREEN_HEIGHT, SCREEN_PIXELS, SCREEN_WIDTH};

pub const W: usize = SCREEN_WIDTH as usize;
pub const H: usize = SCREEN_HEIGHT as usize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OutOfBounds;

pub struct TestCanvas {
    pub pixels: Vec<Rgb565>,
    pub strict: bool,
}

impl TestCanvas {
    pub fn new(strict: bool) -> Self {
        Self {
            pixels: vec![Rgb565::BLACK; SCREEN_PIXELS],
            strict,
        }
    }

    pub fn px(&self, x: i32, y: i32) -> Rgb565 {
        self.pixels[(y as usize) * W + (x as usize)]
    }
}

impl OriginDimensions for TestCanvas {
    fn size(&self) -> Size {
        Size::new(SCREEN_WIDTH, SCREEN_HEIGHT)
    }
}

impl DrawTarget for TestCanvas {
    type Color = Rgb565;
    type Error = OutOfBounds;

    fn draw_iter<I>(&mut self, pixels: I) -> Result<(), Self::Error>
    where
        I: IntoIterator<Item = Pixel<Self::Color>>,
    {
        for Pixel(coord, color) in pixels.into_iter() {
            if coord.x >= 0
                && coord.x < SCREEN_WIDTH as i32
                && coord.y >= 0
                && coord.y < SCREEN_HEIGHT as i32
            {
                let idx = (coord.y as usize) * W + (coord.x as usize);
                self.pixels[idx] = color;
            } else if self.strict {
                return Err(OutOfBounds);
            }
        }
        Ok(())
    }
}

pub fn region_equals(a: &TestCanvas, b: &TestCanvas, xs: Range<i32>, ys: Range<i32>) -> bool {
    for y in ys {
        for x in xs.clone() {
            if a.px(x, y) != b.px(x, y) {
                return false;
            }
        }
    }
    true
}

pub fn login(state: &mut trillby_core::state::UiState<256>, id: &str) {
    let mut s = heapless::String::new();
    let _ = s.push_str(id);
    state.handle_event(trillby_core::event::UiEvent::RfidScanned(s), None, None);
}

pub fn start_job(state: &mut trillby_core::state::UiState<256>, op: &str, job: &str) {
    login(state, op);
    let mut s = heapless::String::new();
    let _ = s.push_str(job);
    state.handle_event(trillby_core::event::UiEvent::BarcodeScanned(s), None, None);
}

pub fn render_to_canvas(renderer: &trillby_ui::view::UiRenderer, state: &trillby_core::state::UiState<256>) -> TestCanvas {
    let mut canvas = TestCanvas::new(false);
    let _ = renderer.render(&mut canvas, state);
    canvas
}

pub fn first_alpha_key_cell() -> embedded_graphics::primitives::Rectangle {
    let screen = embedded_graphics::primitives::Rectangle::new(
        embedded_graphics::geometry::Point::zero(),
        embedded_graphics::geometry::Size::new(SCREEN_WIDTH, SCREEN_HEIGHT),
    );
    let kb = trillby_ui::layout::LayoutZones::compute(screen, true)
        .keyboard_area
        .expect("keyboard area");
    trillby_ui::keyboard_grid::KeyboardGrid::slots(kb, trillby_core::keyboard_types::KeyboardLayer::Alpha)
        .next()
        .expect("first key")
        .0
}

/// Probes the background gap between cards (530, 350).
pub const CARD_GAP_PROBE: embedded_graphics::geometry::Point = embedded_graphics::geometry::Point::new(530, 350);

/// Probes the operator badge display region in the header: x 180..360, y 6..30.
pub const BADGE_REGION: embedded_graphics::primitives::Rectangle = embedded_graphics::primitives::Rectangle::new(
    embedded_graphics::geometry::Point::new(180, 6),
    embedded_graphics::geometry::Size::new(180, 24),
);
