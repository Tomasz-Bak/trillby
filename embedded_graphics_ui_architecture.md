# Embedded Graphics UI Architecture Specification

## Constraints & Execution Context
- **Target:** Embedded `no_std` Rust.
- **Allocation Model:** Zero heap allocation (`alloc` avoided, fixed buffers via `heapless`).
- **Rendering Engine:** `embedded-graphics` (trait-driven iterator pipeline, no mandatory framebuffers).

---

## 1. Zero-Cost Semantic Theming Engine
Decouple widget geometry from concrete color types (`Rgb565`, `BinaryColor`) using a trait-based palette.

```rust
use embedded_graphics::pixelcolor::PixelColor;

pub trait ColorScheme {
    type Color: PixelColor;

    fn background(&self) -> Self::Color;
    fn surface(&self) -> Self::Color;
    fn primary(&self) -> Self::Color;
    fn text(&self) -> Self::Color;
    fn border(&self) -> Self::Color;
}
```

* **Usage:** Pass `&impl ColorScheme` down through the render pass. Generates `PrimitiveStyle` and `MonoTextStyle` tokens on the fly with zero persistent state.

---

## 2. Asset Pipeline (`tinybmp`)
- **Crate:** `tinybmp` (official zero-alloc companion crate).
- **Storage:** Embed assets into `.rodata` via `include_bytes!`.
- **Parsing:** Header parsed lazily on the stack; serves as an iterator directly into `DrawTarget`.
- **Rule:** Assets must be pre-converted to match the target color depth (e.g., 16-bit uncompressed RGB565) to eliminate runtime conversions.

---

## 3. Keyboard & Viewport State Machine
Instead of a dynamic object tree, manage views via explicit state enumeration and deterministic integer coordinate slicing.

### States & Storage
```rust
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum KeyboardMode {
    Hidden,
    Standard, // Alpha layout
    Extended, // Symbols / numbers
}

pub struct UiState<const N: usize> {
    pub keyboard_mode: KeyboardMode,
    pub input_buffer: heapless::String<N>,
    pub dirty: bool,
}
```

### Deterministic Viewport Partitioning
```rust
use embedded_graphics::geometry::{Point, Size};
use embedded_graphics::primitives::Rectangle;

pub struct LayoutZones {
    pub content_area: Rectangle,
    pub keyboard_area: Option<Rectangle>,
}

impl LayoutZones {
    pub fn compute(screen_bounds: Rectangle, mode: KeyboardMode) -> Self {
        match mode {
            KeyboardMode::Hidden => Self {
                content_area: screen_bounds,
                keyboard_area: None,
            },
            KeyboardMode::Standard | KeyboardMode::Extended => {
                let kb_height = 120; // Fixed pixel height
                let top_height = screen_bounds.size.height.saturating_sub(kb_height);

                Self {
                    content_area: Rectangle::new(
                        screen_bounds.top_left,
                        Size::new(screen_bounds.size.width, top_height),
                    ),
                    keyboard_area: Some(Rectangle::new(
                        Point::new(screen_bounds.top_left.x, screen_bounds.top_left.y + top_height as i32),
                        Size::new(screen_bounds.size.width, kb_height),
                    )),
                }
            }
        }
    }
}
```

---

## 4. Virtual Keyboard Layout Engine
Avoid individual widget structs for keys. Map inputs directly using grid arithmetic over static matrix slices.

```rust
pub struct KeyboardGrid;

impl KeyboardGrid {
    const ROWS: usize = 3;
    const COLS: usize = 10;

    const STANDARD: [&'static str; 3] = [
        "QWERTYUIOP",
        "ASDFGHJKL ",
        "ZXCVBNM<- ",
    ];

    const EXTENDED: [&'static str; 3] = [
        "1234567890",
        "-/:;()$&@ ",
        ".,?!'"#<- ",
    ];

    pub fn resolve_key(bounds: Rectangle, point: Point, mode: KeyboardMode) -> Option<char> {
        if !bounds.contains(point) {
            return None;
        }

        let key_w = bounds.size.width as i32 / Self::COLS as i32;
        let key_h = bounds.size.height as i32 / Self::ROWS as i32;

        let col = ((point.x - bounds.top_left.x) / key_w) as usize;
        let row = ((point.y - bounds.top_left.y) / key_h) as usize;

        let layout = match mode {
            KeyboardMode::Standard => &Self::STANDARD,
            KeyboardMode::Extended => &Self::EXTENDED,
            KeyboardMode::Hidden => return None,
        };

        if row < Self::ROWS && col < Self::COLS {
            layout[row].chars().nth(col).filter(|&c| c != ' ')
        } else {
            None
        }
    }
}
```

---

## 5. Input Dispatch Protocol
- Separate touch coordinates from redraw sweeps.
- If `touch.y < keyboard_area.top_left.y`: route event to content controls (text field selection, buttons).
- If `touch.y >= keyboard_area.top_left.y`: pass coordinate to `KeyboardGrid::resolve_key()`.
