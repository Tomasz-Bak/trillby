use embedded_graphics::geometry::Size;
use embedded_graphics::mono_font::{
    ascii::{FONT_6X12, FONT_8X13, FONT_9X18_BOLD},
    MonoFont,
};
use embedded_graphics::pixelcolor::{Rgb565, RgbColor};

/// Semantic theme trait for zero-cost UI styling.
pub trait Theme {
    #[inline] fn background(&self) -> Rgb565 { Rgb565::new(3, 10, 7) } // #1E293B
    #[inline] fn surface(&self) -> Rgb565 { Rgb565::new(6, 16, 10) } // #334155
    #[inline] fn surface_active(&self) -> Rgb565 { Rgb565::new(8, 21, 13) } // #475569
    #[inline] fn primary(&self) -> Rgb565 { Rgb565::new(12, 25, 29) } // #6366F1
    #[inline] fn primary_text(&self) -> Rgb565 { Rgb565::WHITE } // #FFFFFF
    #[inline] fn text(&self) -> Rgb565 { Rgb565::WHITE } // #FFFFFF
    #[inline] fn text_muted(&self) -> Rgb565 { Rgb565::new(24, 52, 27) } // #CBD5E1
    #[inline] fn border(&self) -> Rgb565 { Rgb565::new(12, 28, 17) } // #64748B
    #[inline] fn warning(&self) -> Rgb565 { Rgb565::new(30, 39, 1) } // #F59E0B
    #[inline] fn success(&self) -> Rgb565 { Rgb565::new(2, 46, 16) } // #10B981

    // Geometry & Spacing
    #[inline] fn radius_sm(&self) -> Size { Size::new(4, 4) }
    #[inline] fn radius_md(&self) -> Size { Size::new(6, 6) }
    #[inline] fn radius_lg(&self) -> Size { Size::new(8, 8) }
    #[inline] fn spacing_sm(&self) -> u32 { 4 }
    #[inline] fn spacing_md(&self) -> u32 { 8 }
    #[inline] fn spacing_lg(&self) -> u32 { 12 }
    #[inline] fn spacing_xl(&self) -> u32 { 16 }

    // Fonts
    #[inline] fn font_small(&self) -> &'static MonoFont<'static> { &FONT_6X12 }
    #[inline] fn font_medium(&self) -> &'static MonoFont<'static> { &FONT_8X13 }
    #[inline] fn font_large(&self) -> &'static MonoFont<'static> { &FONT_9X18_BOLD }
}

/// Slate Blue Web Theme using calibrated 16-bit RGB565 colors (Slate 800 Navy Canvas & Indigo palette).
#[derive(Debug, Clone, Copy, Default)]
pub struct DarkFloorTheme;

impl Theme for DarkFloorTheme {}

