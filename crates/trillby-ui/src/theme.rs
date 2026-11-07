use embedded_graphics::geometry::Size;
use embedded_graphics::mono_font::{
    ascii::{FONT_6X12, FONT_8X13, FONT_9X18_BOLD},
    MonoFont,
};
use embedded_graphics::pixelcolor::{Rgb565, RgbColor};

/// Semantic theme trait for zero-cost UI styling.
pub trait Theme {
    #[inline] fn background(&self) -> Rgb565 { Rgb565::new(3, 10, 7) } // #182839
    #[inline] fn surface(&self) -> Rgb565 { Rgb565::new(6, 16, 10) } // #314052
    #[inline] fn surface_active(&self) -> Rgb565 { Rgb565::new(8, 21, 13) } // #41556A
    #[inline] fn primary(&self) -> Rgb565 { Rgb565::new(12, 25, 29) } // #6265EE
    #[inline] fn primary_text(&self) -> Rgb565 { Rgb565::WHITE } // #FFFFFF
    #[inline] fn text(&self) -> Rgb565 { Rgb565::WHITE } // #FFFFFF
    #[inline] fn text_muted(&self) -> Rgb565 { Rgb565::new(24, 52, 27) } // #C5D2DE
    #[inline] fn border(&self) -> Rgb565 { Rgb565::new(12, 28, 17) } // #62718B
    #[inline] fn warning(&self) -> Rgb565 { Rgb565::new(30, 39, 1) } // #F69D08
    #[inline] fn success(&self) -> Rgb565 { Rgb565::new(2, 46, 16) } // #10BA83
    #[inline] fn danger(&self) -> Rgb565 { Rgb565::new(29, 17, 8) } // #EE4441

    // Geometry & Spacing
    #[inline] fn radius_sm(&self) -> Size { Size::new(4, 4) }
    #[inline] fn radius_md(&self) -> Size { Size::new(6, 6) }
    #[inline] fn spacing_sm(&self) -> u32 { 4 }
    #[inline] fn spacing_md(&self) -> u32 { 8 }
    #[inline] fn spacing_lg(&self) -> u32 { 12 }

    // Fonts
    #[inline] fn font_small(&self) -> &'static MonoFont<'static> { &FONT_6X12 }
    #[inline] fn font_medium(&self) -> &'static MonoFont<'static> { &FONT_8X13 }
    #[inline] fn font_large(&self) -> &'static MonoFont<'static> { &FONT_9X18_BOLD }
}

/// Slate Blue Web Theme using calibrated 16-bit RGB565 colors (Slate 800 Navy Canvas & Indigo palette).
#[derive(Debug, Clone, Copy, Default)]
pub struct DarkFloorTheme;

impl Theme for DarkFloorTheme {}

