use embedded_graphics::pixelcolor::{PixelColor, Rgb565, RgbColor};

/// Semantic color palette trait for zero-cost UI styling.
pub trait ColorScheme {
    type Color: PixelColor;

    fn background(&self) -> Self::Color;
    fn surface(&self) -> Self::Color;
    fn surface_active(&self) -> Self::Color;
    fn primary(&self) -> Self::Color;
    fn primary_text(&self) -> Self::Color;
    fn text(&self) -> Self::Color;
    fn text_muted(&self) -> Self::Color;
    fn border(&self) -> Self::Color;
    fn warning(&self) -> Self::Color;
    fn success(&self) -> Self::Color;
}

/// Slate Blue Web Theme using calibrated 16-bit RGB565 colors (Slate 800 Navy Canvas & Indigo palette).
#[derive(Debug, Clone, Copy, Default)]
pub struct DarkFloorTheme;

impl ColorScheme for DarkFloorTheme {
    type Color = Rgb565;

    #[inline]
    fn background(&self) -> Self::Color {
        // Distinct Navy/Slate Blue Canvas (#1E293B - Slate 800, NOT black)
        Rgb565::new(3, 10, 7)
    }

    #[inline]
    fn surface(&self) -> Self::Color {
        // Elevated Slate Surface Card (#334155 - Slate 700)
        Rgb565::new(6, 16, 10)
    }

    #[inline]
    fn surface_active(&self) -> Self::Color {
        // Active Button / Pressed Card (#475569 - Slate 600)
        Rgb565::new(8, 21, 13)
    }

    #[inline]
    fn primary(&self) -> Self::Color {
        // Vibrant Indigo Primary Accent (#6366F1)
        Rgb565::new(12, 25, 29)
    }

    #[inline]
    fn primary_text(&self) -> Self::Color {
        Rgb565::WHITE
    }

    #[inline]
    fn text(&self) -> Self::Color {
        // Crisp High-Contrast White (#FFFFFF)
        Rgb565::WHITE
    }

    #[inline]
    fn text_muted(&self) -> Self::Color {
        // Soft Slate Text (#CBD5E1 - Slate 300)
        Rgb565::new(24, 52, 27)
    }

    #[inline]
    fn border(&self) -> Self::Color {
        // Visible Slate Border (#64748B - Slate 500)
        Rgb565::new(12, 28, 17)
    }

    #[inline]
    fn warning(&self) -> Self::Color {
        // Warm Amber (#F59E0B)
        Rgb565::new(30, 39, 1)
    }

    #[inline]
    fn success(&self) -> Self::Color {
        // Emerald Success (#10B981)
        Rgb565::new(2, 46, 16)
    }
}
