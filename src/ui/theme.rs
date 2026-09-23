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

/// High-contrast production floor theme using 16-bit RGB565 colors.
#[derive(Debug, Clone, Copy, Default)]
pub struct DarkFloorTheme;

impl ColorScheme for DarkFloorTheme {
    type Color = Rgb565;

    #[inline]
    fn background(&self) -> Self::Color {
        // Dark slate background (15, 23, 42)
        Rgb565::new(1, 5, 5)
    }

    #[inline]
    fn surface(&self) -> Self::Color {
        // Dark surface card (30, 41, 59)
        Rgb565::new(3, 10, 7)
    }

    #[inline]
    fn surface_active(&self) -> Self::Color {
        // Active key / card state (51, 65, 85)
        Rgb565::new(6, 16, 10)
    }

    #[inline]
    fn primary(&self) -> Self::Color {
        // Vivid cyan/emerald primary (16, 185, 129)
        Rgb565::new(2, 46, 16)
    }

    #[inline]
    fn primary_text(&self) -> Self::Color {
        Rgb565::WHITE
    }

    #[inline]
    fn text(&self) -> Self::Color {
        // Crisp white text
        Rgb565::WHITE
    }

    #[inline]
    fn text_muted(&self) -> Self::Color {
        // Light gray (148, 163, 184)
        Rgb565::new(18, 40, 23)
    }

    #[inline]
    fn border(&self) -> Self::Color {
        // Subdued border (71, 85, 105)
        Rgb565::new(8, 21, 13)
    }

    #[inline]
    fn warning(&self) -> Self::Color {
        // Warm amber (245, 158, 11)
        Rgb565::new(30, 39, 1)
    }

    #[inline]
    fn success(&self) -> Self::Color {
        // Green success (34, 197, 94)
        Rgb565::new(4, 49, 11)
    }
}
