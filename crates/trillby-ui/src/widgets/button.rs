use crate::theme::ColorScheme;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_8X13, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, RoundedRectangle},
    text::Text,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ButtonVariant {
    #[default]
    Primary,
    Secondary,
    Outline,
    Danger,
    Ghost,
}

pub struct Button<'a> {
    pub bounds: Rectangle,
    pub label: &'a str,
    pub variant: ButtonVariant,
    pub is_pressed: bool,
}

impl<'a> Button<'a> {
    pub fn new(bounds: Rectangle, label: &'a str) -> Self {
        Self {
            bounds,
            label,
            variant: ButtonVariant::Primary,
            is_pressed: false,
        }
    }

    pub fn variant(mut self, variant: ButtonVariant) -> Self {
        self.variant = variant;
        self
    }

    pub fn pressed(mut self, is_pressed: bool) -> Self {
        self.is_pressed = is_pressed;
        self
    }

    pub fn draw<D, C>(&self, target: &mut D, theme: &C) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
        C: ColorScheme<Color = Rgb565>,
    {
        let (bg_color, stroke_color, text_color) = match (self.variant, self.is_pressed) {
            (ButtonVariant::Primary, false) => (theme.primary(), theme.primary(), theme.primary_text()),
            (ButtonVariant::Primary, true) => (theme.surface_active(), theme.primary(), theme.primary_text()),
            (ButtonVariant::Secondary, false) => (theme.surface_active(), theme.border(), theme.text()),
            (ButtonVariant::Secondary, true) => (theme.surface(), theme.border(), theme.text()),
            (ButtonVariant::Outline, false) => (theme.surface(), theme.border(), theme.text()),
            (ButtonVariant::Outline, true) => (theme.surface_active(), theme.border(), theme.primary()),
            (ButtonVariant::Danger, false) => (theme.warning(), theme.warning(), theme.primary_text()),
            (ButtonVariant::Danger, true) => (theme.surface_active(), theme.warning(), theme.warning()),
            (ButtonVariant::Ghost, false) => (theme.background(), theme.background(), theme.text_muted()),
            (ButtonVariant::Ghost, true) => (theme.surface_active(), theme.border(), theme.text()),
        };

        let style = PrimitiveStyleBuilder::new()
            .fill_color(bg_color)
            .stroke_color(stroke_color)
            .stroke_width(1)
            .build();

        RoundedRectangle::with_equal_corners(self.bounds, Size::new(4, 4))
            .into_styled(style)
            .draw(target)?;

        let font_style = MonoTextStyle::new(&FONT_8X13, text_color);
        let char_w = 8;
        let char_h = 13;
        let text_w = (self.label.len() as i32) * char_w;

        let tx = self.bounds.top_left.x + (self.bounds.size.width as i32 - text_w) / 2;
        let ty = self.bounds.top_left.y + (self.bounds.size.height as i32 + char_h) / 2 - 2;

        Text::new(self.label, Point::new(tx, ty), font_style).draw(target)?;

        Ok(())
    }
}
