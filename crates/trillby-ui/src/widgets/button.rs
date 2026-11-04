use crate::theme::Theme;
use embedded_graphics::{
    geometry::Point,
    mono_font::MonoTextStyle,
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
        C: Theme,
    {
        let (fill, stroke, text_color) = match (self.variant, self.is_pressed) {
            (ButtonVariant::Primary, false) => (Some(theme.primary()), Some(theme.primary()), theme.primary_text()),
            (ButtonVariant::Primary, true) => (Some(theme.surface_active()), Some(theme.primary()), theme.primary_text()),
            (ButtonVariant::Secondary, false) => (Some(theme.surface()), Some(theme.border()), theme.text()),
            (ButtonVariant::Secondary, true) => (Some(theme.surface_active()), Some(theme.border()), theme.text()),
            (ButtonVariant::Outline, false) => (Some(theme.surface()), Some(theme.border()), theme.text()),
            (ButtonVariant::Outline, true) => (Some(theme.surface_active()), Some(theme.border()), theme.primary()),
            (ButtonVariant::Danger, false) => (Some(theme.danger()), Some(theme.danger()), theme.primary_text()),
            (ButtonVariant::Danger, true) => (Some(theme.surface_active()), Some(theme.danger()), theme.danger()),
            (ButtonVariant::Ghost, false) => (None, None, theme.text_muted()),
            (ButtonVariant::Ghost, true) => (Some(theme.surface_active()), Some(theme.border()), theme.text()),
        };

        let mut b = PrimitiveStyleBuilder::new().stroke_width(1);
        if let Some(c) = fill {
            b = b.fill_color(c);
        }
        if let Some(c) = stroke {
            b = b.stroke_color(c);
        }
        let style = b.build();

        RoundedRectangle::with_equal_corners(self.bounds, theme.radius_sm())
            .into_styled(style)
            .draw(target)?;

        let font = theme.font_medium();
        let font_style = MonoTextStyle::new(font, text_color);
        let char_w = font.character_size.width as i32;
        let char_h = font.character_size.height as i32;
        let text_w = (self.label.len() as i32) * char_w;

        let tx = self.bounds.top_left.x + (self.bounds.size.width as i32 - text_w) / 2;
        let ty = self.bounds.top_left.y + (self.bounds.size.height as i32 - char_h) / 2 + font.baseline as i32;

        Text::new(self.label, Point::new(tx, ty), font_style)
            .draw(&mut target.clipped(&self.bounds))?;

        Ok(())
    }
}
