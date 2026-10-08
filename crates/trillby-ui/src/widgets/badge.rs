use crate::theme::Theme;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::MonoTextStyle,
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, RoundedRectangle},
    text::Text,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum BadgeVariant {
    #[default]
    Success,
    Warning,
    Info,
    Danger,
}

pub struct Badge<'a> {
    pub top_left: Point,
    pub label: &'a str,
    pub variant: BadgeVariant,
}

impl<'a> Badge<'a> {
    pub fn new(top_left: Point, label: &'a str) -> Self {
        Self {
            top_left,
            label,
            variant: BadgeVariant::Success,
        }
    }

    pub fn variant(mut self, variant: BadgeVariant) -> Self {
        self.variant = variant;
        self
    }

    pub fn draw<D, C>(&self, target: &mut D, theme: &C) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
        C: Theme,
    {
        let (bg_color, text_color) = match self.variant {
            BadgeVariant::Success => (theme.success(), theme.primary_text()),
            BadgeVariant::Warning => (theme.warning(), theme.primary_text()),
            BadgeVariant::Info => (theme.primary(), theme.primary_text()),
            BadgeVariant::Danger => (theme.warning(), theme.primary_text()),
        };

        let font = theme.font_small();
        let char_w = font.character_size.width;
        let char_h = font.character_size.height;
        let pad_h = theme.spacing_md();
        let pad_v = theme.spacing_sm();
        let badge_w = (self.label.len() as u32) * char_w + (pad_h * 2);
        let badge_h = char_h + (pad_v * 2);

        let bounds = Rectangle::new(self.top_left, Size::new(badge_w, badge_h));

        let style = PrimitiveStyleBuilder::new()
            .fill_color(bg_color)
            .build();

        RoundedRectangle::with_equal_corners(bounds, Size::new(badge_h / 2, badge_h / 2))
            .into_styled(style)
            .draw(target)?;

        let text_style = MonoTextStyle::new(font, text_color);
        Text::new(
            self.label,
            Point::new(self.top_left.x + pad_h as i32, self.top_left.y + pad_v as i32 + font.baseline as i32),
            text_style,
        )
        .draw(target)?;

        Ok(())
    }
}
