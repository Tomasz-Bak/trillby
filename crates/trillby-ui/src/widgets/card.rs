use crate::theme::ColorScheme;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_8X13, MonoTextStyle},
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{Line, PrimitiveStyleBuilder, Rectangle, RoundedRectangle},
    text::Text,
};

pub struct Card<'a> {
    pub bounds: Rectangle,
    pub title: Option<&'a str>,
}

impl<'a> Card<'a> {
    pub fn new(bounds: Rectangle) -> Self {
        Self { bounds, title: None }
    }

    pub fn title(mut self, title: &'a str) -> Self {
        self.title = Some(title);
        self
    }

    pub fn draw<D, C>(&self, target: &mut D, theme: &C) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
        C: ColorScheme<Color = Rgb565>,
    {
        // 1. Container Surface
        let card_style = PrimitiveStyleBuilder::new()
            .fill_color(theme.surface())
            .stroke_color(theme.border())
            .stroke_width(1)
            .build();

        RoundedRectangle::with_equal_corners(self.bounds, Size::new(6, 6))
            .into_styled(card_style)
            .draw(target)?;

        // 2. Optional Title Bar & Divider
        if let Some(t) = self.title {
            let title_style = MonoTextStyle::new(&FONT_8X13, theme.text());
            Text::new(t, Point::new(self.bounds.top_left.x + 12, self.bounds.top_left.y + 18), title_style).draw(target)?;

            let divider_y = self.bounds.top_left.y + 26;
            let line_style = PrimitiveStyleBuilder::new()
                .stroke_color(theme.border())
                .stroke_width(1)
                .build();

            Line::new(
                Point::new(self.bounds.top_left.x + 1, divider_y),
                Point::new(self.bounds.top_left.x + self.bounds.size.width as i32 - 1, divider_y),
            )
            .into_styled(line_style)
            .draw(target)?;
        }

        Ok(())
    }
}
