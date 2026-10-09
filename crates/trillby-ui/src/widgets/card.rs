use crate::theme::Theme;
use embedded_graphics::{
    geometry::Point,
    mono_font::MonoTextStyle,
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
        C: Theme,
    {
        // 1. Container Surface
        let card_style = PrimitiveStyleBuilder::new()
            .fill_color(theme.surface())
            .stroke_color(theme.border())
            .stroke_width(1)
            .build();

        RoundedRectangle::with_equal_corners(self.bounds, theme.radius_md())
            .into_styled(card_style)
            .draw(target)?;

        // 2. Optional Title Bar & Divider
        if let Some(t) = self.title {
            let font = theme.font_medium();
            let title_style = MonoTextStyle::new(font, theme.text());
            let pad_h = theme.spacing_lg() as i32;
            let pad_v = theme.spacing_md() as i32;
            
            let title_y = self.bounds.top_left.y + pad_v + font.baseline as i32;
            Text::new(t, Point::new(self.bounds.top_left.x + pad_h, title_y), title_style).draw(target)?;

            let divider_y = title_y + pad_v;
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
