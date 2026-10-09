use crate::theme::Theme;
use embedded_graphics::{
    geometry::Point,
    mono_font::MonoTextStyle,
    pixelcolor::Rgb565,
    prelude::*,
    primitives::{PrimitiveStyleBuilder, Rectangle, RoundedRectangle},
    text::Text,
};

pub struct TextField<'a> {
    pub bounds: Rectangle,
    pub label: Option<&'a str>,
    pub value: &'a str,
    pub placeholder: &'a str,
    pub is_focused: bool,
}

impl<'a> TextField<'a> {
    pub fn new(bounds: Rectangle) -> Self {
        Self {
            bounds,
            label: None,
            value: "",
            placeholder: "",
            is_focused: false,
        }
    }

    pub fn label(mut self, label: &'a str) -> Self {
        self.label = Some(label);
        self
    }

    pub fn value(mut self, value: &'a str) -> Self {
        self.value = value;
        self
    }

    pub fn placeholder(mut self, placeholder: &'a str) -> Self {
        self.placeholder = placeholder;
        self
    }

    pub fn focused(mut self, is_focused: bool) -> Self {
        self.is_focused = is_focused;
        self
    }

    pub fn draw<D, C>(&self, target: &mut D, theme: &C) -> Result<(), D::Error>
    where
        D: DrawTarget<Color = Rgb565>,
        C: Theme,
    {
        // 1. Optional Header Label
        if let Some(lbl) = self.label {
            let font = theme.font_small();
            let label_style = MonoTextStyle::new(font, theme.text_muted());
            let pad_v = theme.spacing_sm() as i32;
            Text::new(lbl, Point::new(self.bounds.top_left.x, self.bounds.top_left.y - pad_v), label_style).draw(target)?;
        }

        // 2. Input Container Outer Box
        let (stroke_color, stroke_width) = if self.is_focused {
            (theme.primary(), 2)
        } else {
            (theme.border(), 1)
        };

        let style = PrimitiveStyleBuilder::new()
            .fill_color(theme.surface())
            .stroke_color(stroke_color)
            .stroke_width(stroke_width)
            .build();

        RoundedRectangle::with_equal_corners(self.bounds, theme.radius_sm())
            .into_styled(style)
            .draw(target)?;

        // 3. Render Value / Placeholder
        let (disp_str, text_color) = if self.value.is_empty() {
            (self.placeholder, theme.text_muted())
        } else {
            (self.value, theme.primary())
        };

        let font = theme.font_large();
        let val_style = MonoTextStyle::new(font, text_color);
        let char_h = font.character_size.height as i32;
        let pad_h = theme.spacing_md() as i32;
        
        let ty = self.bounds.top_left.y + (self.bounds.size.height as i32 - char_h) / 2 + font.baseline as i32;

        Text::new(disp_str, Point::new(self.bounds.top_left.x + pad_h, ty), val_style).draw(target)?;

        Ok(())
    }
}
