use crate::theme::ColorScheme;
use embedded_graphics::{
    geometry::{Point, Size},
    mono_font::{ascii::FONT_6X12, ascii::FONT_9X18_BOLD, MonoTextStyle},
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
        C: ColorScheme<Color = Rgb565>,
    {
        // 1. Optional Header Label
        if let Some(lbl) = self.label {
            let label_style = MonoTextStyle::new(&FONT_6X12, theme.text_muted());
            Text::new(lbl, Point::new(self.bounds.top_left.x, self.bounds.top_left.y - 4), label_style).draw(target)?;
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

        RoundedRectangle::with_equal_corners(self.bounds, Size::new(4, 4))
            .into_styled(style)
            .draw(target)?;

        // 3. Render Value / Placeholder
        let (disp_str, text_color) = if self.value.is_empty() {
            (self.placeholder, theme.text_muted())
        } else {
            (self.value, theme.primary())
        };

        let val_style = MonoTextStyle::new(&FONT_9X18_BOLD, text_color);
        let ty = self.bounds.top_left.y + (self.bounds.size.height as i32 + 18) / 2 - 2;

        Text::new(disp_str, Point::new(self.bounds.top_left.x + 10, ty), val_style).draw(target)?;

        Ok(())
    }
}
