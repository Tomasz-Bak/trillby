pub mod badge;
pub mod button;
pub mod card;
pub mod text_field;

pub use badge::{Badge, BadgeVariant};
pub use button::{Button, ButtonVariant};
pub use card::Card;
pub use text_field::TextField;

pub(crate) fn centered_baseline_y(
    bounds: embedded_graphics::primitives::Rectangle,
    font: &embedded_graphics::mono_font::MonoFont,
) -> i32 {
    let char_h = font.character_size.height as i32;
    bounds.top_left.y + (bounds.size.height as i32 - char_h) / 2 + font.baseline as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{DarkFloorTheme, Theme};
    use embedded_graphics::{
        geometry::{Point, Size},
        pixelcolor::Rgb565,
        primitives::Rectangle,
    };
    use embedded_graphics_framebuf::{backends::FrameBufferBackend, FrameBuf};

    struct SliceBuf<'a>(&'a mut [Rgb565]);

    impl<'a> FrameBufferBackend for SliceBuf<'a> {
        type Color = Rgb565;
        fn set(&mut self, index: usize, color: Rgb565) {
            self.0[index] = color;
        }
        fn get(&self, index: usize) -> Rgb565 {
            self.0[index]
        }
        fn nr_elements(&self) -> usize {
            self.0.len()
        }
    }

    fn draw_widget(
        w: usize,
        h: usize,
        fill: Rgb565,
        draw: impl FnOnce(&mut FrameBuf<Rgb565, SliceBuf<'_>>),
    ) -> std::vec::Vec<Rgb565> {
        let mut pixels = std::vec![fill; w * h];
        let mut fb = FrameBuf::new(SliceBuf(&mut pixels), w, h);
        draw(&mut fb);
        pixels
    }

    fn button_pixel(variant: ButtonVariant, pressed: bool) -> Rgb565 {
        let bounds = Rectangle::new(Point::zero(), Size::new(120, 40));
        let theme = DarkFloorTheme;
        let pixels = draw_widget(120, 40, theme.background(), |fb| {
            Button::new(bounds, "LABEL")
                .variant(variant)
                .pressed(pressed)
                .draw(fb, &theme)
                .unwrap();
        });
        pixels[5 * 120 + 5]
    }

    #[test]
    fn button_variants_pressed_states_and_danger_distinct_from_warning() {
        let theme = DarkFloorTheme;
        assert_eq!(button_pixel(ButtonVariant::Primary, false), theme.primary());
        assert_eq!(button_pixel(ButtonVariant::Primary, true), theme.surface_active());
        assert_ne!(
            button_pixel(ButtonVariant::Danger, false),
            theme.warning(),
            "ButtonVariant::Danger must use a danger color distinct from theme.warning()"
        );
        assert_eq!(button_pixel(ButtonVariant::Secondary, false), theme.surface());
    }

    #[test]
    fn button_long_label_does_not_draw_outside_button_bounds() {
        let theme = DarkFloorTheme;
        let bounds = Rectangle::new(Point::new(20, 10), Size::new(40, 24));
        let pixels = draw_widget(100, 50, Rgb565::new(0, 0, 0), |fb| {
            Button::new(bounds, "VERY_LONG_BUTTON_LABEL")
                .variant(ButtonVariant::Primary)
                .draw(fb, &theme)
                .unwrap();
        });
        for y in 0..50 {
            for x in 0..100 {
                if x < 20 || x >= 60 || y < 10 || y >= 34 {
                    let pixel = pixels[y * 100 + x];
                    assert_eq!(
                        pixel,
                        Rgb565::new(0, 0, 0),
                        "pixel at ({}, {}) was drawn outside button bounds",
                        x, y
                    );
                }
            }
        }
    }

    #[test]
    fn card_and_text_field_pixel_verification() {
        let theme = DarkFloorTheme;

        // Card divider test
        let card_bounds = Rectangle::new(Point::new(10, 10), Size::new(100, 80));
        let font = theme.font_medium();
        let pad_v = theme.spacing_md() as i32;
        let divider_y = card_bounds.top_left.y + pad_v + font.baseline as i32 + pad_v;

        // Card with title
        let pixels = draw_widget(120, 100, theme.background(), |fb| {
            Card::new(card_bounds)
                .title("TEST")
                .draw(fb, &theme)
                .unwrap();
        });
        assert_eq!(pixels[divider_y as usize * 120 + 50], theme.border());

        // Card without title
        let pixels = draw_widget(120, 100, theme.background(), |fb| {
            Card::new(card_bounds)
                .draw(fb, &theme)
                .unwrap();
        });
        assert_eq!(pixels[divider_y as usize * 120 + 50], theme.surface());

        // TextField border test
        let field_bounds = Rectangle::new(Point::new(10, 10), Size::new(100, 40));

        // Unfocused TextField
        let pixels = draw_widget(120, 60, theme.background(), |fb| {
            TextField::new(field_bounds)
                .focused(false)
                .draw(fb, &theme)
                .unwrap();
        });
        assert_eq!(pixels[10 * 120 + 50], theme.border());

        // Focused TextField
        let pixels = draw_widget(120, 60, theme.background(), |fb| {
            TextField::new(field_bounds)
                .focused(true)
                .draw(fb, &theme)
                .unwrap();
        });
        assert_eq!(pixels[10 * 120 + 50], theme.primary());
    }

}
