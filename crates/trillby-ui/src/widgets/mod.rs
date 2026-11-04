pub mod badge;
pub mod button;
pub mod card;
pub mod text_field;

pub use badge::{Badge, BadgeVariant};
pub use button::{Button, ButtonVariant};
pub use card::Card;
pub use text_field::TextField;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::theme::{DarkFloorTheme, Theme};
    use embedded_graphics::{
        geometry::{Point, Size},
        pixelcolor::Rgb565,
        primitives::Rectangle,
    };
    use embedded_graphics_framebuf::FrameBuf;

    #[test]
    fn button_variants_pressed_states_and_danger_distinct_from_warning() {
        let theme = DarkFloorTheme;
        let bounds = Rectangle::new(Point::zero(), Size::new(120, 40));

        // Primary unpressed
        let mut pixels = [theme.background(); 120 * 40];
        let mut fb = FrameBuf::new(&mut pixels, 120, 40);
        Button::new(bounds, "OK")
            .variant(ButtonVariant::Primary)
            .pressed(false)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[5 * 120 + 5], theme.primary());

        // Primary pressed
        let mut pixels = [theme.background(); 120 * 40];
        let mut fb = FrameBuf::new(&mut pixels, 120, 40);
        Button::new(bounds, "OK")
            .variant(ButtonVariant::Primary)
            .pressed(true)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[5 * 120 + 5], theme.surface_active());

        // Danger button must use a danger color distinct from theme.warning()
        let mut pixels = [theme.background(); 120 * 40];
        let mut fb = FrameBuf::new(&mut pixels, 120, 40);
        Button::new(bounds, "DANGER")
            .variant(ButtonVariant::Danger)
            .pressed(false)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_ne!(
            pixels[5 * 120 + 5],
            theme.warning(),
            "ButtonVariant::Danger must use a danger color distinct from theme.warning()"
        );

        // Secondary unpressed
        let mut pixels = [theme.background(); 120 * 40];
        let mut fb = FrameBuf::new(&mut pixels, 120, 40);
        Button::new(bounds, "SEC")
            .variant(ButtonVariant::Secondary)
            .pressed(false)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[5 * 120 + 5], theme.surface());

        // Ghost unpressed leaves background untouched
        let sentinel = Rgb565::new(31, 0, 31);
        let mut pixels = [sentinel; 120 * 40];
        let mut fb = FrameBuf::new(&mut pixels, 120, 40);
        Button::new(bounds, "GHOST")
            .variant(ButtonVariant::Ghost)
            .pressed(false)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[5 * 120 + 5], sentinel);
    }

    #[test]
    fn button_long_label_does_not_draw_outside_button_bounds() {
        let theme = DarkFloorTheme;
        let bounds = Rectangle::new(Point::new(20, 10), Size::new(40, 24));
        let mut pixels = [Rgb565::new(0, 0, 0); 100 * 50];
        let mut fb = FrameBuf::new(&mut pixels, 100, 50);

        Button::new(bounds, "VERY_LONG_BUTTON_LABEL")
            .variant(ButtonVariant::Primary)
            .draw(&mut fb, &theme)
            .unwrap();

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
        let mut pixels = [theme.background(); 120 * 100];
        let mut fb = FrameBuf::new(&mut pixels, 120, 100);
        Card::new(card_bounds)
            .title("TEST")
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[divider_y as usize * 120 + 50], theme.border());

        // Card without title
        let mut pixels = [theme.background(); 120 * 100];
        let mut fb = FrameBuf::new(&mut pixels, 120, 100);
        Card::new(card_bounds)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[divider_y as usize * 120 + 50], theme.surface());

        // TextField border test
        let field_bounds = Rectangle::new(Point::new(10, 10), Size::new(100, 40));

        // Unfocused TextField
        let mut pixels = [theme.background(); 120 * 60];
        let mut fb = FrameBuf::new(&mut pixels, 120, 60);
        TextField::new(field_bounds)
            .focused(false)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[10 * 120 + 50], theme.border());

        // Focused TextField
        let mut pixels = [theme.background(); 120 * 60];
        let mut fb = FrameBuf::new(&mut pixels, 120, 60);
        TextField::new(field_bounds)
            .focused(true)
            .draw(&mut fb, &theme)
            .unwrap();
        assert_eq!(pixels[10 * 120 + 50], theme.primary());
    }
}
