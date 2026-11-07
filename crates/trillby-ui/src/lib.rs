#![no_std]

#[cfg(test)]
extern crate std;
#[cfg(test)]
extern crate self as trillby_ui;

#[cfg(test)]
#[path = "../tests/support/mod.rs"]
pub(crate) mod test_support;

pub mod keyboard_grid;
pub mod layout;
pub mod theme;
pub mod view;
pub mod widgets;

pub use keyboard_grid::KeyboardGrid;
pub use layout::{
    dispatch_touch, LayoutZones, ScreenPixels, SCREEN_HEIGHT, SCREEN_PIXELS, SCREEN_WIDTH,
};
pub use theme::{DarkFloorTheme, Theme};
pub use view::{core_point_to_eg, core_rect_to_eg, eg_rect_to_core, UiRenderer};
pub use widgets::{Badge, BadgeVariant, Button, ButtonVariant, Card, TextField};
