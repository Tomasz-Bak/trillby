//! On-screen keyboard layout as plain `const` data.
//!
//! Each layer is a table of rows; each row is a slice of [`Slot`]s whose spans
//! add up to [`COLS`] grid units (enforced at compile time). Hit-testing and
//! drawing both walk the same table via [`KeyboardGrid::slots`], so geometry
//! can't drift between what's drawn and what's tappable.
//!
//! To rebind a spare key, edit [`SPECIAL_BINDINGS`].

use embedded_graphics::geometry::{Point, Size};
use embedded_graphics::primitives::Rectangle;
use trillby_core::keyboard_types::{Key, KeyboardLayer};

pub const ROWS: usize = 4;
pub const COLS: usize = 10;

/// One key position. `span` is its width in grid units (a row is `COLS` units).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Slot {
    pub key: Key,
    pub span: u8,
}

pub type Layout = [&'static [Slot]; ROWS];

const fn ch(c: char) -> Slot {
    Slot { key: Key::Char(c), span: 1 }
}
const fn special(index: u8) -> Slot {
    Slot { key: Key::Special(index), span: 1 }
}
const fn wide(key: Key, span: u8) -> Slot {
    Slot { key, span }
}

const CONTROL_ROW: &[Slot] = &[
    wide(Key::LayerToggle, 2),
    wide(Key::Space, 4),
    wide(Key::Backspace, 2),
    wide(Key::Enter, 2),
];

#[rustfmt::skip]
pub const ALPHA: Layout = [
    &[ch('Q'), ch('W'), ch('E'), ch('R'), ch('T'), ch('Y'), ch('U'), ch('I'), ch('O'), ch('P')],
    &[ch('A'), ch('S'), ch('D'), ch('F'), ch('G'), ch('H'), ch('J'), ch('K'), ch('L'), special(0)],
    &[ch('Z'), ch('X'), ch('C'), ch('V'), ch('B'), ch('N'), ch('M'), ch(','), ch('.'), special(1)],
    CONTROL_ROW,
];

#[rustfmt::skip]
pub const SYMBOLS: Layout = [
    &[ch('1'), ch('2'), ch('3'), ch('4'), ch('5'), ch('6'), ch('7'), ch('8'), ch('9'), ch('0')],
    &[ch('-'), ch('/'), ch(':'), ch(';'), ch('('), ch(')'), ch('$'), ch('&'), ch('@'), special(2)],
    &[ch('.'), ch(','), ch('?'), ch('!'), ch('\''), ch('"'), ch('#'), ch('%'), ch('*'), special(3)],
    CONTROL_ROW,
];

/// What a `Key::Special(i)` slot does. `key` must not itself be `Special`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Binding {
    pub label: &'static str,
    pub key: Key,
}

/// Rebindable spare keys, indexed by `Key::Special(i)`.
/// `None` = unbound: drawn as a blank key, taps are ignored.
///
/// Example: `Some(Binding { label: "-", key: Key::Char('-') })`
pub const SPECIAL_BINDINGS: [Option<Binding>; 4] = [
    None, // ALPHA   row 1, last column
    None, // ALPHA   row 2, last column
    None, // SYMBOLS row 1, last column
    None, // SYMBOLS row 2, last column
];

// Compile-time layout validation: every row must fill exactly COLS units.
const fn row_units(row: &[Slot]) -> usize {
    let mut i = 0;
    let mut units = 0;
    while i < row.len() {
        units += row[i].span as usize;
        i += 1;
    }
    units
}
const fn layout_is_valid(layout: &Layout) -> bool {
    let mut r = 0;
    while r < ROWS {
        if row_units(layout[r]) != COLS {
            return false;
        }
        r += 1;
    }
    true
}
const _: () = assert!(layout_is_valid(&ALPHA), "ALPHA: a row does not span COLS units");
const _: () = assert!(layout_is_valid(&SYMBOLS), "SYMBOLS: a row does not span COLS units");

fn binding(index: u8) -> Option<Binding> {
    SPECIAL_BINDINGS.get(index as usize).copied().flatten()
}

impl Slot {
    /// The key a tap on this slot produces (`Special` resolved via bindings).
    pub fn resolved(self) -> Option<Key> {
        match self.key {
            Key::Special(i) => binding(i).map(|b| b.key),
            key => Some(key),
        }
    }

    /// Text drawn on the key. `buf` backs the label for `Char` keys.
    pub fn label<'a>(self, layer: KeyboardLayer, buf: &'a mut [u8; 4]) -> &'a str {
        match self.key {
            Key::Char(c) => c.encode_utf8(buf),
            Key::Space => "SPACE",
            Key::Backspace => "DEL",
            Key::Enter => "ENTER",
            Key::LayerToggle => match layer {
                KeyboardLayer::Alpha => "?123",
                KeyboardLayer::Symbols => "ABC",
            },
            Key::Special(i) => binding(i).map_or("", |b| b.label),
        }
    }
}

pub struct KeyboardGrid;

impl KeyboardGrid {
    pub const fn layout(layer: KeyboardLayer) -> &'static Layout {
        match layer {
            KeyboardLayer::Alpha => &ALPHA,
            KeyboardLayer::Symbols => &SYMBOLS,
        }
    }

    /// Every slot of `layer` with its on-screen cell inside `bounds`.
    ///
    /// Edges are computed proportionally (`width * unit / COLS`), so cells
    /// tile `bounds` exactly with no remainder gap on the right/bottom.
    pub fn slots(bounds: Rectangle, layer: KeyboardLayer) -> impl Iterator<Item = (Rectangle, Slot)> {
        Self::layout(layer).iter().enumerate().flat_map(move |(row, slots)| {
            let mut unit = 0usize;
            slots.iter().map(move |&slot| {
                let cell = cell_rect(bounds, row, unit, slot.span as usize);
                unit += slot.span as usize;
                (cell, slot)
            })
        })
    }

    /// Slot under `point`, if any.
    pub fn slot_at(bounds: Rectangle, point: Point, layer: KeyboardLayer) -> Option<Slot> {
        Self::slots(bounds, layer)
            .find(|(cell, _)| cell.contains(point))
            .map(|(_, slot)| slot)
    }

    /// Key produced by a tap at `point`; `None` outside the grid or on an unbound slot.
    pub fn resolve_key(bounds: Rectangle, point: Point, layer: KeyboardLayer) -> Option<Key> {
        Self::slot_at(bounds, point, layer)?.resolved()
    }
}

fn cell_rect(bounds: Rectangle, row: usize, unit: usize, span: usize) -> Rectangle {
    let w = bounds.size.width as usize;
    let h = bounds.size.height as usize;
    let x0 = w * unit / COLS;
    let x1 = w * (unit + span) / COLS;
    let y0 = h * row / ROWS;
    let y1 = h * (row + 1) / ROWS;
    Rectangle::new(
        bounds.top_left + Point::new(x0 as i32, y0 as i32),
        Size::new((x1 - x0) as u32, (y1 - y0) as u32),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const KB: Rectangle = Rectangle::new(Point::new(0, 300), Size::new(800, 180));

    #[test]
    fn alpha_keys_resolve() {
        let at = |x, y| KeyboardGrid::resolve_key(KB, Point::new(x, y), KeyboardLayer::Alpha);
        assert_eq!(at(10, 310), Some(Key::Char('Q')));
        assert_eq!(at(750, 310), Some(Key::Char('P')));
        assert_eq!(at(50, 450), Some(Key::LayerToggle));
        assert_eq!(at(300, 450), Some(Key::Space));
        assert_eq!(at(550, 450), Some(Key::Backspace));
        assert_eq!(at(700, 450), Some(Key::Enter));
    }

    #[test]
    fn symbols_keys_resolve() {
        let at = |x, y| KeyboardGrid::resolve_key(KB, Point::new(x, y), KeyboardLayer::Symbols);
        assert_eq!(at(10, 310), Some(Key::Char('1')));
    }

    #[test]
    fn unbound_special_slots_are_inert() {
        for layer in KeyboardLayer::ALL {
            for (cell, slot) in KeyboardGrid::slots(KB, layer) {
                if let Key::Special(i) = slot.key {
                    let mut buf = [0; 4];
                    assert!(SPECIAL_BINDINGS[i as usize].is_none());
                    assert_eq!(slot.label(layer, &mut buf), "");
                    assert_eq!(KeyboardGrid::resolve_key(KB, cell.center(), layer), None);
                }
            }
        }
    }

    #[test]
    fn special_indices_are_in_range() {
        for layer in KeyboardLayer::ALL {
            for (_, slot) in KeyboardGrid::slots(KB, layer) {
                if let Key::Special(i) = slot.key {
                    assert!((i as usize) < SPECIAL_BINDINGS.len());
                }
            }
        }
    }

    /// Drawing and hit-testing share `slots()`; prove each cell's centre maps back to it
    /// and that cells tile the keyboard exactly.
    #[test]
    fn cells_round_trip_and_tile() {
        for layer in KeyboardLayer::ALL {
            let mut area = 0u32;
            for (cell, slot) in KeyboardGrid::slots(KB, layer) {
                assert_eq!(KeyboardGrid::slot_at(KB, cell.center(), layer), Some(slot));
                area += cell.size.width * cell.size.height;
            }
            assert_eq!(area, KB.size.width * KB.size.height);
        }
    }

    #[test]
    fn all_alpha_and_symbols_slots_resolve_at_edges_and_labels_match() {
        for layer in KeyboardLayer::ALL {
            for (rect, slot) in KeyboardGrid::slots(KB, layer) {
                let mut buf = [0u8; 4];
                let label = slot.label(layer, &mut buf);
                match slot.key {
                    Key::Space => assert_eq!(label, "SPACE"),
                    Key::Backspace => assert_eq!(label, "DEL"),
                    Key::Enter => assert_eq!(label, "ENTER"),
                    Key::LayerToggle => match layer {
                        KeyboardLayer::Alpha => assert_eq!(label, "?123"),
                        KeyboardLayer::Symbols => assert_eq!(label, "ABC"),
                    },
                    Key::Special(_) => assert_eq!(label, ""),
                    Key::Char(c) => {
                        let mut expected = [0u8; 4];
                        assert_eq!(label, c.encode_utf8(&mut expected));
                    }
                }

                assert_eq!(KeyboardGrid::slot_at(KB, rect.top_left, layer), Some(slot));
                let bottom_right = rect.top_left
                    + Point::new(rect.size.width as i32 - 1, rect.size.height as i32 - 1);
                assert_eq!(KeyboardGrid::slot_at(KB, bottom_right, layer), Some(slot));
            }

            for &pt in &[
                Point::new(0, 299),
                Point::new(-1, 350),
                Point::new(800, 350),
                Point::new(400, 480),
            ] {
                assert_eq!(KeyboardGrid::slot_at(KB, pt, layer), None);
            }
        }
    }

    #[test]
    fn cells_tile_disjointly_without_gaps_on_non_divisible_bounds() {
        let bounds = Rectangle::new(Point::new(3, 7), Size::new(799, 179));
        for layer in KeyboardLayer::ALL {
            let mut total_area = 0u32;
            let mut prev_row_bottom_y = bounds.top_left.y;
            let mut row_height_sum = 0u32;

            for (row_idx, row_slots) in KeyboardGrid::layout(layer).iter().enumerate() {
                let mut unit = 0usize;
                let mut prev_cell_right_x = bounds.top_left.x;
                let mut row_width_sum = 0u32;
                let mut current_row_height = None;

                for &slot in row_slots.iter() {
                    let cell = cell_rect(bounds, row_idx, unit, slot.span as usize);
                    unit += slot.span as usize;

                    // Zero gap, zero overlap horizontally
                    assert_eq!(cell.top_left.x, prev_cell_right_x);
                    prev_cell_right_x = cell.top_left.x + cell.size.width as i32;
                    row_width_sum += cell.size.width;

                    if let Some(h) = current_row_height {
                        assert_eq!(cell.size.height, h);
                        assert_eq!(cell.top_left.y, prev_row_bottom_y);
                    } else {
                        current_row_height = Some(cell.size.height);
                        assert_eq!(cell.top_left.y, prev_row_bottom_y);
                    }

                    total_area += cell.size.width * cell.size.height;
                }

                assert_eq!(row_width_sum, 799);
                assert_eq!(prev_cell_right_x, bounds.top_left.x + 799);

                let h = current_row_height.unwrap();
                row_height_sum += h;
                prev_row_bottom_y += h as i32;
            }

            assert_eq!(row_height_sum, 179);
            assert_eq!(prev_row_bottom_y, bounds.top_left.y + 179);
            assert_eq!(total_area, 799 * 179);
        }
    }
}
