/// Which character set the on-screen keyboard shows.
///
/// Visibility is a separate `bool` on `UiState`: the header button only toggles
/// that, and `Key::LayerToggle` only toggles this. Keeping them as two fields
/// makes it impossible for one control to accidentally cycle the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum KeyboardLayer {
    #[default]
    Alpha,
    Symbols,
}

impl KeyboardLayer {
    pub const fn toggled(self) -> Self {
        match self {
            Self::Alpha => Self::Symbols,
            Self::Symbols => Self::Alpha,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    Space,
    Backspace,
    Enter,
    /// Switch between `KeyboardLayer::Alpha` and `KeyboardLayer::Symbols`.
    LayerToggle,
    /// Rebindable slot; index into the UI's special-key binding table.
    /// Core never sees this variant: the UI resolves it to the bound key
    /// (or drops the press if the slot is unbound).
    Special(u8),
}
