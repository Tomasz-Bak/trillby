use crate::geometry::Point;
use heapless::String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiEvent {
    TouchDown { scaled: Point, raw: (i32, i32) },
    TouchUp { scaled: Point, raw: (i32, i32) },
    TouchMove { scaled: Point, raw: (i32, i32) },
    RfidScanned(String<32>),
    BarcodeScanned(String<64>),
    Tick,
}
