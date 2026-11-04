#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NetworkStatus {
    #[default]
    Offline,
    Connecting,
    Handshaking,
    Online,
    Syncing(u16),
}
