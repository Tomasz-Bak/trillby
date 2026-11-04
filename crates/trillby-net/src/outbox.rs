//! Offline Resilient Outbox Queue
//!
//! Fixed-capacity zero-allocation ring buffer storing *plaintext* events
//! awaiting server acknowledgement.
//!
//! Events are deliberately NOT sealed at enqueue time: the session key,
//! session id and sequence number only exist once a handshake completes, and
//! all three change on every reconnect. `NetClient` encrypts the head event
//! with the *current* session right before transmitting it, so events queued
//! while offline (or left unacknowledged when a link drops) are always
//! deliverable on the next session.

use crate::packet::{MsgType, MAX_PAYLOAD_LEN, TAG_LEN};

/// Largest plaintext that still fits in one frame after the AEAD tag.
pub const MAX_EVENT_LEN: usize = MAX_PAYLOAD_LEN as usize - TAG_LEN;
const _: () = assert!(MAX_EVENT_LEN <= u8::MAX as usize);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxError {
    Full,
    FrameTooLarge,
}

#[derive(Clone, Copy)]
pub struct QueuedEvent {
    pub msg_type: MsgType,
    pub len: u8,
    pub data: [u8; MAX_EVENT_LEN],
}

impl QueuedEvent {
    pub const fn empty() -> Self {
        Self {
            msg_type: MsgType::Data,
            len: 0,
            data: [0u8; MAX_EVENT_LEN],
        }
    }
}

pub struct Outbox<const CAP: usize> {
    events: [QueuedEvent; CAP],
    head: usize,
    tail: usize,
    count: usize,
}

impl<const CAP: usize> Outbox<CAP> {
    pub const fn new() -> Self {
        Self {
            events: [QueuedEvent::empty(); CAP],
            head: 0,
            tail: 0,
            count: 0,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn is_full(&self) -> bool {
        self.count == CAP
    }

    pub fn len(&self) -> usize {
        self.count
    }

    pub fn capacity(&self) -> usize {
        CAP
    }

    /// Enqueue a plaintext event.
    pub fn push(&mut self, msg_type: MsgType, plaintext: &[u8]) -> Result<(), OutboxError> {
        if plaintext.len() > MAX_EVENT_LEN {
            return Err(OutboxError::FrameTooLarge);
        }
        if self.count >= CAP {
            return Err(OutboxError::Full);
        }

        let slot = &mut self.events[self.tail];
        slot.msg_type = msg_type;
        slot.len = plaintext.len() as u8;
        slot.data[..plaintext.len()].copy_from_slice(plaintext);

        self.tail = (self.tail + 1) % CAP;
        self.count += 1;
        Ok(())
    }

    /// Inspect the oldest unacknowledged event at the head of the queue.
    pub fn peek(&self) -> Option<(MsgType, &[u8])> {
        if self.count == 0 {
            None
        } else {
            let slot = &self.events[self.head];
            Some((slot.msg_type, &slot.data[..slot.len as usize]))
        }
    }

    /// Remove the head event (after the server acknowledged it).
    pub fn pop(&mut self) -> bool {
        if self.count == 0 {
            return false;
        }
        self.head = (self.head + 1) % CAP;
        self.count -= 1;
        true
    }

    pub fn clear(&mut self) {
        self.head = 0;
        self.tail = 0;
        self.count = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_outbox_fifo_lifecycle() {
        let mut outbox: Outbox<4> = Outbox::new();
        assert!(outbox.is_empty());

        assert!(outbox.push(MsgType::Data, b"EVENT_1").is_ok());
        assert!(outbox.push(MsgType::AuthInit, b"EVENT_2").is_ok());
        assert!(outbox.push(MsgType::Heartbeat, b"EVENT_3").is_ok());
        assert_eq!(outbox.len(), 3);

        // Peek head
        let (ty, data) = outbox.peek().unwrap();
        assert_eq!(ty, MsgType::Data);
        assert_eq!(data, b"EVENT_1");

        // Pop event 1
        assert!(outbox.pop());
        assert_eq!(outbox.len(), 2);

        // Next peek should be event 2
        let (ty2, data2) = outbox.peek().unwrap();
        assert_eq!(ty2, MsgType::AuthInit);
        assert_eq!(data2, b"EVENT_2");

        // Pop event 2
        assert!(outbox.pop());
        assert_eq!(outbox.len(), 1);

        // Push until full (exercises ring wrap-around)
        assert!(outbox.push(MsgType::Data, b"EVENT_4").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_5").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_6").is_ok());
        assert!(outbox.is_full());
        assert_eq!(outbox.push(MsgType::Data, b"EVENT_7"), Err(OutboxError::Full));

        // FIFO order preserved across wrap
        for expected in [&b"EVENT_3"[..], b"EVENT_4", b"EVENT_5", b"EVENT_6"] {
            assert_eq!(outbox.peek().unwrap().1, expected);
            assert!(outbox.pop());
        }
        assert!(!outbox.pop());
    }

    #[test]
    fn test_outbox_rejects_oversized_event() {
        let mut outbox: Outbox<2> = Outbox::new();
        assert!(outbox.push(MsgType::Data, &[0u8; MAX_EVENT_LEN]).is_ok());
        assert_eq!(
            outbox.push(MsgType::Data, &[0u8; MAX_EVENT_LEN + 1]),
            Err(OutboxError::FrameTooLarge)
        );
    }

    #[test]
    fn test_outbox_clear_and_capacity_reuse() {
        let mut outbox: Outbox<3> = Outbox::new();
        assert_eq!(outbox.capacity(), 3);
        assert!(outbox.is_empty());
        assert_eq!(outbox.len(), 0);

        // Fill to capacity
        assert!(outbox.push(MsgType::Data, b"EVENT_1").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_2").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_3").is_ok());
        assert!(outbox.is_full());
        assert_eq!(outbox.len(), 3);
        assert_eq!(outbox.push(MsgType::Data, b"EVENT_4"), Err(OutboxError::Full));

        // Clear outbox
        outbox.clear();
        assert!(outbox.is_empty());
        assert!(!outbox.is_full());
        assert_eq!(outbox.len(), 0);
        assert_eq!(outbox.peek(), None);
        assert!(!outbox.pop());

        // Re-fill to capacity to verify reuse
        assert!(outbox.push(MsgType::Data, b"EVENT_A").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_B").is_ok());
        assert!(outbox.push(MsgType::Data, b"EVENT_C").is_ok());
        assert!(outbox.is_full());
        assert_eq!(outbox.len(), 3);
        assert_eq!(outbox.push(MsgType::Data, b"EVENT_D"), Err(OutboxError::Full));

        assert_eq!(outbox.peek().unwrap().1, b"EVENT_A");
        assert!(outbox.pop());
        assert_eq!(outbox.peek().unwrap().1, b"EVENT_B");
        assert!(outbox.pop());
        assert_eq!(outbox.peek().unwrap().1, b"EVENT_C");
        assert!(outbox.pop());
        assert!(outbox.is_empty());
        assert!(!outbox.pop());
    }
}
