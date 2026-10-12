//! Offline Resilient Outbox Queue
//!
//! Fixed-capacity zero-allocation ring buffer storing encrypted binary frames
//! awaiting server acknowledgement.

use crate::packet::MAX_FRAME_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutboxError {
    Full,
    FrameTooLarge,
}

#[derive(Clone, Copy)]
pub struct QueuedFrame {
    pub seq_num: u32,
    pub len: u16,
    pub data: [u8; MAX_FRAME_LEN],
}

impl QueuedFrame {
    pub const fn empty() -> Self {
        Self {
            seq_num: 0,
            len: 0,
            data: [0u8; MAX_FRAME_LEN],
        }
    }
}

pub struct Outbox<const CAP: usize> {
    frames: [QueuedFrame; CAP],
    head: usize,
    tail: usize,
    count: usize,
}

impl<const CAP: usize> Outbox<CAP> {
    pub const fn new() -> Self {
        Self {
            frames: [QueuedFrame::empty(); CAP],
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

    /// Enqueue an encrypted frame.
    pub fn push(&mut self, seq_num: u32, frame: &[u8]) -> Result<(), OutboxError> {
        if self.count >= CAP {
            return Err(OutboxError::Full);
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(OutboxError::FrameTooLarge);
        }

        let slot = &mut self.frames[self.tail];
        slot.seq_num = seq_num;
        slot.len = frame.len() as u16;
        slot.data[..frame.len()].copy_from_slice(frame);

        self.tail = (self.tail + 1) % CAP;
        self.count += 1;
        Ok(())
    }

    /// Inspect the oldest unacknowledged frame at the head of the queue.
    pub fn peek(&self) -> Option<(u32, &[u8])> {
        if self.count == 0 {
            None
        } else {
            let slot = &self.frames[self.head];
            Some((slot.seq_num, &slot.data[..slot.len as usize]))
        }
    }

    /// Acknowledge and remove the head frame if `seq_num` matches or is ahead.
    pub fn ack(&mut self, seq_num: u32) -> bool {
        if self.count == 0 {
            return false;
        }
        let head_slot = &self.frames[self.head];
        if head_slot.seq_num <= seq_num {
            self.head = (self.head + 1) % CAP;
            self.count -= 1;
            true
        } else {
            false
        }
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

        assert!(outbox.push(1, b"FRAME_1").is_ok());
        assert!(outbox.push(2, b"FRAME_2").is_ok());
        assert!(outbox.push(3, b"FRAME_3").is_ok());
        assert_eq!(outbox.len(), 3);

        // Peek head
        let (seq, data) = outbox.peek().unwrap();
        assert_eq!(seq, 1);
        assert_eq!(data, b"FRAME_1");

        // Ack frame 1
        assert!(outbox.ack(1));
        assert_eq!(outbox.len(), 2);

        // Next peek should be frame 2
        let (seq2, data2) = outbox.peek().unwrap();
        assert_eq!(seq2, 2);
        assert_eq!(data2, b"FRAME_2");

        // Ack frame 2
        assert!(outbox.ack(2));
        assert_eq!(outbox.len(), 1);

        // Push until full
        assert!(outbox.push(4, b"FRAME_4").is_ok());
        assert!(outbox.push(5, b"FRAME_5").is_ok());
        assert!(outbox.push(6, b"FRAME_6").is_ok());
        assert!(outbox.is_full());
        assert_eq!(outbox.push(7, b"FRAME_7"), Err(OutboxError::Full));
    }
}
