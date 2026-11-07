use heapless::{Deque, String};

pub const MAX_OPERATOR_ID_LEN: usize = 32;
pub const MAX_JOB_ID_LEN: usize = 64;

pub const DUMMY_OPERATOR_ID: &str = "DUMMY_OP_01";
pub const DUMMY_JOB_ID: &str = "DUMMY_JOB_01";
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionState {
    #[default]
    Idle,
    Authenticated {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
    },
    Working {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
        job_id: String<MAX_JOB_ID_LEN>,
        started_at_ms: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    OperatorLogin {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
        at_ms: u64,
    },
    OperatorLogout {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
        at_ms: u64,
    },
    WorkStart {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
        job_id: String<MAX_JOB_ID_LEN>,
        started_at_ms: u64,
    },
    WorkStop {
        operator_id: String<MAX_OPERATOR_ID_LEN>,
        job_id: String<MAX_JOB_ID_LEN>,
        started_at_ms: u64,
        stopped_at_ms: u64,
        duration_ms: u64,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionRejectReason {
    NotAuthenticated,
    JobMismatch,
}

fn to_bounded_string<const CAP: usize>(s: &str) -> String<CAP> {
    let mut out = String::new();
    let _ = crate::push_truncated(&mut out, s);
    out
}

/// FNV-1a over the full, untruncated identifier so ids sharing the stored
/// (truncated) prefix still compare distinct.
fn identifier_key(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in s.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[derive(Debug, Clone)]
pub struct OperatorSession {
    state: SessionState,
    events: Deque<SessionEvent, 8>,
    operator_key: u64,
    job_key: u64,
}

impl PartialEq for OperatorSession {
    fn eq(&self, other: &Self) -> bool {
        self.state == other.state
            && self.operator_key == other.operator_key
            && self.job_key == other.job_key
            && self.events.iter().eq(other.events.iter())
    }
}

impl Eq for OperatorSession {}

impl Default for OperatorSession {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorSession {
    pub const fn new() -> Self {
        Self {
            state: SessionState::Idle,
            events: Deque::new(),
            operator_key: 0,
            job_key: 0,
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn pop_event(&mut self) -> Option<SessionEvent> {
        self.events.pop_front()
    }

    pub fn clear(&mut self) {
        self.state = SessionState::Idle;
        self.events.clear();
        self.operator_key = 0;
        self.job_key = 0;
    }

    fn enqueue(&mut self, event: SessionEvent) {
        if self.events.is_full() {
            let _ = self.events.pop_front();
        }
        let _ = self.events.push_back(event);
    }

    pub fn handle_rfid(&mut self, badge: &str, now_ms: u64) {
        let badge_id: String<MAX_OPERATOR_ID_LEN> = to_bounded_string(badge);
        let badge_key = identifier_key(badge);
        match &self.state {
            SessionState::Idle => {
                self.operator_key = badge_key;
                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: badge_id,
                    at_ms: now_ms,
                });
            }
            SessionState::Authenticated { operator_id } => {
                let old_op = operator_id.clone();
                let same_op = badge_id == old_op && badge_key == self.operator_key;
                if same_op {
                    self.operator_key = 0;
                    self.state = SessionState::Idle;
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                } else {
                    self.operator_key = badge_key;
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        at_ms: now_ms,
                    });
                }
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_ms,
            } => {
                let old_op = operator_id.clone();
                let active_job = job_id.clone();
                let start_ms = *started_at_ms;
                let duration_ms = now_ms.saturating_sub(start_ms);
                let same_op = badge_id == old_op && badge_key == self.operator_key;

                self.enqueue(SessionEvent::WorkStop {
                    operator_id: old_op.clone(),
                    job_id: active_job,
                    started_at_ms: start_ms,
                    stopped_at_ms: now_ms,
                    duration_ms,
                });

                if same_op {
                    self.operator_key = 0;
                    self.job_key = 0;
                    self.state = SessionState::Idle;
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                } else {
                    self.operator_key = badge_key;
                    self.job_key = 0;
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        at_ms: now_ms,
                    });
                }
            }
        }
    }

    pub fn handle_barcode(&mut self, code: &str, now_ms: u64) -> Result<(), SessionRejectReason> {
        let code_id: String<MAX_JOB_ID_LEN> = to_bounded_string(code);
        match &self.state {
            SessionState::Idle => Err(SessionRejectReason::NotAuthenticated),
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.job_key = identifier_key(code);
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_ms: now_ms,
                };
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_ms: now_ms,
                });
                Ok(())
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_ms,
            } => {
                if code_id == *job_id && identifier_key(code) == self.job_key {
                    let op_id = operator_id.clone();
                    let active_job = job_id.clone();
                    let start_ms = *started_at_ms;
                    let duration_ms = now_ms.saturating_sub(start_ms);

                    self.job_key = 0;
                    self.state = SessionState::Authenticated {
                        operator_id: op_id.clone(),
                    };
                    self.enqueue(SessionEvent::WorkStop {
                        operator_id: op_id,
                        job_id: active_job,
                        started_at_ms: start_ms,
                        stopped_at_ms: now_ms,
                        duration_ms,
                    });
                    Ok(())
                } else {
                    Err(SessionRejectReason::JobMismatch)
                }
            }
        }
    }

    pub fn force_authenticate(&mut self, badge: &str, now_ms: u64) -> bool {
        let badge_id: String<MAX_OPERATOR_ID_LEN> = to_bounded_string(badge);
        let badge_key = identifier_key(badge);
        match &self.state {
            SessionState::Idle => {
                self.operator_key = badge_key;
                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: badge_id,
                    at_ms: now_ms,
                });
                true
            }
            SessionState::Authenticated { operator_id } => {
                let same_op = *operator_id == badge_id && badge_key == self.operator_key;
                if same_op {
                    false
                } else {
                    let old_op = operator_id.clone();
                    self.operator_key = badge_key;
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        at_ms: now_ms,
                    });
                    true
                }
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_ms,
            } => {
                let old_op = operator_id.clone();
                let active_job = job_id.clone();
                let start_ms = *started_at_ms;
                let duration_ms = now_ms.saturating_sub(start_ms);
                let same_op = old_op == badge_id && badge_key == self.operator_key;

                self.operator_key = badge_key;
                self.job_key = 0;
                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: old_op.clone(),
                    job_id: active_job,
                    started_at_ms: start_ms,
                    stopped_at_ms: now_ms,
                    duration_ms,
                });
                if !same_op {
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        at_ms: now_ms,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        at_ms: now_ms,
                    });
                }
                true
            }
        }
    }

    pub fn force_start_job(&mut self, default_badge: &str, code: &str, now_ms: u64) -> bool {
        let code_id: String<MAX_JOB_ID_LEN> = to_bounded_string(code);
        match &self.state {
            SessionState::Idle => {
                let op_id: String<MAX_OPERATOR_ID_LEN> = to_bounded_string(default_badge);
                self.operator_key = identifier_key(default_badge);
                self.job_key = identifier_key(code);
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_ms: now_ms,
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: op_id.clone(),
                    at_ms: now_ms,
                });
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_ms: now_ms,
                });
                true
            }
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.job_key = identifier_key(code);
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_ms: now_ms,
                };
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_ms: now_ms,
                });
                true
            }
            SessionState::Working { .. } => false,
        }
    }

    pub fn force_stop_job(&mut self, now_ms: u64) -> bool {
        match &self.state {
            SessionState::Working {
                operator_id,
                job_id,
                started_at_ms,
            } => {
                let op_id = operator_id.clone();
                let active_job = job_id.clone();
                let start_ms = *started_at_ms;
                let duration_ms = now_ms.saturating_sub(start_ms);

                self.job_key = 0;
                self.state = SessionState::Authenticated {
                    operator_id: op_id.clone(),
                };
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: op_id,
                    job_id: active_job,
                    started_at_ms: start_ms,
                    stopped_at_ms: now_ms,
                    duration_ms,
                });
                true
            }
            SessionState::Idle | SessionState::Authenticated { .. } => false,
        }
    }

    pub fn force_logout(&mut self, now_ms: u64) -> bool {
        match &self.state {
            SessionState::Idle => false,
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.operator_key = 0;
                self.job_key = 0;
                self.state = SessionState::Idle;
                self.enqueue(SessionEvent::OperatorLogout {
                    operator_id: op_id,
                    at_ms: now_ms,
                });
                true
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_ms,
            } => {
                let op_id = operator_id.clone();
                let active_job = job_id.clone();
                let start_ms = *started_at_ms;
                let duration_ms = now_ms.saturating_sub(start_ms);
                self.operator_key = 0;
                self.job_key = 0;
                self.state = SessionState::Idle;
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: op_id.clone(),
                    job_id: active_job,
                    started_at_ms: start_ms,
                    stopped_at_ms: now_ms,
                    duration_ms,
                });
                self.enqueue(SessionEvent::OperatorLogout {
                    operator_id: op_id,
                    at_ms: now_ms,
                });
                true
            }
        }
    }

    pub fn login(&mut self, id: &str, now_ms: u64) {
        self.handle_rfid(id, now_ms);
    }

    pub fn logout(&mut self, now_ms: u64) -> bool {
        self.force_logout(now_ms)
    }

    pub fn start_work(&mut self, code: &str, now_ms: u64) -> bool {
        self.force_start_job(crate::session::DUMMY_OPERATOR_ID, code, now_ms)
    }

    pub fn stop_work(&mut self, now_ms: u64) -> Option<String<MAX_OPERATOR_ID_LEN>> {
        match &self.state {
            SessionState::Working { operator_id, .. } => {
                let op = operator_id.clone();
                if self.force_stop_job(now_ms) {
                    Some(op)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn s32(val: &str) -> String<MAX_OPERATOR_ID_LEN> {
        to_bounded_string(val)
    }

    pub(crate) fn s64(val: &str) -> String<MAX_JOB_ID_LEN> {
        to_bounded_string(val)
    }

    pub(crate) fn drain(s: &mut OperatorSession) -> heapless::Vec<SessionEvent, 8> {
        let mut events = heapless::Vec::new();
        while let Some(ev) = s.pop_event() {
            let _ = events.push(ev);
        }
        events
    }

    pub(crate) fn login(op: &str, at_ms: u64) -> SessionEvent {
        SessionEvent::OperatorLogin {
            operator_id: s32(op),
            at_ms,
        }
    }

    pub(crate) fn logout(op: &str, at_ms: u64) -> SessionEvent {
        SessionEvent::OperatorLogout {
            operator_id: s32(op),
            at_ms,
        }
    }

    pub(crate) fn start(op: &str, job: &str, at_ms: u64) -> SessionEvent {
        SessionEvent::WorkStart {
            operator_id: s32(op),
            job_id: s64(job),
            started_at_ms: at_ms,
        }
    }

    pub(crate) fn stop(op: &str, job: &str, start_ms: u64, end_ms: u64) -> SessionEvent {
        SessionEvent::WorkStop {
            operator_id: s32(op),
            job_id: s64(job),
            started_at_ms: start_ms,
            stopped_at_ms: end_ms,
            duration_ms: end_ms - start_ms,
        }
    }
    #[test]
    fn barcode_rejected_when_idle() {
        let mut session = OperatorSession::new();
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            session.handle_barcode("JOB-100", 5),
            Err(SessionRejectReason::NotAuthenticated)
        );
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(drain(&mut session), []);
    }

    #[test]
    fn login_work_start_stop_and_same_rfid_logout() {
        let mut session = OperatorSession::new();

        // 1. Scan RFID -> Authenticated
        session.handle_rfid("OP-1", 10);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-1")
            }
        );
        assert_eq!(drain(&mut session), [login("OP-1", 10)]);

        // 2. Scan barcode -> Working
        assert_eq!(session.handle_barcode("JOB-42", 20), Ok(()));
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-42"),
                started_at_ms: 20,
            }
        );
        assert_eq!(drain(&mut session), [start("OP-1", "JOB-42", 20)]);

        // 3. Scan different barcode -> rejected (JobMismatch)
        assert_eq!(
            session.handle_barcode("JOB-99", 30),
            Err(SessionRejectReason::JobMismatch)
        );
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-42"),
                started_at_ms: 20,
            }
        );
        assert_eq!(drain(&mut session), []);

        // 4. Scan matching barcode -> WorkStop, returns to Authenticated
        assert_eq!(session.handle_barcode("JOB-42", 50), Ok(()));
        assert_eq!(drain(&mut session), [stop("OP-1", "JOB-42", 20, 50)]);

        // 5. Scan same RFID -> OperatorLogout, returns to Idle
        session.handle_rfid("OP-1", 60);
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(drain(&mut session), [logout("OP-1", 60)]);
    }

    #[test]
    fn different_rfid_switches_operator_when_authenticated() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 1);
        let _ = drain(&mut session);

        session.handle_rfid("OP-B", 5);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-B")
            }
        );
        assert_eq!(drain(&mut session), [logout("OP-A", 5), login("OP-B", 5)]);
    }

    #[test]
    fn same_rfid_while_working_auto_stops_and_logs_out() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 10);
        assert_eq!(session.handle_barcode("JOB-1", 15), Ok(()));
        let _ = drain(&mut session);

        session.handle_rfid("OP-A", 35);
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            drain(&mut session),
            [stop("OP-A", "JOB-1", 15, 35), logout("OP-A", 35)]
        );
    }

    #[test]
    fn different_rfid_while_working_auto_stops_and_switches_operator() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 10);
        assert_eq!(session.handle_barcode("JOB-1", 20), Ok(()));
        let _ = drain(&mut session);

        session.handle_rfid("OP-B", 25);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-B")
            }
        );
        assert_eq!(
            drain(&mut session),
            [
                stop("OP-A", "JOB-1", 20, 25),
                logout("OP-A", 25),
                login("OP-B", 25),
            ]
        );
    }

    #[test]
    fn clear_resets_state_and_events() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 1);
        assert_eq!(session.handle_barcode("JOB-1", 2), Ok(()));
        session.clear();
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(drain(&mut session), []);
    }

    #[test]
    fn force_stop_job_transitions_working_to_authenticated() {
        let mut session = OperatorSession::new();
        assert!(!session.force_stop_job(10));

        session.handle_rfid("OP-1", 10);
        let _ = drain(&mut session);
        assert!(!session.force_stop_job(15));

        assert_eq!(session.handle_barcode("JOB-55", 20), Ok(()));
        let _ = drain(&mut session);

        assert!(session.force_stop_job(30));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-1")
            }
        );
        assert_eq!(drain(&mut session), [stop("OP-1", "JOB-55", 20, 30)]);
    }

    #[test]
    fn force_logout_from_idle_authenticated_and_working() {
        let mut session = OperatorSession::new();
        assert!(!session.force_logout(5));

        // From Authenticated -> Idle
        session.handle_rfid("OP-1", 10);
        let _ = drain(&mut session);
        assert!(session.force_logout(15));
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(drain(&mut session), [logout("OP-1", 15)]);

        // From Working -> WorkStop + OperatorLogout -> Idle
        session.handle_rfid("OP-2", 20);
        assert_eq!(session.handle_barcode("JOB-77", 25), Ok(()));
        let _ = drain(&mut session);

        assert!(session.force_logout(40));
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            drain(&mut session),
            [stop("OP-2", "JOB-77", 25, 40), logout("OP-2", 40)]
        );
    }

    #[test]
    fn force_authenticate_from_idle_authenticated_and_working() {
        let mut session = OperatorSession::new();

        // 1. From Idle -> Authenticated
        assert!(session.force_authenticate(DUMMY_OPERATOR_ID, 5));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32(DUMMY_OPERATOR_ID)
            }
        );
        assert_eq!(drain(&mut session), [login(DUMMY_OPERATOR_ID, 5)]);

        // 2. Already Authenticated with same badge -> no-op
        assert!(!session.force_authenticate(DUMMY_OPERATOR_ID, 10));
        assert_eq!(drain(&mut session), []);

        // 3. Authenticated with different badge -> switches operator
        assert!(session.force_authenticate("OP-2", 12));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-2")
            }
        );
        assert_eq!(
            drain(&mut session),
            [logout(DUMMY_OPERATOR_ID, 12), login("OP-2", 12)]
        );

        // 4. From Working with same operator -> stops job and stays Authenticated
        assert_eq!(session.handle_barcode("JOB-1", 20), Ok(()));
        let _ = drain(&mut session);
        assert!(session.force_authenticate("OP-2", 30));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-2")
            }
        );
        assert_eq!(drain(&mut session), [stop("OP-2", "JOB-1", 20, 30)]);

        // 5. From Working with different operator -> stops job and switches operator
        assert_eq!(session.handle_barcode("JOB-2", 40), Ok(()));
        let _ = drain(&mut session);
        assert!(session.force_authenticate(DUMMY_OPERATOR_ID, 50));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32(DUMMY_OPERATOR_ID)
            }
        );
        assert_eq!(
            drain(&mut session),
            [
                stop("OP-2", "JOB-2", 40, 50),
                logout("OP-2", 50),
                login(DUMMY_OPERATOR_ID, 50),
            ]
        );
    }

    #[test]
    fn force_start_job_from_idle_authenticated_and_working() {
        let mut session = OperatorSession::new();

        // 1. From Idle -> auto-authenticates default_badge and starts job
        assert!(session.force_start_job(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 10));
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32(DUMMY_OPERATOR_ID),
                job_id: s64(DUMMY_JOB_ID),
                started_at_ms: 10,
            }
        );
        assert_eq!(
            drain(&mut session),
            [
                login(DUMMY_OPERATOR_ID, 10),
                start(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 10),
            ]
        );

        // 2. While Working -> returns false (no-op)
        assert!(!session.force_start_job(DUMMY_OPERATOR_ID, "OTHER_JOB", 15));
        assert_eq!(drain(&mut session), []);

        // 3. From Authenticated -> starts job for current operator
        session.clear();
        session.handle_rfid("REAL-OP", 20);
        let _ = drain(&mut session);
        assert!(session.force_start_job(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 25));
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32("REAL-OP"),
                job_id: s64(DUMMY_JOB_ID),
                started_at_ms: 25,
            }
        );
        assert_eq!(
            drain(&mut session),
            [start("REAL-OP", DUMMY_JOB_ID, 25)]
        );
    }
    #[test]
    fn event_queue_capacity_8_fifo_and_oldest_eviction_on_overflow() {
        let mut session = OperatorSession::new();

        // 1. handle_rfid("OP_1", 10) -> 1 event (OperatorLogin(OP_1))
        session.handle_rfid("OP_1", 10);

        // 2. handle_rfid("OP_2", 20) -> +2 events (OperatorLogout(OP_1), OperatorLogin(OP_2); total 3)
        session.handle_rfid("OP_2", 20);

        // 3. handle_barcode("JOB_1", 30) -> +1 event (WorkStart(OP_2, JOB_1); total 4)
        assert!(session.handle_barcode("JOB_1", 30).is_ok());

        // 4. handle_rfid("OP_3", 40) -> +3 events (WorkStop(OP_2, JOB_1), OperatorLogout(OP_2), OperatorLogin(OP_3); total 7)
        session.handle_rfid("OP_3", 40);

        // 5. handle_barcode("JOB_2", 50) -> +1 event (WorkStart(OP_3, JOB_2); total 8, full)
        assert!(session.handle_barcode("JOB_2", 50).is_ok());

        // 6. handle_rfid("OP_4", 60) -> +3 events (WorkStop(OP_3, JOB_2), OperatorLogout(OP_3), OperatorLogin(OP_4)),
        // evicting the 3 oldest events (OperatorLogin(OP_1), OperatorLogout(OP_1), OperatorLogin(OP_2)).
        session.handle_rfid("OP_4", 60);

        // Drain all events with drain() and assert exact 8-event FIFO sequence
        assert_eq!(
            drain(&mut session),
            [
                start("OP_2", "JOB_1", 30),
                stop("OP_2", "JOB_1", 30, 40),
                logout("OP_2", 40),
                login("OP_3", 40),
                start("OP_3", "JOB_2", 50),
                stop("OP_3", "JOB_2", 50, 60),
                logout("OP_3", 60),
                login("OP_4", 60),
            ]
        );
    }

    #[test]
    fn duration_ms_non_monotonic_time_and_u64_max_saturation() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP_1", 10);
        assert!(session.handle_barcode("JOB_1", 100).is_ok());
        let _ = drain(&mut session);

        // Non-monotonic clock: stopped at ms 50 < started at ms 100
        assert!(session.handle_barcode("JOB_1", 50).is_ok());
        assert_eq!(
            drain(&mut session),
            [SessionEvent::WorkStop {
                operator_id: s32("OP_1"),
                job_id: s64("JOB_1"),
                started_at_ms: 100,
                stopped_at_ms: 50,
                duration_ms: 0,
            }]
        );

        // Saturation at u64::MAX
        session.clear();
        session.handle_rfid("OP_1", 0);
        assert!(session.handle_barcode("JOB_MAX", 0).is_ok());
        let _ = drain(&mut session);

        assert!(session.handle_barcode("JOB_MAX", u64::MAX).is_ok());
        assert_eq!(
            drain(&mut session),
            [SessionEvent::WorkStop {
                operator_id: s32("OP_1"),
                job_id: s64("JOB_MAX"),
                started_at_ms: 0,
                stopped_at_ms: u64::MAX,
                duration_ms: u64::MAX,
            }]
        );
    }

    #[test]
    fn multibyte_utf8_truncation_and_distinct_overlong_identifiers() {
        let mut session = OperatorSession::new();

        // 15 "é" characters (30 bytes) + 1 '🦀' (4 bytes) = 34 bytes
        let badge_multi = "ééééééééééééééé🦀";
        let expected_multi = "ééééééééééééééé";
        session.handle_rfid(badge_multi, 1);
        match session.state() {
            SessionState::Authenticated { operator_id } => {
                assert_eq!(operator_id.as_str(), expected_multi);
            }
            other => panic!("expected Authenticated state, got {:?}", other),
        }

        // Two distinct 33-character badges sharing a 32-byte prefix:
        // "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1" vs "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2"
        let badge_a = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA1";
        let badge_b = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2";

        session.clear();
        session.handle_rfid(badge_a, 1);
        session.handle_rfid(badge_b, 2);
        // badge_b must NOT treat badge_b as a same-operator logout to SessionState::Idle
        assert_ne!(
            session.state(),
            &SessionState::Idle,
            "badge_b with distinct 33rd char was falsely treated as same-operator logout"
        );

        // Two distinct 65-character jobs sharing a 64-byte prefix:
        // 64 'J's followed by '1' vs '2'
        let job_a = "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ1";
        let job_b = "JJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJJ2";

        session.clear();
        session.handle_rfid("OP_1", 1);
        assert!(session.handle_barcode(job_a, 2).is_ok());
        assert_eq!(
            session.handle_barcode(job_b, 3),
            Err(SessionRejectReason::JobMismatch),
            "job_b with distinct 65th char was falsely accepted as matching active job"
        );
    }

}
