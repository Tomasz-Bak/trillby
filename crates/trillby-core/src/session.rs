use heapless::{String, Vec};

pub const DUMMY_OPERATOR_ID: &str = "DUMMY_OP_01";
pub const DUMMY_JOB_ID: &str = "DUMMY_JOB_01";

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum SessionState {
    #[default]
    Idle,
    Authenticated {
        operator_id: String<32>,
    },
    Working {
        operator_id: String<32>,
        job_id: String<64>,
        started_at_tick: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEvent {
    OperatorLogin {
        operator_id: String<32>,
        tick: u64,
    },
    OperatorLogout {
        operator_id: String<32>,
        tick: u64,
    },
    WorkStart {
        operator_id: String<32>,
        job_id: String<64>,
        started_at_tick: u64,
    },
    WorkStop {
        operator_id: String<32>,
        job_id: String<64>,
        started_at_tick: u64,
        stopped_at_tick: u64,
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
    for ch in s.chars() {
        if out.push(ch).is_err() {
            break;
        }
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperatorSession {
    state: SessionState,
    events: Vec<SessionEvent, 8>,
}

impl Default for OperatorSession {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorSession {
    pub const fn new() -> Self {
        Self {
            state: SessionState::Idle,
            events: Vec::new(),
        }
    }

    pub fn state(&self) -> &SessionState {
        &self.state
    }

    pub fn pop_event(&mut self) -> Option<SessionEvent> {
        if self.events.is_empty() {
            None
        } else {
            Some(self.events.remove(0))
        }
    }

    pub fn clear(&mut self) {
        self.state = SessionState::Idle;
        self.events.clear();
    }

    fn enqueue(&mut self, event: SessionEvent) {
        if self.events.is_full() {
            let _ = self.events.remove(0);
        }
        let _ = self.events.push(event);
    }

    pub fn handle_rfid(&mut self, badge: &str, tick: u64) {
        let badge_id: String<32> = to_bounded_string(badge);
        match &self.state {
            SessionState::Idle => {
                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: badge_id,
                    tick,
                });
            }
            SessionState::Authenticated { operator_id } => {
                let old_op = operator_id.clone();
                if badge_id == old_op {
                    self.state = SessionState::Idle;
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                } else {
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        tick,
                    });
                }
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_tick,
            } => {
                let old_op = operator_id.clone();
                let active_job = job_id.clone();
                let start_tick = *started_at_tick;
                let duration_ms = tick
                    .saturating_sub(start_tick)
                    .saturating_mul(crate::POLL_TIMEOUT_MS as u64);

                self.enqueue(SessionEvent::WorkStop {
                    operator_id: old_op.clone(),
                    job_id: active_job,
                    started_at_tick: start_tick,
                    stopped_at_tick: tick,
                    duration_ms,
                });

                if badge_id == old_op {
                    self.state = SessionState::Idle;
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                } else {
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        tick,
                    });
                }
            }
        }
    }

    pub fn handle_barcode(&mut self, code: &str, tick: u64) -> Result<(), SessionRejectReason> {
        let code_id: String<64> = to_bounded_string(code);
        match &self.state {
            SessionState::Idle => Err(SessionRejectReason::NotAuthenticated),
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_tick: tick,
                };
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_tick: tick,
                });
                Ok(())
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_tick,
            } => {
                if code_id == *job_id {
                    let op_id = operator_id.clone();
                    let active_job = job_id.clone();
                    let start_tick = *started_at_tick;
                    let duration_ms = tick
                        .saturating_sub(start_tick)
                        .saturating_mul(crate::POLL_TIMEOUT_MS as u64);

                    self.state = SessionState::Authenticated {
                        operator_id: op_id.clone(),
                    };
                    self.enqueue(SessionEvent::WorkStop {
                        operator_id: op_id,
                        job_id: active_job,
                        started_at_tick: start_tick,
                        stopped_at_tick: tick,
                        duration_ms,
                    });
                    Ok(())
                } else {
                    Err(SessionRejectReason::JobMismatch)
                }
            }
        }
    }


    pub fn force_authenticate(&mut self, badge: &str, tick: u64) -> bool {
        let badge_id: String<32> = to_bounded_string(badge);
        match &self.state {
            SessionState::Idle => {
                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: badge_id,
                    tick,
                });
                true
            }
            SessionState::Authenticated { operator_id } => {
                if *operator_id == badge_id {
                    false
                } else {
                    let old_op = operator_id.clone();
                    self.state = SessionState::Authenticated {
                        operator_id: badge_id.clone(),
                    };
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        tick,
                    });
                    true
                }
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_tick,
            } => {
                let old_op = operator_id.clone();
                let active_job = job_id.clone();
                let start_tick = *started_at_tick;
                let duration_ms = tick
                    .saturating_sub(start_tick)
                    .saturating_mul(crate::POLL_TIMEOUT_MS as u64);

                self.state = SessionState::Authenticated {
                    operator_id: badge_id.clone(),
                };
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: old_op.clone(),
                    job_id: active_job,
                    started_at_tick: start_tick,
                    stopped_at_tick: tick,
                    duration_ms,
                });
                if old_op != badge_id {
                    self.enqueue(SessionEvent::OperatorLogout {
                        operator_id: old_op,
                        tick,
                    });
                    self.enqueue(SessionEvent::OperatorLogin {
                        operator_id: badge_id,
                        tick,
                    });
                }
                true
            }
        }
    }

    pub fn force_start_job(&mut self, default_badge: &str, code: &str, tick: u64) -> bool {
        let code_id: String<64> = to_bounded_string(code);
        match &self.state {
            SessionState::Idle => {
                let op_id: String<32> = to_bounded_string(default_badge);
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_tick: tick,
                };
                self.enqueue(SessionEvent::OperatorLogin {
                    operator_id: op_id.clone(),
                    tick,
                });
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_tick: tick,
                });
                true
            }
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.state = SessionState::Working {
                    operator_id: op_id.clone(),
                    job_id: code_id.clone(),
                    started_at_tick: tick,
                };
                self.enqueue(SessionEvent::WorkStart {
                    operator_id: op_id,
                    job_id: code_id,
                    started_at_tick: tick,
                });
                true
            }
            SessionState::Working { .. } => false,
        }
    }
    pub fn force_stop_job(&mut self, tick: u64) -> bool {
        match &self.state {
            SessionState::Working {
                operator_id,
                job_id,
                started_at_tick,
            } => {
                let op_id = operator_id.clone();
                let active_job = job_id.clone();
                let start_tick = *started_at_tick;
                let duration_ms = tick
                    .saturating_sub(start_tick)
                    .saturating_mul(crate::POLL_TIMEOUT_MS as u64);

                self.state = SessionState::Authenticated {
                    operator_id: op_id.clone(),
                };
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: op_id,
                    job_id: active_job,
                    started_at_tick: start_tick,
                    stopped_at_tick: tick,
                    duration_ms,
                });
                true
            }
            SessionState::Idle | SessionState::Authenticated { .. } => false,
        }
    }

    pub fn force_logout(&mut self, tick: u64) -> bool {
        match &self.state {
            SessionState::Idle => false,
            SessionState::Authenticated { operator_id } => {
                let op_id = operator_id.clone();
                self.state = SessionState::Idle;
                self.enqueue(SessionEvent::OperatorLogout {
                    operator_id: op_id,
                    tick,
                });
                true
            }
            SessionState::Working {
                operator_id,
                job_id,
                started_at_tick,
            } => {
                let op_id = operator_id.clone();
                let active_job = job_id.clone();
                let start_tick = *started_at_tick;
                let duration_ms = tick
                    .saturating_sub(start_tick)
                    .saturating_mul(crate::POLL_TIMEOUT_MS as u64);

                self.state = SessionState::Idle;
                self.enqueue(SessionEvent::WorkStop {
                    operator_id: op_id.clone(),
                    job_id: active_job,
                    started_at_tick: start_tick,
                    stopped_at_tick: tick,
                    duration_ms,
                });
                self.enqueue(SessionEvent::OperatorLogout {
                    operator_id: op_id,
                    tick,
                });
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s32(val: &str) -> String<32> {
        to_bounded_string(val)
    }

    fn s64(val: &str) -> String<64> {
        to_bounded_string(val)
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
        assert_eq!(session.pop_event(), None);
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
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32("OP-1"),
                tick: 10
            })
        );
        assert_eq!(session.pop_event(), None);

        // 2. Scan barcode -> Working
        assert_eq!(session.handle_barcode("JOB-42", 20), Ok(()));
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-42"),
                started_at_tick: 20,
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStart {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-42"),
                started_at_tick: 20,
            })
        );
        assert_eq!(session.pop_event(), None);

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
                started_at_tick: 20,
            }
        );
        assert_eq!(session.pop_event(), None);

        // 4. Scan matching barcode -> WorkStop, returns to Authenticated
        assert_eq!(session.handle_barcode("JOB-42", 50), Ok(()));
        let expected_duration = (50 - 20) * (crate::POLL_TIMEOUT_MS as u64);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-1")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-42"),
                started_at_tick: 20,
                stopped_at_tick: 50,
                duration_ms: expected_duration,
            })
        );
        assert_eq!(session.pop_event(), None);

        // 5. Scan same RFID -> OperatorLogout, returns to Idle
        session.handle_rfid("OP-1", 60);
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-1"),
                tick: 60,
            })
        );
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn different_rfid_switches_operator_when_authenticated() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 1);
        let _ = session.pop_event();

        session.handle_rfid("OP-B", 5);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-B")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-A"),
                tick: 5,
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32("OP-B"),
                tick: 5,
            })
        );
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn same_rfid_while_working_auto_stops_and_logs_out() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 10);
        assert_eq!(session.handle_barcode("JOB-1", 15), Ok(()));
        let _ = session.pop_event();
        let _ = session.pop_event();

        session.handle_rfid("OP-A", 35);
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-A"),
                job_id: s64("JOB-1"),
                started_at_tick: 15,
                stopped_at_tick: 35,
                duration_ms: 20 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-A"),
                tick: 35,
            })
        );
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn different_rfid_while_working_auto_stops_and_switches_operator() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 10);
        assert_eq!(session.handle_barcode("JOB-1", 20), Ok(()));
        let _ = session.pop_event();
        let _ = session.pop_event();

        session.handle_rfid("OP-B", 25);
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-B")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-A"),
                job_id: s64("JOB-1"),
                started_at_tick: 20,
                stopped_at_tick: 25,
                duration_ms: 5 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-A"),
                tick: 25,
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32("OP-B"),
                tick: 25,
            })
        );
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn clear_resets_state_and_events() {
        let mut session = OperatorSession::new();
        session.handle_rfid("OP-A", 1);
        assert_eq!(session.handle_barcode("JOB-1", 2), Ok(()));
        session.clear();
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn force_stop_job_transitions_working_to_authenticated() {
        let mut session = OperatorSession::new();
        assert!(!session.force_stop_job(10));

        session.handle_rfid("OP-1", 10);
        let _ = session.pop_event();
        assert!(!session.force_stop_job(15));

        assert_eq!(session.handle_barcode("JOB-55", 20), Ok(()));
        let _ = session.pop_event();

        assert!(session.force_stop_job(30));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-1")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-1"),
                job_id: s64("JOB-55"),
                started_at_tick: 20,
                stopped_at_tick: 30,
                duration_ms: 10 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(session.pop_event(), None);
    }

    #[test]
    fn force_logout_from_idle_authenticated_and_working() {
        let mut session = OperatorSession::new();
        assert!(!session.force_logout(5));

        // From Authenticated -> Idle
        session.handle_rfid("OP-1", 10);
        let _ = session.pop_event();
        assert!(session.force_logout(15));
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-1"),
                tick: 15,
            })
        );
        assert_eq!(session.pop_event(), None);

        // From Working -> WorkStop + OperatorLogout -> Idle
        session.handle_rfid("OP-2", 20);
        assert_eq!(session.handle_barcode("JOB-77", 25), Ok(()));
        let _ = session.pop_event();
        let _ = session.pop_event();

        assert!(session.force_logout(40));
        assert_eq!(session.state(), &SessionState::Idle);
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-2"),
                job_id: s64("JOB-77"),
                started_at_tick: 25,
                stopped_at_tick: 40,
                duration_ms: 15 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-2"),
                tick: 40,
            })
        );
        assert_eq!(session.pop_event(), None);
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
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32(DUMMY_OPERATOR_ID),
                tick: 5,
            })
        );
        assert_eq!(session.pop_event(), None);

        // 2. Already Authenticated with same badge -> no-op
        assert!(!session.force_authenticate(DUMMY_OPERATOR_ID, 10));
        assert_eq!(session.pop_event(), None);

        // 3. Authenticated with different badge -> switches operator
        assert!(session.force_authenticate("OP-2", 12));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-2")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32(DUMMY_OPERATOR_ID),
                tick: 12,
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32("OP-2"),
                tick: 12,
            })
        );
        assert_eq!(session.pop_event(), None);

        // 4. From Working with same operator -> stops job and stays Authenticated
        assert_eq!(session.handle_barcode("JOB-1", 20), Ok(()));
        let _ = session.pop_event();
        assert!(session.force_authenticate("OP-2", 30));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32("OP-2")
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-2"),
                job_id: s64("JOB-1"),
                started_at_tick: 20,
                stopped_at_tick: 30,
                duration_ms: 10 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(session.pop_event(), None);

        // 5. From Working with different operator -> stops job and switches operator
        assert_eq!(session.handle_barcode("JOB-2", 40), Ok(()));
        let _ = session.pop_event();
        assert!(session.force_authenticate(DUMMY_OPERATOR_ID, 50));
        assert_eq!(
            session.state(),
            &SessionState::Authenticated {
                operator_id: s32(DUMMY_OPERATOR_ID)
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStop {
                operator_id: s32("OP-2"),
                job_id: s64("JOB-2"),
                started_at_tick: 40,
                stopped_at_tick: 50,
                duration_ms: 10 * (crate::POLL_TIMEOUT_MS as u64),
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogout {
                operator_id: s32("OP-2"),
                tick: 50,
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32(DUMMY_OPERATOR_ID),
                tick: 50,
            })
        );
        assert_eq!(session.pop_event(), None);
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
                started_at_tick: 10,
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::OperatorLogin {
                operator_id: s32(DUMMY_OPERATOR_ID),
                tick: 10,
            })
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStart {
                operator_id: s32(DUMMY_OPERATOR_ID),
                job_id: s64(DUMMY_JOB_ID),
                started_at_tick: 10,
            })
        );
        assert_eq!(session.pop_event(), None);

        // 2. While Working -> returns false (no-op)
        assert!(!session.force_start_job(DUMMY_OPERATOR_ID, "OTHER_JOB", 15));
        assert_eq!(session.pop_event(), None);

        // 3. From Authenticated -> starts job for current operator
        session.clear();
        session.handle_rfid("REAL-OP", 20);
        let _ = session.pop_event();
        assert!(session.force_start_job(DUMMY_OPERATOR_ID, DUMMY_JOB_ID, 25));
        assert_eq!(
            session.state(),
            &SessionState::Working {
                operator_id: s32("REAL-OP"),
                job_id: s64(DUMMY_JOB_ID),
                started_at_tick: 25,
            }
        );
        assert_eq!(
            session.pop_event(),
            Some(SessionEvent::WorkStart {
                operator_id: s32("REAL-OP"),
                job_id: s64(DUMMY_JOB_ID),
                started_at_tick: 25,
            })
        );
        assert_eq!(session.pop_event(), None);
    }
}
