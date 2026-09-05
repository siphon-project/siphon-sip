//! B2BUA forking — parallel and sequential call attempts.
//!
//! When a Python script calls `call.fork(targets, strategy, timeout)`, the
//! B2BUA creates one outbound INVITE leg per target.  The [`B2buaFork`]
//! tracks each leg and determines when the fork has settled (one leg answered,
//! all failed, or 6xx received).
//!
//! # Parallel strategy
//!
//! All B legs are dialled simultaneously.  The first to answer (200 OK) wins;
//! all other legs receive CANCEL.  This is the "ring all" pattern used for
//! residential multi-device and call-centre overflow.
//!
//! # Sequential strategy
//!
//! B legs are tried one at a time in the order provided.  If the current leg
//! fails or times out, the next leg is attempted.  This is the "hunt group"
//! or "serial forking" pattern.

use crate::sip::uri::SipUri;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Forking strategy for B2BUA calls.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkStrategy {
    /// Ring all targets simultaneously; first answer wins.
    #[default]
    Parallel,
    /// Try targets one at a time in order.
    Sequential,
}

/// State of a single B leg in a forked call.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegState {
    /// INVITE not yet sent.
    Pending,
    /// INVITE sent, waiting for response.
    Trying,
    /// Received 180 Ringing or 183 Session Progress.
    Ringing,
    /// Received 200 OK — this leg won.
    Answered,
    /// Received a final error response.
    Failed(u16),
    /// CANCEL sent (another leg won or 6xx received).
    Cancelled,
}

/// A single B leg in a forked B2BUA call.
#[derive(Debug, Clone)]
pub struct ForkLeg {
    /// Destination URI for this leg.
    pub target: SipUri,
    /// Current state of this leg.
    pub state: LegState,
    /// Per-leg INVITE timeout in seconds.
    pub timeout_secs: u32,
}

/// Action the B2BUA core should take after a leg event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkAction {
    /// A leg answered — cancel all other legs, bridge the call.
    LegAnswered(usize),
    /// A 6xx was received — cancel all legs, reject call.
    Reject6xx(u16),
    /// Waiting for more legs to settle (parallel mode).
    ContinueWaiting,
    /// All legs failed — reject call with best error code.
    AllFailed(u16),
    /// Sequential mode: try the leg at the given index.
    TryNext(usize),
    /// A leg is ringing — forward 180 to A leg.
    Ringing(usize),
}

/// Manages multiple B legs for a forked B2BUA call.
///
/// Created when the Python script calls `call.fork(targets, strategy, timeout)`.
/// The B2BUA core feeds leg events into [`on_leg_response`](Self::on_leg_response)
/// and acts on the returned [`ForkAction`].
#[derive(Debug)]
pub struct B2buaFork {
    /// All B legs.
    pub legs: Vec<ForkLeg>,
    /// Forking strategy.
    pub strategy: ForkStrategy,
    /// Index of the winning leg (if any).
    pub winner: Option<usize>,
    /// Whether we already forwarded a ringing indication to the A leg.
    sent_ringing: bool,
}

impl B2buaFork {
    /// Create a new fork with the given targets, strategy, and per-leg timeout.
    pub fn new(targets: Vec<SipUri>, strategy: ForkStrategy, timeout_secs: u32) -> Self {
        let legs = targets
            .into_iter()
            .map(|target| ForkLeg {
                target,
                state: LegState::Pending,
                timeout_secs,
            })
            .collect();

        Self {
            legs,
            strategy,
            winner: None,
            sent_ringing: false,
        }
    }

    /// Number of legs.
    pub fn leg_count(&self) -> usize {
        self.legs.len()
    }

    /// Returns `true` when every leg has reached a terminal state.
    pub fn is_settled(&self) -> bool {
        self.legs.iter().all(|leg| {
            matches!(
                leg.state,
                LegState::Answered | LegState::Failed(_) | LegState::Cancelled
            )
        })
    }

    /// Mark a leg as [`Trying`](LegState::Trying) (INVITE sent).
    pub fn mark_trying(&mut self, index: usize) {
        if index < self.legs.len() {
            self.legs[index].state = LegState::Trying;
        }
    }

    /// Mark a leg as [`Cancelled`](LegState::Cancelled).
    pub fn mark_cancelled(&mut self, index: usize) {
        if index < self.legs.len() {
            self.legs[index].state = LegState::Cancelled;
        }
    }

    /// Feed a SIP response from leg `index` into the fork.
    ///
    /// Returns the [`ForkAction`] the B2BUA core should take.
    pub fn on_leg_response(&mut self, index: usize, status_code: u16) -> ForkAction {
        if index >= self.legs.len() {
            return ForkAction::ContinueWaiting;
        }

        // 180 / 183 — ringing
        if status_code == 180 || status_code == 183 {
            self.legs[index].state = LegState::Ringing;
            if !self.sent_ringing {
                self.sent_ringing = true;
                return ForkAction::Ringing(index);
            }
            return ForkAction::ContinueWaiting;
        }

        // Other provisional (100, etc.) — no action
        if (100..200).contains(&status_code) {
            return ForkAction::ContinueWaiting;
        }

        // 200 OK — this leg wins
        if (200..300).contains(&status_code) {
            self.legs[index].state = LegState::Answered;
            self.winner = Some(index);
            return ForkAction::LegAnswered(index);
        }

        // 6xx — immediate rejection
        if status_code >= 600 {
            self.legs[index].state = LegState::Failed(status_code);
            return ForkAction::Reject6xx(status_code);
        }

        // 3xx–5xx error
        self.legs[index].state = LegState::Failed(status_code);

        match self.strategy {
            ForkStrategy::Parallel => {
                if self.is_settled() {
                    ForkAction::AllFailed(self.best_error())
                } else {
                    ForkAction::ContinueWaiting
                }
            }
            ForkStrategy::Sequential => {
                if let Some(next) = self.next_pending_leg() {
                    ForkAction::TryNext(next)
                } else {
                    ForkAction::AllFailed(self.best_error())
                }
            }
        }
    }

    /// The highest-priority error code among failed legs.
    ///
    /// Same priority as proxy: 6xx > 5xx > 4xx > 3xx, highest code wins.
    fn best_error(&self) -> u16 {
        self.legs
            .iter()
            .filter_map(|leg| match leg.state {
                LegState::Failed(code) => Some(code),
                _ => None,
            })
            .max_by(|a, b| error_priority(*a).cmp(&error_priority(*b)))
            .unwrap_or(500)
    }

    /// Index of the next [`Pending`](LegState::Pending) leg, if any.
    fn next_pending_leg(&self) -> Option<usize> {
        self.legs
            .iter()
            .position(|leg| leg.state == LegState::Pending)
    }
}

/// Priority score for error response codes (shared logic with proxy fork).
fn error_priority(code: u16) -> u32 {
    let class_weight = match code {
        600..=699 => 3000,
        500..=599 => 2000,
        400..=499 => 1000,
        300..=399 => 0,
        _ => 0,
    };
    class_weight + code as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sip::uri::{Scheme, SipUri};

    fn uri(user: &str, host: &str) -> SipUri {
        SipUri {
            scheme: Scheme::Sip,
            user: Some(user.to_string()),
            host: host.to_string(),
            port: None,
            params: Vec::new(),
            headers: Vec::new(),
            user_params: Vec::new(),
        }
    }

    fn make_fork(count: usize, strategy: ForkStrategy) -> B2buaFork {
        let targets: Vec<SipUri> = (0..count)
            .map(|index| uri(&format!("agent{}", index), "pbx.example.com"))
            .collect();
        B2buaFork::new(targets, strategy, 30)
    }

    // -------------------------------------------------------------------
    // Parallel forking
    // -------------------------------------------------------------------

    #[test]
    fn test_parallel_first_answer_wins() {
        let mut fork = make_fork(3, ForkStrategy::Parallel);
        for index in 0..3 {
            fork.mark_trying(index);
        }

        let action = fork.on_leg_response(1, 200);
        assert_eq!(action, ForkAction::LegAnswered(1));
        assert_eq!(fork.winner, Some(1));
    }

    #[test]
    fn test_parallel_6xx_rejects_immediately() {
        let mut fork = make_fork(3, ForkStrategy::Parallel);
        for index in 0..3 {
            fork.mark_trying(index);
        }

        let action = fork.on_leg_response(0, 603);
        assert_eq!(action, ForkAction::Reject6xx(603));
    }

    #[test]
    fn test_parallel_all_fail() {
        let mut fork = make_fork(3, ForkStrategy::Parallel);
        for index in 0..3 {
            fork.mark_trying(index);
        }

        fork.on_leg_response(0, 486);
        fork.on_leg_response(1, 404);
        let action = fork.on_leg_response(2, 503);
        assert_eq!(action, ForkAction::AllFailed(503));
    }

    #[test]
    fn test_parallel_ringing_forwarded_once() {
        let mut fork = make_fork(3, ForkStrategy::Parallel);
        for index in 0..3 {
            fork.mark_trying(index);
        }

        // First 180 → forward
        let action = fork.on_leg_response(0, 180);
        assert_eq!(action, ForkAction::Ringing(0));

        // Second 180 → suppress
        let action = fork.on_leg_response(1, 180);
        assert_eq!(action, ForkAction::ContinueWaiting);
    }

    #[test]
    fn test_parallel_100_ignored() {
        let mut fork = make_fork(2, ForkStrategy::Parallel);
        for index in 0..2 {
            fork.mark_trying(index);
        }

        let action = fork.on_leg_response(0, 100);
        assert_eq!(action, ForkAction::ContinueWaiting);
    }

    // -------------------------------------------------------------------
    // Sequential forking
    // -------------------------------------------------------------------

    #[test]
    fn test_sequential_tries_next_on_failure() {
        let mut fork = make_fork(3, ForkStrategy::Sequential);
        fork.mark_trying(0);

        let action = fork.on_leg_response(0, 486);
        assert_eq!(action, ForkAction::TryNext(1));
    }

    #[test]
    fn test_sequential_answer_stops() {
        let mut fork = make_fork(3, ForkStrategy::Sequential);
        fork.mark_trying(0);

        let action = fork.on_leg_response(0, 200);
        assert_eq!(action, ForkAction::LegAnswered(0));
        assert_eq!(fork.winner, Some(0));
    }

    #[test]
    fn test_sequential_all_fail() {
        let mut fork = make_fork(3, ForkStrategy::Sequential);

        fork.mark_trying(0);
        let action = fork.on_leg_response(0, 404);
        assert_eq!(action, ForkAction::TryNext(1));

        fork.mark_trying(1);
        let action = fork.on_leg_response(1, 486);
        assert_eq!(action, ForkAction::TryNext(2));

        fork.mark_trying(2);
        let action = fork.on_leg_response(2, 503);
        assert_eq!(action, ForkAction::AllFailed(503));
    }

    // -------------------------------------------------------------------
    // Edge cases
    // -------------------------------------------------------------------

    #[test]
    fn test_single_leg_answer() {
        let mut fork = make_fork(1, ForkStrategy::Parallel);
        fork.mark_trying(0);

        let action = fork.on_leg_response(0, 200);
        assert_eq!(action, ForkAction::LegAnswered(0));
    }

    #[test]
    fn test_single_leg_failure() {
        let mut fork = make_fork(1, ForkStrategy::Parallel);
        fork.mark_trying(0);

        let action = fork.on_leg_response(0, 486);
        assert_eq!(action, ForkAction::AllFailed(486));
    }

    #[test]
    fn test_out_of_bounds_leg() {
        let mut fork = make_fork(2, ForkStrategy::Parallel);
        let action = fork.on_leg_response(99, 200);
        assert_eq!(action, ForkAction::ContinueWaiting);
    }

    #[test]
    fn test_is_settled() {
        let mut fork = make_fork(2, ForkStrategy::Parallel);
        assert!(!fork.is_settled());

        fork.mark_trying(0);
        fork.mark_trying(1);
        fork.on_leg_response(0, 200);
        assert!(!fork.is_settled());

        fork.mark_cancelled(1);
        assert!(fork.is_settled());
    }

    #[test]
    fn test_default_strategy_is_parallel() {
        assert_eq!(ForkStrategy::default(), ForkStrategy::Parallel);
    }
}
