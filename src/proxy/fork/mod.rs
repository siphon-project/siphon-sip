//! Proxy forking and response aggregation — RFC 3261 §16.7.
//!
//! When a Python script calls `request.fork(targets)`, the proxy creates one
//! client transaction per target.  The [`ForkAggregator`] collects responses
//! from all branches and decides what to forward upstream.
//!
//! # Parallel strategy (default)
//!
//! All branches are started simultaneously.  The aggregator follows RFC 3261
//! §16.7 step 3:
//!
//! - **First 2xx** → forward to UAC, CANCEL all other pending branches.
//! - **6xx received** → forward immediately, CANCEL all other branches.
//! - **All branches failed** → forward the "best" error response.
//!   Priority: 6xx > 5xx > 4xx; within a class, highest code wins.
//! - **Provisional (1xx)** → forward the first 100 Trying; forward every
//!   180 Ringing / 183 Session Progress from any branch.
//!
//! # Sequential strategy
//!
//! Branches are tried one at a time in the order provided (typically sorted by
//! `Contact` q-value descending).  On a non-2xx final response, the next branch
//! is attempted.  A 2xx or 6xx terminates the sequence immediately.

use crate::sip::uri::SipUri;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// Which forking behaviour the proxy should use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ForkStrategy {
    /// Send to all targets simultaneously; first 2xx wins.
    #[default]
    Parallel,
    /// Try targets one at a time; move to next on failure.
    Sequential,
}

/// Per-branch state in a forked request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BranchState {
    /// Branch created but INVITE not yet sent.
    Pending,
    /// INVITE sent, no response yet.
    Trying,
    /// A provisional response (1xx) was received.
    Proceeding(u16),
    /// A final response was received.
    Completed(u16),
    /// Branch was cancelled (e.g. another branch won with 2xx).
    Cancelled,
}

/// Where a branch's final response came from.
///
/// A proxy answers a branch itself when it cannot be completed — a transport
/// error on forwarding (RFC 3261 §16.9 → 503) or a client transaction timeout
/// (§16.7 step 2 → 408).  Those are statements about *this proxy's* plumbing,
/// not about the callee, so when a sibling branch reached a real endpoint its
/// answer is the one the caller wants to hear.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResponseOrigin {
    /// A real response, from the downstream peer.
    #[default]
    Peer,
    /// Synthesized by this proxy because the branch never got an answer.
    Local,
}

/// A single branch of a forked request.
#[derive(Debug, Clone)]
pub struct ForkBranch {
    /// The target URI for this branch.
    pub target: SipUri,
    /// Current state of this branch.
    pub state: BranchState,
    /// Where this branch's final response came from.  Set to
    /// [`Local`](ResponseOrigin::Local) by [`ForkAggregator::mark_local_failure`]
    /// before the proxy injects its own response for the branch.
    pub origin: ResponseOrigin,
}

/// Action the proxy core should take after a branch response arrives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ForkAction {
    /// A 2xx was received — forward it upstream and CANCEL all other branches.
    Forward2xx,
    /// A 6xx was received — forward it upstream and CANCEL all other branches.
    Forward6xx,
    /// Waiting for more branches to complete (parallel mode).
    ContinueWaiting,
    /// All branches failed — forward the best error response upstream.
    ForwardBestError(u16),
    /// Sequential mode: start the branch at the given index.
    TryNext(usize),
    /// Forward a provisional response upstream (180/183 from any branch).
    ForwardProvisional(u16),
}

/// Aggregates responses from multiple forked branches.
///
/// Created when the Python script calls `request.fork(targets)`.  The proxy
/// core feeds branch responses into [`on_branch_response`](Self::on_branch_response)
/// and acts on the returned [`ForkAction`].
#[derive(Debug)]
pub struct ForkAggregator {
    /// All branches for this fork.
    pub branches: Vec<ForkBranch>,
    /// Forking strategy.
    pub strategy: ForkStrategy,
    /// Whether we already forwarded a 100 Trying upstream.
    sent_100: bool,
    /// Whether a 2xx (or 6xx) has already been forwarded — guards
    /// against the parallel-fork race where a CANCELled branch's
    /// already-in-flight 200 OK arrives after another branch's 200
    /// already won.  Without this flag the aggregator would happily
    /// say `Forward2xx` for every 2xx received, the proxy would
    /// forward both copies, and the UAC would see two 200s for one
    /// INVITE (the documented Proxy/TCP ~0.025 % FailedCall rate).
    final_forwarded: bool,
}

impl ForkAggregator {
    /// Create a new aggregator for the given targets and strategy.
    pub fn new(targets: Vec<SipUri>, strategy: ForkStrategy) -> Self {
        let branches = targets
            .into_iter()
            .map(|target| ForkBranch {
                target,
                state: BranchState::Pending,
                origin: ResponseOrigin::Peer,
            })
            .collect();

        Self {
            branches,
            strategy,
            sent_100: false,
            final_forwarded: false,
        }
    }

    /// Number of branches.
    pub fn branch_count(&self) -> usize {
        self.branches.len()
    }

    /// Returns `true` when every branch has reached a terminal state
    /// ([`Completed`](BranchState::Completed) or [`Cancelled`](BranchState::Cancelled)).
    pub fn is_complete(&self) -> bool {
        self.branches.iter().all(|branch| {
            matches!(
                branch.state,
                BranchState::Completed(_) | BranchState::Cancelled
            )
        })
    }

    /// Mark a branch as [`Trying`](BranchState::Trying) (INVITE sent).
    pub fn mark_trying(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].state = BranchState::Trying;
        }
    }

    /// Mark a branch as [`Cancelled`](BranchState::Cancelled).
    pub fn mark_cancelled(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].state = BranchState::Cancelled;
        }
    }

    /// Record that the *next* final response on this branch is one the proxy
    /// synthesized for itself, not one a peer sent.
    ///
    /// Called immediately before the proxy injects a 503 (transport error,
    /// RFC 3261 §16.9) or a 408 (transaction timeout, §16.7 step 2) for a
    /// branch that will never be answered from the network, so
    /// [`best_error`](Self::best_error) can keep it from outranking a real
    /// answer from a sibling branch.
    pub fn mark_local_failure(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].origin = ResponseOrigin::Local;
        }
    }

    /// Feed a response from branch `index` into the aggregator.
    ///
    /// Returns the [`ForkAction`] the proxy core should take.
    pub fn on_branch_response(&mut self, index: usize, status_code: u16) -> ForkAction {
        if index >= self.branches.len() {
            return ForkAction::ContinueWaiting;
        }

        // Provisional (1xx)
        if (100..200).contains(&status_code) {
            self.branches[index].state = BranchState::Proceeding(status_code);
            if status_code == 100 {
                if self.sent_100 {
                    return ForkAction::ContinueWaiting;
                }
                self.sent_100 = true;
            }
            // Forward 100 (first only), 180, 183 from any branch
            return ForkAction::ForwardProvisional(status_code);
        }

        // Final response
        self.branches[index].state = BranchState::Completed(status_code);

        // 2xx — immediate win.  If a final has already been forwarded
        // upstream, drop this duplicate (race: branch B's 200 was in
        // flight when branch A's 200 won and CANCELs were sent; on TCP
        // both 200s reach the proxy intact).
        if (200..300).contains(&status_code) {
            if self.final_forwarded {
                return ForkAction::ContinueWaiting;
            }
            self.final_forwarded = true;
            return ForkAction::Forward2xx;
        }

        // 6xx — immediate termination.  Same dedup as 2xx.
        if status_code >= 600 {
            if self.final_forwarded {
                return ForkAction::ContinueWaiting;
            }
            self.final_forwarded = true;
            return ForkAction::Forward6xx;
        }

        // 3xx–5xx — depends on strategy.  In all cases, if a final
        // response was already forwarded upstream (e.g. a 2xx won
        // earlier and other branches are completing with errors after
        // the CANCEL races), drop the late one to avoid the duplicate-
        // 2xx-or-error problem upstream.
        if self.final_forwarded {
            return ForkAction::ContinueWaiting;
        }
        match self.strategy {
            ForkStrategy::Parallel => {
                if self.is_complete() {
                    self.final_forwarded = true;
                    ForkAction::ForwardBestError(self.best_error())
                } else {
                    ForkAction::ContinueWaiting
                }
            }
            ForkStrategy::Sequential => {
                // Find the next pending branch
                if let Some(next) = self.next_pending_branch() {
                    ForkAction::TryNext(next)
                } else {
                    self.final_forwarded = true;
                    ForkAction::ForwardBestError(self.best_error())
                }
            }
        }
    }

    /// The "best" error code among completed branches.
    ///
    /// **A real answer always beats one this proxy invented.** A branch the
    /// proxy failed locally (transport error → 503, timeout → 408) says
    /// something about our plumbing; a branch that reached an endpoint and came
    /// back `486 Busy Here` says something about the callee, and that is what
    /// the caller needs to hear. Without this rule the class ordering below
    /// would hand a 503 (class 5xx) the win over a 486 (class 4xx) and the
    /// caller would be told "Server Internal Error" while a phone was ringing
    /// busy next to it.
    ///
    /// Within whichever set is chosen: 6xx > 5xx > 4xx > 3xx, highest code
    /// first inside a class.
    fn best_error(&self) -> u16 {
        let completed = |origin: ResponseOrigin| {
            self.branches
                .iter()
                .filter(move |branch| branch.origin == origin)
                .filter_map(|branch| match branch.state {
                    BranchState::Completed(code) if code >= 300 => Some(code),
                    _ => None,
                })
                .max_by(|a, b| error_priority(*a).cmp(&error_priority(*b)))
        };
        completed(ResponseOrigin::Peer)
            .or_else(|| completed(ResponseOrigin::Local))
            .unwrap_or(500)
    }

    /// Index of the next [`Pending`](BranchState::Pending) branch, if any.
    fn next_pending_branch(&self) -> Option<usize> {
        self.branches
            .iter()
            .position(|branch| branch.state == BranchState::Pending)
    }
}

/// Priority score for error response codes.
///
/// Higher score = higher priority when selecting the "best" error to forward.
/// 6xx class beats 5xx, 5xx beats 4xx, 4xx beats 3xx.
/// Within a class, higher code wins.
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
mod tests;
