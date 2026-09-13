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
//! - **All branches failed** → forward the best failure (§16.7 step 6, see
//!   [`crate::sip::best_response`]): the lowest class present, preferring
//!   401/407/415/420/484 within 4xx, with 503 below every other 5xx.  The
//!   chosen branch's own response is forwarded, and a 401/407 carries every
//!   challenge from the other 401/407 branches (step 7).
//! - **Provisional (1xx)** → forward the first 100 Trying; forward every
//!   180 Ringing / 183 Session Progress from any branch.
//!
//! # Sequential strategy
//!
//! Branches are tried one at a time in the order provided (typically sorted by
//! `Contact` q-value descending).  On a non-2xx final response, the next branch
//! is attempted.  A 2xx or 6xx terminates the sequence immediately.

use crate::sip::best_response::ResponseRank;
use crate::sip::message::SipMessage;
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
    /// This branch's final failure as received, kept until the fork settles so
    /// the chosen one can be forwarded with its own headers.  Only fed through
    /// [`ForkAggregator::on_response`].
    response: Option<SipMessage>,
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
    /// All branches failed — forward the best failure upstream.  Carries the
    /// chosen branch's status as received; its response, when one was fed, is
    /// in [`ForkAggregator::take_best_response`].
    ForwardBestError(u16),
    /// Sequential mode: start the branch at the given index.
    TryNext(usize),
    /// Forward a provisional response upstream (180/183 from any branch).
    ForwardProvisional(u16),
}

/// Aggregates responses from multiple forked branches.
///
/// Created when the Python script calls `request.fork(targets)`.  The proxy
/// core feeds branch responses into [`on_response`](Self::on_response) and acts
/// on the returned [`ForkAction`].
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
    /// The response chosen when the fork settled on
    /// [`ForwardBestError`](ForkAction::ForwardBestError), until the proxy
    /// takes it.
    best_response: Option<SipMessage>,
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
                response: None,
            })
            .collect();

        Self {
            branches,
            strategy,
            sent_100: false,
            final_forwarded: false,
            best_response: None,
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
    /// [`best_branch`](Self::best_branch) can put a real answer from a sibling
    /// branch ahead of it.
    pub fn mark_local_failure(&mut self, index: usize) {
        if index < self.branches.len() {
            self.branches[index].origin = ResponseOrigin::Local;
        }
    }

    /// Feed `response`, branch `index`'s response with status `status_code`,
    /// into the aggregator.
    ///
    /// Same as [`on_branch_response`](Self::on_branch_response), except that a
    /// final failure is kept: when the fork settles on
    /// [`ForwardBestError`](ForkAction::ForwardBestError), the chosen branch's
    /// response is ready in [`take_best_response`](Self::take_best_response).
    pub fn on_response(
        &mut self,
        index: usize,
        status_code: u16,
        response: &SipMessage,
    ) -> ForkAction {
        // Nothing arriving after a final has gone upstream can be chosen, so
        // nothing is kept for it.
        if status_code >= 300 && !self.final_forwarded {
            if let Some(branch) = self.branches.get_mut(index) {
                branch.response = Some(response.clone());
            }
        }
        self.on_branch_response(index, status_code)
    }

    /// Feed a response status from branch `index` into the aggregator.
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
            self.settle();
            return ForkAction::Forward2xx;
        }

        // 6xx — immediate termination.  Same dedup as 2xx.
        if status_code >= 600 {
            if self.final_forwarded {
                return ForkAction::ContinueWaiting;
            }
            self.settle();
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
                    self.settle_on_best_failure()
                } else {
                    ForkAction::ContinueWaiting
                }
            }
            ForkStrategy::Sequential => {
                // Find the next pending branch
                if let Some(next) = self.next_pending_branch() {
                    ForkAction::TryNext(next)
                } else {
                    self.settle_on_best_failure()
                }
            }
        }
    }

    /// The response chosen when the fork settled on
    /// [`ForwardBestError`](ForkAction::ForwardBestError), with the step 7
    /// challenges added.  `None` before that, once taken, or when the chosen
    /// branch was fed by status alone.
    pub fn take_best_response(&mut self) -> Option<SipMessage> {
        self.best_response.take()
    }

    /// A final response is going upstream, so nothing kept for the others can
    /// be forwarded any more.
    fn settle(&mut self) {
        self.final_forwarded = true;
        for branch in &mut self.branches {
            branch.response = None;
        }
    }

    /// Settle on the best failure across the branches (RFC 3261 §16.7 step 6).
    fn settle_on_best_failure(&mut self) -> ForkAction {
        let best = self.best_branch();
        let status_code = best
            .and_then(|index| match self.branches[index].state {
                BranchState::Completed(code) => Some(code),
                _ => None,
            })
            .unwrap_or(500);
        self.best_response = best.and_then(|index| {
            let mut response = self.branches[index].response.take()?;
            if matches!(status_code, 401 | 407) {
                self.collect_challenges(index, &mut response);
            }
            Some(response)
        });
        self.settle();
        ForkAction::ForwardBestError(status_code)
    }

    /// Index of the best failed branch.
    ///
    /// The ranking is RFC 3261 §16.7 step 6 ([`crate::sip::best_response`]):
    /// the lowest class wins, and a 408 from a timed-out branch (§16.8)
    /// competes like any other 4xx.  Within what those rules leave level, **a
    /// real answer beats one this proxy invented**: a branch the proxy failed
    /// itself (transport error → 503, timeout → 408) says something about our
    /// plumbing, and a sibling that reached an endpoint and came back `404`
    /// says something about the callee, which is what the caller needs to hear.
    /// The preference never crosses a class: a peer's 500 still loses to a
    /// local 408.
    fn best_branch(&self) -> Option<usize> {
        self.branches
            .iter()
            .enumerate()
            .filter_map(|(index, branch)| match branch.state {
                BranchState::Completed(code) if code >= 300 => Some((
                    index,
                    ResponseRank::preferring(code, branch.origin == ResponseOrigin::Peer),
                )),
                _ => None,
            })
            .max_by_key(|(_, rank)| *rank)
            .map(|(index, _)| index)
    }

    /// RFC 3261 §16.7 step 7: a forwarded 401 or 407 carries every
    /// `WWW-Authenticate` and `Proxy-Authenticate` value from every other 401
    /// and 407 in the response context, unmodified, so the caller can answer
    /// each realm in one retry instead of discovering them one at a time.
    fn collect_challenges(&self, chosen: usize, response: &mut SipMessage) {
        for (index, branch) in self.branches.iter().enumerate() {
            if index == chosen || !matches!(branch.state, BranchState::Completed(401 | 407)) {
                continue;
            }
            let Some(other) = branch.response.as_ref() else {
                continue;
            };
            for name in ["WWW-Authenticate", "Proxy-Authenticate"] {
                for value in other.headers.get_all(name).into_iter().flatten() {
                    response.headers.add(name, value.clone());
                }
            }
        }
    }

    /// Index of the next [`Pending`](BranchState::Pending) branch, if any.
    fn next_pending_branch(&self) -> Option<usize> {
        self.branches
            .iter()
            .position(|branch| branch.state == BranchState::Pending)
    }

    /// Number of branch responses currently kept (leak-test accessor).
    #[cfg(test)]
    fn kept_response_count(&self) -> usize {
        self.branches
            .iter()
            .filter(|branch| branch.response.is_some())
            .count()
    }
}

#[cfg(test)]
mod tests;
