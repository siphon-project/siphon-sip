//! Reply pipeline — determines which Python handlers to invoke when a
//! response arrives from a downstream branch.
//!
//! The proxy core loop will:
//! 1. Feed the response to [`ForkAggregator::on_branch_response`] to get a [`ForkAction`].
//! 2. Call [`ReplyPipeline::classify`] to determine which handlers apply.
//! 3. Invoke the handlers in priority order.
//! 4. Forward or suppress the response based on whether `reply.relay()` was called.

use crate::script::engine::HandlerKind;

/// Outcome of running reply handlers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyAction {
    /// Handler called `relay()` / `forward()` — proceed with forwarding.
    Forward,
    /// Handler returned without calling `relay()` / `forward()` — suppress.
    Suppress,
    /// No handler registered for this event — forward unchanged (default).
    NoHandler,
}

/// Classifies a proxy response to determine which Python handlers should run.
pub struct ReplyPipeline;

impl ReplyPipeline {
    /// Determine which handler kinds apply for a given proxy response.
    ///
    /// Returns handler kinds in priority order. The proxy core should invoke
    /// the first kind that has a registered handler and stop.
    ///
    /// Priority (highest first):
    /// 1. `ProxyRegisterReply` — if the request method is REGISTER
    /// 2. `ProxyFailure` — if all branches failed
    /// 3. `ProxyReply` — global reply handler (fallback)
    pub fn classify(request_method: &str, all_branches_failed: bool) -> Vec<HandlerKind> {
        let mut kinds = Vec::with_capacity(3);

        // REGISTER-specific reply handler takes priority.
        if request_method == "REGISTER" {
            kinds.push(HandlerKind::ProxyRegisterReply);
        }

        // Failure handler fires when all branches have failed.
        if all_branches_failed {
            kinds.push(HandlerKind::ProxyFailure);
        }

        // Global reply handler is always a candidate.
        kinds.push(HandlerKind::ProxyReply);

        kinds
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_200_yields_only_proxy_reply() {
        let kinds = ReplyPipeline::classify("INVITE", false);
        assert_eq!(kinds, vec![HandlerKind::ProxyReply]);
    }

    #[test]
    fn invite_180_yields_only_proxy_reply() {
        let kinds = ReplyPipeline::classify("INVITE", false);
        assert_eq!(kinds, vec![HandlerKind::ProxyReply]);
    }

    #[test]
    fn invite_all_failed_yields_failure_then_reply() {
        let kinds = ReplyPipeline::classify("INVITE", true);
        assert_eq!(
            kinds,
            vec![HandlerKind::ProxyFailure, HandlerKind::ProxyReply,]
        );
    }

    #[test]
    fn register_200_yields_register_reply_then_reply() {
        let kinds = ReplyPipeline::classify("REGISTER", false);
        assert_eq!(
            kinds,
            vec![HandlerKind::ProxyRegisterReply, HandlerKind::ProxyReply,]
        );
    }

    #[test]
    fn register_all_failed_yields_all_three() {
        let kinds = ReplyPipeline::classify("REGISTER", true);
        assert_eq!(
            kinds,
            vec![
                HandlerKind::ProxyRegisterReply,
                HandlerKind::ProxyFailure,
                HandlerKind::ProxyReply,
            ]
        );
    }

    #[test]
    fn subscribe_normal_yields_only_proxy_reply() {
        let kinds = ReplyPipeline::classify("SUBSCRIBE", false);
        assert_eq!(kinds, vec![HandlerKind::ProxyReply]);
    }

    #[test]
    fn options_failure_yields_failure_then_reply() {
        let kinds = ReplyPipeline::classify("OPTIONS", true);
        assert_eq!(
            kinds,
            vec![HandlerKind::ProxyFailure, HandlerKind::ProxyReply,]
        );
    }
}
