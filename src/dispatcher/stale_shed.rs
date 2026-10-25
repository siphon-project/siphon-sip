//! Age-based load shedding of inbound requests.
//!
//! Every inbound message is a job on the script executor, and under overload
//! those jobs queue. A request that waited long enough is not worth running:
//! the client's transaction gives up at Timer F (non-INVITE) or Timer B
//! (INVITE), 64·T1 = 32 s with the RFC 3261 default T1, and an answer that
//! leaves after that is wasted work, while the client has already retried
//! into the same queue. Under a re-REGISTER storm that is overload collapse:
//! the executor stays saturated answering requests nobody waits for any more.
//!
//! So when the dispatcher job picks up a request that queued past
//! [`STALE_REQUEST_BUDGET`], it answers `503 Service Unavailable` with a
//! `Retry-After` (RFC 3261 §21.5.4) and never runs the script, which turns a
//! timeout the client retries at once into an answer it backs off on
//! (RFC 3261 §21.5.4, RFC 3263 §4.3, RFC 5390 §5).
//!
//! What is shed, and what is not:
//!
//! - **Shed:** dialog-initiating and out-of-dialog requests, i.e. a request
//!   with no To tag: initial and refresh REGISTER, an initial INVITE or
//!   SUBSCRIBE, OPTIONS, MESSAGE, PUBLISH, an out-of-dialog REFER or NOTIFY.
//!   This is new work; refusing it is what relieves the queue.
//! - **ACK never:** no response to an ACK is allowed (RFC 3261 §17.1.1.3),
//!   and an ACK is cheap. It is handled before this check anyway.
//! - **CANCEL never:** the framework answers it itself (RFC 3261 §9.2), ahead
//!   of this check, and it is what releases a pending INVITE.
//! - **In-dialog requests never** (a To tag, and BYE whatever it carries): they
//!   are the cheap work that releases resources. A shed BYE leaves a dialog,
//!   its media and its charging session dangling until a timer finds them,
//!   and a shed re-INVITE or UPDATE breaks a session refresh. They run however
//!   long they queued.
//! - **Responses never:** a dropped response strands the client transaction
//!   that waits for it and the server transaction behind it, and the far end
//!   has already done the work; forwarding it is cheap and completes a
//!   transaction instead of starting one.
//! - **Timer expiries and continuations never:** they are not dispatcher
//!   jobs. Timer B/F/H expiries and async-handler continuations reach the
//!   executor through `spawn_queued`, which waits for room and carries no age
//!   policy, because dropping one strands a transaction a client is owed an
//!   answer on.
//!
//! The 503 goes through a server transaction exactly as any locally answered
//! request does ([`super::request::answer_locally`]), so a retransmission of
//! the shed request is answered from the cached 503 instead of queueing again,
//! an ACK to a shed INVITE is absorbed, and the response leaves through the
//! same egress as every response, over the UE's security association on a
//! P-CSCF.
//!
//! Feedback-based overload control (RFC 7339, the `oc` Via parameters) is the
//! natural follow-up and is not implemented here.

use super::*;

/// How long an initial request may wait in the script executor's queue before
/// it is answered 503 instead of reaching the script.
///
/// 16·T1, a quarter of Timer F / Timer B (64·T1 = 32 s with the RFC 3261
/// default T1 of 500 ms, which every SIP client uses for its own timers, so
/// siphon's configuration cannot move it). A request that waited this long has
/// at most 24 s of its client's transaction left for everything still ahead of
/// it: the script itself, which may block on an HSS, a registrar backend or
/// DNS, then the next hop and its own answer back. Past that the answer is
/// likely to land after the client gave up. Fixed rather than configurable for
/// that reason: the clock it races is the client's, not ours.
pub(super) const STALE_REQUEST_BUDGET: std::time::Duration = std::time::Duration::from_secs(8);

/// Ceiling on the base of the `Retry-After` value, in seconds: Timer F.
const RETRY_AFTER_CEILING_SECS: u64 = 32;

/// Is `message`, a request of `method`, shed once it has queued past the
/// budget? Only runs when the budget is already exceeded, so it costs the hot
/// path nothing. See the module docs for the rule and its reasons.
pub(super) fn sheds_when_stale(method: &str, message: &SipMessage) -> bool {
    if matches!(method, "ACK" | "CANCEL" | "BYE") {
        return false;
    }
    !super::request::to_has_tag(message)
}

/// The `Retry-After` for a request shed after waiting `queue_wait`, in seconds.
///
/// The base is the queue wait itself (rounded up, capped at Timer F): that is
/// how far behind the executor runs, and a client that comes back sooner only
/// joins the same backlog. On top goes a spread of up to half the base, taken
/// from the Call-ID, so the clients shed in one second do not all come back in
/// the same second and rebuild the storm. Deterministic per Call-ID, so a
/// value is reproducible in a test; a retransmission is answered from the
/// transaction's cached 503 anyway.
pub(super) fn retry_after_secs(queue_wait: std::time::Duration, call_id: &str) -> u64 {
    let rounded_up = queue_wait
        .as_secs()
        .saturating_add(u64::from(queue_wait.subsec_nanos() > 0));
    let base = rounded_up.clamp(1, RETRY_AFTER_CEILING_SECS);
    // FNV-1a over the Call-ID: stable, no allocation.
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in call_id.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    base + hash % (base / 2 + 1)
}

/// Answer `message`, which waited `queue_wait` in the executor queue, with
/// `503 Service Unavailable` and a `Retry-After`, through a server transaction,
/// without running the script.
pub(super) fn shed_stale_request(
    inbound: &InboundMessage,
    message: &SipMessage,
    method: &str,
    queue_wait: std::time::Duration,
    state: &Arc<DispatcherState>,
) {
    // A copy of this request already took the transaction on another worker
    // and answers it; nothing more to do here.
    let Some(server_key) = super::request::open_server_transaction(inbound, message, method, state)
    else {
        return;
    };
    let call_id = message
        .headers
        .call_id()
        .map(String::as_str)
        .unwrap_or_default();
    let retry_after = retry_after_secs(queue_wait, call_id);
    let mut response = build_response(
        message,
        503,
        "Service Unavailable",
        state.identity.load().server.as_deref(),
        &[(
            crate::script::api::request::ReplyHeaderOp::Replace,
            "Retry-After".to_string(),
            retry_after.to_string(),
        )],
    );
    // The builder copies a REGISTER's Expires for the 2xx a registrar grants;
    // nothing was granted here.
    response.headers.remove("Expires");
    super::request::answer_locally(response, server_key.as_ref(), inbound, state);

    if let Some(parsed) = message.method() {
        crate::metrics::stale_shed::record(parsed);
    }
    warn_shed(method, queue_wait, state.stale_request_budget);
}

/// A rate-limited WARN for a shed request: the first one, then at most one
/// every [`WARN_EVERY`], carrying how many went unlogged in between. The
/// counter carries the exact numbers.
fn warn_shed(method: &str, queue_wait: std::time::Duration, budget: std::time::Duration) {
    const WARN_EVERY: std::time::Duration = std::time::Duration::from_secs(10);
    static LAST_WARNED: std::sync::Mutex<Option<std::time::Instant>> = std::sync::Mutex::new(None);
    static UNLOGGED: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

    // `try_lock`: a worker that finds another one logging just counts itself
    // into the next line rather than waiting.
    let due = match LAST_WARNED.try_lock() {
        Ok(mut last) => {
            let now = std::time::Instant::now();
            if last.is_none_or(|at| now.duration_since(at) >= WARN_EVERY) {
                *last = Some(now);
                true
            } else {
                false
            }
        }
        Err(_) => false,
    };
    if !due {
        UNLOGGED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        return;
    }
    let unlogged = UNLOGGED.swap(0, std::sync::atomic::Ordering::Relaxed);
    warn!(
        method,
        queue_wait_ms = u64::try_from(queue_wait.as_millis()).unwrap_or(u64::MAX),
        budget_ms = u64::try_from(budget.as_millis()).unwrap_or(u64::MAX),
        shed_since_last_warning = unlogged,
        "Python executor overloaded: answering an initial request 503 without running the \
         script, it waited {} ms in the queue (budget {} ms)",
        queue_wait.as_millis(),
        budget.as_millis()
    );
}
