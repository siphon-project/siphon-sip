//! Script coroutines waiting on what the engine reports later: a recording's
//! closed file, and the digits a caller keys while a read is active.
//!
//! Both are resolved by the connection's reader (`connection::route_frame`),
//! so the state lives here, in Rust, scoped to the call or the recording, and
//! not in a script: a DTMF event can land on any script worker, and a
//! per-call Python buffer read from another worker is a race.

use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::sync::{mpsc, oneshot};

use crate::rtpengine::events::RecordingFinished;

/// How long a `RecordingFinished` nobody was waiting for yet is kept. The
/// accept and the event travel on one connection in order, but the reader may
/// route the event before the coroutine that read the accept has registered
/// its waiter (a recording that fails at once). Kept long enough to close that
/// gap, short enough that recordings started over the control rail, which no
/// script waits on, do not pile up.
const UNCLAIMED_RECORDING_TTL: Duration = Duration::from_secs(30);

/// Why a [`DigitRead`] ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DigitReadEnd {
    /// A terminator digit was keyed; it is not part of the digits.
    Terminator,
    /// `max_digits` were collected.
    MaxDigits,
    /// Nothing was keyed within the first-digit timeout.
    Timeout,
    /// No further digit within the inter-digit timeout.
    InterDigitTimeout,
    /// Another read on the same call replaced this one, or the control
    /// connection went away (the call's events will not come any more).
    Interrupted,
}

impl DigitReadEnd {
    /// The name a script sees.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Terminator => "terminator",
            Self::MaxDigits => "max_digits",
            Self::Timeout => "timeout",
            Self::InterDigitTimeout => "inter_digit_timeout",
            Self::Interrupted => "interrupted",
        }
    }
}

/// What a read of keyed digits yielded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DigitRead {
    pub digits: String,
    pub end: DigitReadEnd,
}

/// When a read of keyed digits completes: the first of these.
#[derive(Debug, Clone)]
pub struct DigitReadLimits {
    /// Digits that end the read (`#` usually). Not included in the result.
    pub terminators: String,
    /// End after this many digits.
    pub max_digits: Option<usize>,
    /// End when nothing at all was keyed within this.
    pub timeout: Duration,
    /// End when no further digit came within this after the last one.
    pub inter_digit_timeout: Duration,
}

/// One active read: the digits go down this channel.
struct Reader {
    /// Told apart from a later reader on the same call, so that only the
    /// reader that registered an entry removes it.
    serial: u64,
    sender: mpsc::UnboundedSender<String>,
}

/// The waiters of one engine control connection.
#[derive(Default)]
pub struct Waiters {
    recordings: DashMap<String, oneshot::Sender<RecordingFinished>>,
    unclaimed: DashMap<String, (Instant, RecordingFinished)>,
    readers: DashMap<String, Reader>,
    next_serial: std::sync::atomic::AtomicU64,
}

impl Waiters {
    /// The reader saw a recording end. Resolves its waiter, or keeps the
    /// result for a waiter about to register.
    pub fn recording_finished(&self, finished: &RecordingFinished) {
        if let Some((_, sender)) = self.recordings.remove(&finished.recording_id) {
            let _ = sender.send(finished.clone());
            return;
        }
        let now = Instant::now();
        self.unclaimed
            .retain(|_, (seen, _)| now.duration_since(*seen) < UNCLAIMED_RECORDING_TTL);
        self.unclaimed
            .insert(finished.recording_id.clone(), (now, finished.clone()));
    }

    /// Wait for a recording to end, at most `deadline`. `None` when it did
    /// not end in time or the connection went away first.
    pub async fn wait_recording(
        &self,
        recording_id: &str,
        deadline: Duration,
    ) -> Option<RecordingFinished> {
        if let Some((_, (_, finished))) = self.unclaimed.remove(recording_id) {
            return Some(finished);
        }
        let (sender, receiver) = oneshot::channel();
        self.recordings.insert(recording_id.to_string(), sender);
        // Registered after the check above: the reader may have stashed it in
        // between.
        if let Some((_, (_, finished))) = self.unclaimed.remove(recording_id) {
            self.recordings.remove(recording_id);
            return Some(finished);
        }
        let outcome = tokio::time::timeout(deadline, receiver).await;
        self.recordings.remove(recording_id);
        match outcome {
            Ok(Ok(finished)) => Some(finished),
            _ => None,
        }
    }

    /// The reader saw a digit. `true` when a read on the call took it, which
    /// then is not also an `@rtpengine.on_dtmf` event.
    pub fn offer_digit(&self, call_id: &str, digit: &str) -> bool {
        match self.readers.get(call_id) {
            Some(reader) => reader.sender.send(digit.to_string()).is_ok(),
            None => false,
        }
    }

    /// Collect the digits keyed on `call_id` until `limits` say stop. A read
    /// already active on the call ends (`Interrupted`) with what it had.
    pub async fn read_digits(&self, call_id: &str, limits: &DigitReadLimits) -> DigitRead {
        let serial = self
            .next_serial
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (sender, mut receiver) = mpsc::unbounded_channel();
        self.readers
            .insert(call_id.to_string(), Reader { serial, sender });
        let mut digits = String::new();
        let started = Instant::now();
        let end = loop {
            let wait = if digits.is_empty() {
                limits.timeout.saturating_sub(started.elapsed())
            } else {
                limits.inter_digit_timeout
            };
            match tokio::time::timeout(wait, receiver.recv()).await {
                Ok(Some(digit)) => {
                    if !digit.is_empty() && limits.terminators.contains(digit.as_str()) {
                        break DigitReadEnd::Terminator;
                    }
                    digits.push_str(&digit);
                    if limits
                        .max_digits
                        .is_some_and(|max| digits.chars().count() >= max)
                    {
                        break DigitReadEnd::MaxDigits;
                    }
                }
                Ok(None) => break DigitReadEnd::Interrupted,
                Err(_) if digits.is_empty() => break DigitReadEnd::Timeout,
                Err(_) => break DigitReadEnd::InterDigitTimeout,
            }
        };
        self.readers
            .remove_if(call_id, |_, reader| reader.serial == serial);
        DigitRead { digits, end }
    }

    /// The connection went away: every waiter resolves now (a recording as
    /// not finished, a read as interrupted) instead of at its deadline.
    pub fn clear(&self) {
        self.recordings.clear();
        self.readers.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> (usize, usize, usize) {
        (
            self.recordings.len(),
            self.unclaimed.len(),
            self.readers.len(),
        )
    }
}

/// The waiting verbs of a client: a recording's end and keyed digits, both
/// resolved by its connection's reader.
impl super::SiphonRtpClient {
    /// Wait until the engine says `recording_id` ended and its file is closed.
    pub async fn wait_recording(
        &self,
        recording_id: &str,
        deadline: Duration,
    ) -> Option<RecordingFinished> {
        self.waiters.wait_recording(recording_id, deadline).await
    }

    /// Collect the digits keyed on a call (RFC 4733, as the engine detects
    /// them) until `limits` end the read.
    pub async fn read_digits(&self, call_id: &str, limits: &DigitReadLimits) -> DigitRead {
        // Under a per-call scope the leg's digits arrive under its engine
        // call-id, and so the read is keyed on that.
        self.waiters
            .read_digits(&super::per_call::leg_call_id(call_id), limits)
            .await
    }
}

impl super::SiphonRtpClientSet {
    /// Wait for a recording on the instance bound to this call to end.
    pub async fn wait_recording(
        &self,
        call_id: &str,
        recording_id: &str,
        deadline: Duration,
    ) -> Option<RecordingFinished> {
        self.select(call_id)
            .wait_recording(recording_id, deadline)
            .await
    }

    /// Collect keyed digits on the instance bound to this call.
    pub async fn read_digits(&self, call_id: &str, limits: &DigitReadLimits) -> DigitRead {
        self.select(call_id).read_digits(call_id, limits).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn finished(id: &str) -> RecordingFinished {
        RecordingFinished {
            call_id: "c".into(),
            from_tag: "f".into(),
            recording_id: id.into(),
            path: Some(format!("/spool/{id}.wav")),
            reason: "silence",
            duration_ms: 4200,
        }
    }

    fn limits(terminators: &str, max_digits: Option<usize>) -> DigitReadLimits {
        DigitReadLimits {
            terminators: terminators.into(),
            max_digits,
            timeout: Duration::from_millis(300),
            inter_digit_timeout: Duration::from_millis(150),
        }
    }

    #[tokio::test]
    async fn a_waiter_gets_the_finished_recording() {
        let waiters = Arc::new(Waiters::default());
        let waiting = Arc::clone(&waiters);
        let task =
            tokio::spawn(async move { waiting.wait_recording("r1", Duration::from_secs(2)).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiters.recording_finished(&finished("r1"));
        let got = task.await.expect("join").expect("finished");
        assert_eq!(got.path.as_deref(), Some("/spool/r1.wav"));
        assert_eq!(got.reason, "silence");
        assert_eq!(waiters.len(), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_recording_that_ended_before_the_waiter_registered_is_not_lost() {
        let waiters = Waiters::default();
        waiters.recording_finished(&finished("r2"));
        let got = waiters
            .wait_recording("r2", Duration::from_millis(10))
            .await
            .expect("kept for the waiter");
        assert_eq!(got.duration_ms, 4200);
        assert_eq!(waiters.len(), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_recording_that_never_ends_times_out_and_leaves_nothing_behind() {
        let waiters = Waiters::default();
        assert!(waiters
            .wait_recording("r3", Duration::from_millis(10))
            .await
            .is_none());
        assert_eq!(waiters.len(), (0, 0, 0));
    }

    async fn read_with(digits: &[&str], limits: DigitReadLimits) -> DigitRead {
        let waiters = Arc::new(Waiters::default());
        let reading = Arc::clone(&waiters);
        let task = tokio::spawn(async move { reading.read_digits("c", &limits).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        for digit in digits {
            assert!(waiters.offer_digit("c", digit));
        }
        let read = task.await.expect("join");
        assert_eq!(waiters.len(), (0, 0, 0));
        assert!(!waiters.offer_digit("c", "9"), "no reader after the read");
        read
    }

    #[tokio::test]
    async fn a_terminator_ends_the_read_and_is_not_returned() {
        let read = read_with(&["1", "2", "3", "#", "4"], limits("#", None)).await;
        assert_eq!(read.digits, "123");
        assert_eq!(read.end, DigitReadEnd::Terminator);
    }

    #[tokio::test]
    async fn max_digits_ends_the_read() {
        let read = read_with(&["7", "8"], limits("#", Some(1))).await;
        assert_eq!(read.digits, "7");
        assert_eq!(read.end, DigitReadEnd::MaxDigits);
    }

    #[tokio::test]
    async fn nothing_keyed_is_an_empty_timeout() {
        let read = read_with(&[], limits("#", None)).await;
        assert_eq!(read.digits, "");
        assert_eq!(read.end, DigitReadEnd::Timeout);
    }

    #[tokio::test]
    async fn a_pause_after_a_digit_is_an_inter_digit_timeout() {
        let read = read_with(&["4", "2"], limits("#", None)).await;
        assert_eq!(read.digits, "42");
        assert_eq!(read.end, DigitReadEnd::InterDigitTimeout);
    }

    #[tokio::test]
    async fn a_digit_with_no_read_active_is_left_to_the_event_handlers() {
        let waiters = Waiters::default();
        assert!(!waiters.offer_digit("c", "5"));
    }

    #[tokio::test]
    async fn a_second_read_interrupts_the_first_and_only_its_own_entry_is_removed() {
        let waiters = Arc::new(Waiters::default());
        let first = Arc::clone(&waiters);
        let long = DigitReadLimits {
            timeout: Duration::from_secs(5),
            ..limits("#", None)
        };
        let first_limits = long.clone();
        let first_task = tokio::spawn(async move { first.read_digits("c", &first_limits).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert!(waiters.offer_digit("c", "1"));
        let second = Arc::clone(&waiters);
        let second_task = tokio::spawn(async move { second.read_digits("c", &long).await });
        let interrupted = first_task.await.expect("join");
        assert_eq!(interrupted.digits, "1");
        assert_eq!(interrupted.end, DigitReadEnd::Interrupted);
        assert!(waiters.offer_digit("c", "2"));
        assert!(waiters.offer_digit("c", "#"));
        let read = second_task.await.expect("join");
        assert_eq!(read.digits, "2");
        assert_eq!(waiters.len(), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_lost_connection_releases_every_waiter() {
        let waiters = Arc::new(Waiters::default());
        let reading = Arc::clone(&waiters);
        let long = DigitReadLimits {
            timeout: Duration::from_secs(5),
            ..limits("#", None)
        };
        let task = tokio::spawn(async move { reading.read_digits("c", &long).await });
        tokio::time::sleep(Duration::from_millis(20)).await;
        waiters.clear();
        let read = task.await.expect("join");
        assert_eq!(read.end, DigitReadEnd::Interrupted);
    }

    #[tokio::test]
    async fn reads_on_many_calls_leave_no_reader_behind() {
        let waiters = Arc::new(Waiters::default());
        let mut tasks = Vec::new();
        for index in 0..200 {
            let reading = Arc::clone(&waiters);
            tasks.push(tokio::spawn(async move {
                reading
                    .read_digits(&format!("call-{index}"), &limits("#", Some(1)))
                    .await
            }));
        }
        tokio::time::sleep(Duration::from_millis(30)).await;
        for index in 0..200 {
            waiters.offer_digit(&format!("call-{index}"), "1");
        }
        for task in tasks {
            task.await.expect("join");
        }
        assert_eq!(waiters.len(), (0, 0, 0));
    }
}
