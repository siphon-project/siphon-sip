//! The runner's wake: a self-pipe the driver loop's selector watches.
//!
//! Any thread may wake the runner, attached to the interpreter or not, and
//! doing so never touches Python: it is one atomic swap and, for the first
//! wake since the runner last looked, one nonblocking one-byte write. Every
//! further wake until the runner disarms finds the flag set and does nothing,
//! so a burst of N wakes costs the selector one readable event.
//!
//! No wake is lost because of the order each side works in:
//!
//! - a waker makes its work visible first, then swaps the flag to armed and
//!   writes a byte if it was not;
//! - the runner empties the socket, then disarms, then looks for work.
//!
//! Work published before the disarm is found by the look that follows it. Work
//! published after it finds the flag clear and writes a byte, which makes the
//! socket readable again. Both sides use `SeqCst`: the pattern is two threads
//! each writing one location and then reading the other, which weaker
//! orderings do not keep apart.

use std::io::{ErrorKind, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use tracing::debug;

/// The waking side: shared by every thread that hands the runner work.
pub(crate) struct WakeSender {
    armed: AtomicBool,
    writer: UnixStream,
    /// Bytes written to the pipe, so the coalescing is observable.
    writes: AtomicU64,
}

/// The woken side: owned by the driver thread, its fd watched by the loop.
pub(crate) struct WakeReceiver {
    reader: UnixStream,
}

/// A connected, nonblocking pair.
pub(crate) fn wake_pair() -> std::io::Result<(WakeSender, WakeReceiver)> {
    let (writer, reader) = UnixStream::pair()?;
    writer.set_nonblocking(true)?;
    reader.set_nonblocking(true)?;
    Ok((
        WakeSender {
            armed: AtomicBool::new(false),
            writer,
            writes: AtomicU64::new(0),
        },
        WakeReceiver { reader },
    ))
}

/// How one attempt to write the wake byte ended.
#[derive(Debug, PartialEq, Eq)]
enum Written {
    /// The byte is in the pipe.
    Byte,
    /// The pipe is full, so a readable event is pending already.
    AlreadyPending,
    /// The other end is gone or the write failed outright.
    Failed(ErrorKind),
}

/// Write one byte, retrying a write a signal interrupted. Never waits: a full
/// pipe is a wake that is pending already.
fn write_wake_byte(writer: &mut dyn Write) -> Written {
    loop {
        match writer.write(&[1]) {
            Ok(_) => return Written::Byte,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) if error.kind() == ErrorKind::WouldBlock => return Written::AlreadyPending,
            Err(error) => return Written::Failed(error.kind()),
        }
    }
}

/// Read until the pipe is empty, retrying a read a signal interrupted. Returns
/// the bytes taken.
fn read_wake_bytes(reader: &mut dyn Read) -> usize {
    let mut taken = 0;
    let mut buffer = [0u8; 64];
    loop {
        match reader.read(&mut buffer) {
            // End of file: every writer is gone.
            Ok(0) => return taken,
            Ok(count) => taken += count,
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            // `WouldBlock` is the empty pipe; anything else ends the read too,
            // and the selector reports the fd again if it is still readable.
            Err(_) => return taken,
        }
    }
}

impl WakeSender {
    /// Make the runner's fd readable unless a wake is pending already.
    pub(crate) fn wake(&self) {
        if self.armed.swap(true, Ordering::SeqCst) {
            return;
        }
        match write_wake_byte(&mut &self.writer) {
            Written::Byte => {
                self.writes.fetch_add(1, Ordering::Relaxed);
            }
            Written::AlreadyPending => {}
            // Only once the runner has closed its end: nothing is left to wake.
            Written::Failed(kind) => debug!(?kind, "runner wake pipe write failed"),
        }
    }

    /// The runner is about to look for work: wakes from here on write again.
    pub(crate) fn disarm(&self) {
        self.armed.swap(false, Ordering::SeqCst);
    }

    /// Bytes written to the pipe so far.
    pub(crate) fn writes(&self) -> u64 {
        self.writes.load(Ordering::Relaxed)
    }

    /// A second handle on the write end, to see from outside whether the read
    /// end is still open.
    #[cfg(test)]
    pub(crate) fn probe(&self) -> UnixStream {
        self.writer.try_clone().expect("the write end duplicates")
    }
}

impl WakeReceiver {
    /// The fd the loop's selector watches.
    pub(crate) fn fd(&self) -> RawFd {
        self.reader.as_raw_fd()
    }

    /// Take every pending wake byte. Returns how many there were.
    pub(crate) fn clear(&self) -> usize {
        read_wake_bytes(&mut &self.reader)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Arc;

    /// A writer or reader that plays back a script of results.
    struct Scripted {
        results: VecDeque<std::io::Result<usize>>,
        calls: usize,
    }

    impl Scripted {
        fn new(results: Vec<std::io::Result<usize>>) -> Self {
            Self {
                results: results.into(),
                calls: 0,
            }
        }

        fn next(&mut self) -> std::io::Result<usize> {
            self.calls += 1;
            self.results
                .pop_front()
                .unwrap_or_else(|| Err(ErrorKind::WouldBlock.into()))
        }
    }

    impl Write for Scripted {
        fn write(&mut self, _buffer: &[u8]) -> std::io::Result<usize> {
            self.next()
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Read for Scripted {
        fn read(&mut self, _buffer: &mut [u8]) -> std::io::Result<usize> {
            self.next()
        }
    }

    #[test]
    fn an_interrupted_write_is_retried() {
        let mut writer = Scripted::new(vec![
            Err(ErrorKind::Interrupted.into()),
            Err(ErrorKind::Interrupted.into()),
            Ok(1),
        ]);
        assert_eq!(write_wake_byte(&mut writer), Written::Byte);
        assert_eq!(writer.calls, 3);
    }

    #[test]
    fn a_full_pipe_is_a_pending_wake_not_a_wait() {
        let mut writer = Scripted::new(vec![Err(ErrorKind::WouldBlock.into())]);
        assert_eq!(write_wake_byte(&mut writer), Written::AlreadyPending);
        assert_eq!(writer.calls, 1);
    }

    #[test]
    fn a_closed_pipe_fails_the_write_without_retrying() {
        let mut writer = Scripted::new(vec![Err(ErrorKind::BrokenPipe.into())]);
        assert_eq!(
            write_wake_byte(&mut writer),
            Written::Failed(ErrorKind::BrokenPipe)
        );
        assert_eq!(writer.calls, 1);
    }

    #[test]
    fn an_interrupted_read_is_retried_until_the_pipe_is_empty() {
        let mut reader = Scripted::new(vec![
            Ok(64),
            Err(ErrorKind::Interrupted.into()),
            Ok(3),
            Err(ErrorKind::WouldBlock.into()),
        ]);
        assert_eq!(read_wake_bytes(&mut reader), 67);
        assert_eq!(reader.calls, 4);
    }

    #[test]
    fn end_of_file_ends_the_read() {
        let mut reader = Scripted::new(vec![Ok(2), Ok(0), Ok(5)]);
        assert_eq!(read_wake_bytes(&mut reader), 2);
    }

    #[test]
    fn a_wake_makes_the_fd_readable_once() {
        let (sender, receiver) = wake_pair().expect("a socket pair");
        assert_eq!(receiver.clear(), 0, "nothing pending before the first wake");
        sender.wake();
        assert_eq!(receiver.clear(), 1);
        assert_eq!(receiver.clear(), 0);
    }

    #[test]
    fn wakes_coalesce_until_the_runner_disarms() {
        let (sender, receiver) = wake_pair().expect("a socket pair");
        for _ in 0..1000 {
            sender.wake();
        }
        assert_eq!(sender.writes(), 1);
        assert_eq!(receiver.clear(), 1);

        // Still armed: the runner has not said it is looking yet.
        sender.wake();
        assert_eq!(receiver.clear(), 0);

        sender.disarm();
        sender.wake();
        sender.wake();
        assert_eq!(receiver.clear(), 1);
        assert_eq!(sender.writes(), 2);
    }

    #[test]
    fn concurrent_wakes_write_one_byte() {
        let (sender, receiver) = wake_pair().expect("a socket pair");
        let sender = Arc::new(sender);
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let sender = Arc::clone(&sender);
                std::thread::spawn(move || {
                    for _ in 0..10_000 {
                        sender.wake();
                    }
                })
            })
            .collect();
        for thread in threads {
            thread.join().expect("waker thread");
        }
        assert_eq!(sender.writes(), 1);
        assert_eq!(receiver.clear(), 1);
    }

    /// With the pipe's buffer full the write end reports `WouldBlock`; a wake
    /// then returns at once instead of waiting for room.
    #[test]
    fn a_wake_on_a_full_pipe_returns_without_writing() {
        let (sender, receiver) = wake_pair().expect("a socket pair");
        let mut filler = sender.probe();
        filler.set_nonblocking(true).expect("nonblocking filler");
        let chunk = [0u8; 4096];
        let mut filled = 0usize;
        loop {
            match filler.write(&chunk) {
                Ok(count) => filled += count,
                Err(error) if error.kind() == ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == ErrorKind::Interrupted => {}
                Err(error) => panic!("filling the pipe failed: {error}"),
            }
        }
        // The last byte of room, so the wake's own byte cannot fit.
        while matches!(filler.write(&[0]), Ok(1)) {
            filled += 1;
        }

        sender.wake();
        assert_eq!(sender.writes(), 0, "the full pipe took no wake byte");
        assert_eq!(receiver.clear(), filled);
    }

    #[test]
    fn a_wake_after_the_reader_closed_writes_nothing() {
        let (sender, receiver) = wake_pair().expect("a socket pair");
        drop(receiver);
        // A child process another test is starting holds a copy of the read
        // end until it execs, so the first writes may still find a peer.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let before = sender.writes();
            sender.disarm();
            sender.wake();
            if sender.writes() == before {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "writes still land on a closed pipe"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
    }
}
