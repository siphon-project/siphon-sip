//! The process's open file limit (`RLIMIT_NOFILE`).
//!
//! Docker, containerd and systemd start services with a soft limit of 1024 and
//! a far higher hard limit (524288 on current releases). The 1024 only protects
//! programs that call `select()`, whose fd sets stop at `FD_SETSIZE` = 1024.
//! siphon's I/O is epoll, so at startup it raises its soft limit to the hard
//! limit, as Go programs have done since Go 1.19. Without that, one TCP or TLS
//! connection per client runs out of descriptors near 1000 clients while the
//! hard limit sits unused.
//!
//! Child processes get the original soft limit back between fork and exec
//! ([`command`]), because a child may be a C program that uses `select()`. An
//! operator who wants a lower ceiling lowers the hard limit (container
//! `ulimits`, systemd `LimitNOFILE`); siphon never goes above it.

use std::ffi::OsStr;
use std::io;
use std::sync::OnceLock;

use tracing::{info, warn};

/// The soft limit as siphon found it, kept only once it has been raised.
/// Restored in every child spawned through [`command`].
static ORIGINAL: OnceLock<libc::rlimit> = OnceLock::new();

/// Below this many descriptors siphon warns at startup that the limit, not the
/// hardware, decides how many stream clients it can hold.
pub const LOW_LIMIT_WARNING: libc::rlim_t = 65_536;

/// What [`raise_soft_limit`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RaiseOutcome {
    /// The soft limit went from `from` to the hard limit `to`.
    Raised {
        from: libc::rlim_t,
        to: libc::rlim_t,
    },
    /// The soft limit already equalled the hard limit.
    AlreadyAtHard { soft: libc::rlim_t },
    /// `setrlimit` refused; the process keeps `soft`.
    Failed {
        soft: libc::rlim_t,
        hard: libc::rlim_t,
        errno: i32,
    },
    /// `getrlimit` itself failed, so nothing was changed.
    Unreadable { errno: i32 },
}

impl RaiseOutcome {
    /// The soft limit the process runs with after the raise, when known.
    pub fn soft_limit(&self) -> Option<libc::rlim_t> {
        match *self {
            RaiseOutcome::Raised { to, .. } => Some(to),
            RaiseOutcome::AlreadyAtHard { soft } | RaiseOutcome::Failed { soft, .. } => Some(soft),
            RaiseOutcome::Unreadable { .. } => None,
        }
    }
}

fn read_limit() -> io::Result<libc::rlimit> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, writable rlimit for the call's duration.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(limit)
}

fn errno_of(error: &io::Error) -> i32 {
    error.raw_os_error().unwrap_or(0)
}

/// Raise the soft `RLIMIT_NOFILE` to the hard limit. Call before any thread or
/// descriptor exists ([`crate::server::SiphonServer::run`] does it first). A
/// failure leaves the limit as it was; the process works below it.
pub fn raise_soft_limit() -> RaiseOutcome {
    let original = match read_limit() {
        Ok(limit) => limit,
        Err(error) => {
            return RaiseOutcome::Unreadable {
                errno: errno_of(&error),
            }
        }
    };
    if original.rlim_cur >= original.rlim_max {
        return RaiseOutcome::AlreadyAtHard {
            soft: original.rlim_cur,
        };
    }
    let raised = libc::rlimit {
        rlim_cur: original.rlim_max,
        rlim_max: original.rlim_max,
    };
    // SAFETY: `raised` is a valid rlimit read by the call and not kept.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &raised) } != 0 {
        return RaiseOutcome::Failed {
            soft: original.rlim_cur,
            hard: original.rlim_max,
            errno: errno_of(&io::Error::last_os_error()),
        };
    }
    // A second raise in the same process (an embedder running two servers)
    // finds the limit already at hard and never gets here, so the first
    // original is the one children get back.
    let _ = ORIGINAL.set(original);
    RaiseOutcome::Raised {
        from: original.rlim_cur,
        to: original.rlim_max,
    }
}

/// Log what [`raise_soft_limit`] did. Separate from the raise because the raise
/// runs before logging is set up.
pub fn log_outcome(outcome: &RaiseOutcome) {
    match *outcome {
        RaiseOutcome::Raised { from, to } => {
            info!("RLIMIT_NOFILE soft {from} -> {to} (hard {to})");
        }
        RaiseOutcome::AlreadyAtHard { soft } => {
            info!("RLIMIT_NOFILE soft {soft} (already at hard)");
        }
        RaiseOutcome::Failed { soft, hard, errno } => {
            warn!(
                "RLIMIT_NOFILE soft {soft} kept: raising it to the hard limit {hard} failed: {}",
                io::Error::from_raw_os_error(errno)
            );
        }
        RaiseOutcome::Unreadable { errno } => {
            warn!(
                "RLIMIT_NOFILE could not be read, limit left as it is: {}",
                io::Error::from_raw_os_error(errno)
            );
        }
    }
    if let Some(soft) = outcome.soft_limit() {
        if soft < LOW_LIMIT_WARNING {
            warn!(
                "RLIMIT_NOFILE soft limit {soft} is below {LOW_LIMIT_WARNING}: it caps the number \
                 of TCP/TLS/WebSocket clients this process can hold; raise the hard limit \
                 (container ulimits nofile, systemd LimitNOFILE)"
            );
        }
    }
}

/// The current soft `RLIMIT_NOFILE`, for log lines about descriptor exhaustion.
pub fn current_soft_limit() -> Option<libc::rlim_t> {
    read_limit().ok().map(|limit| limit.rlim_cur)
}

/// A `std::process::Command` for `program` whose child starts with the soft
/// limit siphon found at startup, not the raised one. Every process siphon
/// spawns goes through here (clippy's `disallowed-methods` holds that).
#[allow(clippy::disallowed_methods)] // the one place allowed to build a Command
pub fn command(program: impl AsRef<OsStr>) -> std::process::Command {
    let mut command = std::process::Command::new(program);
    if let Some(original) = ORIGINAL.get().copied() {
        use std::os::unix::process::CommandExt;
        // SAFETY: the hook runs in the child between fork and exec, where only
        // async-signal-safe calls are allowed. It makes one `setrlimit` call
        // (async-signal-safe) on a value copied in before the fork; it does not
        // allocate, lock or touch shared state. Lowering the soft limit to its
        // original value is always permitted; if it fails anyway the child runs
        // with the raised limit, as Go's equivalent does.
        unsafe {
            command.pre_exec(move || {
                libc::setrlimit(libc::RLIMIT_NOFILE, &original);
                Ok(())
            });
        }
    }
    command
}

/// [`command`] for code that awaits the child on tokio.
pub fn tokio_command(program: impl AsRef<OsStr>) -> tokio::process::Command {
    tokio::process::Command::from(command(program))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_capture::LogBuffer;

    /// Set this process's limit. Only ever called inside an `own_process`
    /// child, which nothing else shares.
    fn set_limit(soft: libc::rlim_t, hard: libc::rlim_t) {
        let limit = libc::rlimit {
            rlim_cur: soft,
            rlim_max: hard,
        };
        // SAFETY: valid rlimit, read by the call only.
        let result = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) };
        assert_eq!(
            result,
            0,
            "setrlimit {soft}:{hard}: {}",
            io::Error::last_os_error()
        );
    }

    fn logged(outcome: &RaiseOutcome) -> String {
        let log = LogBuffer::default();
        let subscriber = tracing_subscriber::fmt()
            .with_ansi(false)
            .with_writer(log.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || log_outcome(outcome));
        log.rendered()
    }

    #[test]
    fn soft_limit_is_raised_to_the_hard_limit() {
        crate::own_process::run(
            concat!(module_path!(), "::soft_limit_is_raised_to_the_hard_limit"),
            || {
                set_limit(1024, 4096);
                let outcome = raise_soft_limit();
                assert_eq!(
                    outcome,
                    RaiseOutcome::Raised {
                        from: 1024,
                        to: 4096
                    }
                );
                let now = read_limit().expect("getrlimit");
                assert_eq!((now.rlim_cur, now.rlim_max), (4096, 4096));
                assert_eq!(current_soft_limit(), Some(4096));
                let log = logged(&outcome);
                assert!(
                    log.contains("INFO")
                        && log.contains("RLIMIT_NOFILE soft 1024 -> 4096 (hard 4096)"),
                    "{log}"
                );
            },
        );
    }

    #[test]
    fn a_limit_already_at_hard_is_left_alone() {
        crate::own_process::run(
            concat!(module_path!(), "::a_limit_already_at_hard_is_left_alone"),
            || {
                set_limit(2048, 2048);
                let outcome = raise_soft_limit();
                assert_eq!(outcome, RaiseOutcome::AlreadyAtHard { soft: 2048 });
                let now = read_limit().expect("getrlimit");
                assert_eq!((now.rlim_cur, now.rlim_max), (2048, 2048));
                assert!(ORIGINAL.get().is_none(), "nothing to restore in children");
                let log = logged(&outcome);
                assert!(
                    log.contains("RLIMIT_NOFILE soft 2048 (already at hard)"),
                    "{log}"
                );
            },
        );
    }

    #[test]
    fn a_child_starts_with_the_original_soft_limit() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::a_child_starts_with_the_original_soft_limit"
            ),
            || {
                set_limit(1024, 4096);
                assert!(matches!(raise_soft_limit(), RaiseOutcome::Raised { .. }));
                let output = command("sh")
                    .args(["-c", "ulimit -Sn; ulimit -Hn"])
                    .output()
                    .expect("run sh");
                assert_eq!(String::from_utf8_lossy(&output.stdout), "1024\n4096\n");
            },
        );
    }

    #[tokio::test]
    async fn a_tokio_child_starts_with_the_original_soft_limit() {
        // The tokio variant is built from the std one; prove the hook survives
        // the conversion. Runs in-process: without a raise there is nothing to
        // restore, so the child sees the same soft limit as this process.
        let expected = current_soft_limit().expect("getrlimit");
        let output = tokio_command("sh")
            .args(["-c", "ulimit -Sn"])
            .output()
            .await
            .expect("run sh");
        assert_eq!(
            String::from_utf8_lossy(&output.stdout).trim(),
            expected.to_string()
        );
    }

    #[test]
    fn a_tokio_child_after_a_raise_starts_with_the_original_soft_limit() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::a_tokio_child_after_a_raise_starts_with_the_original_soft_limit"
            ),
            || {
                set_limit(1024, 4096);
                assert!(matches!(raise_soft_limit(), RaiseOutcome::Raised { .. }));
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                let output = runtime
                    .block_on(async {
                        tokio_command("sh")
                            .args(["-c", "ulimit -Sn"])
                            .output()
                            .await
                    })
                    .expect("run sh");
                assert_eq!(String::from_utf8_lossy(&output.stdout), "1024\n");
            },
        );
    }

    #[test]
    fn a_low_limit_is_warned_about() {
        let log = logged(&RaiseOutcome::Raised {
            from: 1024,
            to: 4096,
        });
        assert!(log.contains("WARN"), "{log}");
        assert!(log.contains("soft limit 4096 is below 65536"), "{log}");
    }

    #[test]
    fn a_high_limit_is_not_warned_about() {
        let log = logged(&RaiseOutcome::Raised {
            from: 1024,
            to: 524_288,
        });
        assert!(!log.contains("WARN"), "{log}");
        assert!(
            log.contains("RLIMIT_NOFILE soft 1024 -> 524288 (hard 524288)"),
            "{log}"
        );
    }

    #[test]
    fn a_failed_raise_is_warned_with_the_errno_and_the_kept_limit() {
        let log = logged(&RaiseOutcome::Failed {
            soft: 100_000,
            hard: 200_000,
            errno: libc::EPERM,
        });
        assert!(log.contains("WARN"), "{log}");
        assert!(log.contains("soft 100000 kept"), "{log}");
        assert!(log.contains("hard limit 200000"), "{log}");
        assert!(log.contains("Operation not permitted"), "{log}");
    }

    #[test]
    fn soft_limit_of_each_outcome() {
        assert_eq!(
            RaiseOutcome::Raised { from: 1, to: 2 }.soft_limit(),
            Some(2)
        );
        assert_eq!(
            RaiseOutcome::AlreadyAtHard { soft: 3 }.soft_limit(),
            Some(3)
        );
        assert_eq!(
            RaiseOutcome::Failed {
                soft: 4,
                hard: 5,
                errno: 1
            }
            .soft_limit(),
            Some(4)
        );
        assert_eq!(RaiseOutcome::Unreadable { errno: 1 }.soft_limit(), None);
    }
}
