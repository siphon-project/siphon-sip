//! Deriving a recording directory from a storage key.
//!
//! A recording session's files live in one directory per session, inside the
//! directory the operator configured. This module is the only place that
//! directory is built, and it holds the invariant: the per-session component is
//! siphon's own storage key, and the directory it names stays inside the
//! configured base.

use std::path::{Component, Path, PathBuf};

use thiserror::Error;

/// Why a storage key could not be turned into a recording directory.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum RecordingPathError {
    /// The key was empty.
    #[error("storage key is empty")]
    Empty,
    /// The key held an ASCII control character or a NUL, which no path
    /// component may carry.
    #[error("storage key holds a control character")]
    ControlCharacter,
    /// The key was not a single ordinary path segment: it was absolute, held a
    /// separator, or was `.` / `..`.
    #[error("storage key {key:?} is not a single path segment")]
    NotOneSegment {
        /// The rejected key.
        key: String,
    },
    /// The joined path did not land directly inside the base. Unreachable while
    /// the checks above hold — it is the post-condition, so that a later change
    /// loosening them fails loudly instead of quietly writing somewhere else.
    #[error("recording directory {dir:?} is not directly inside {base:?}")]
    OutsideBase {
        /// The configured base directory.
        base: String,
        /// The directory that would have been used.
        dir: String,
    },
}

/// Build the recording directory for one session: `base` with `key` beneath it.
///
/// `key` is siphon's own per-session storage key. It must be a single ordinary
/// path segment, and the directory it produces must sit directly inside `base`.
///
/// `base` is deliberately not canonicalised: the directory does not exist when
/// this runs, so there is nothing to resolve yet. Containment comes from `key`
/// being a single `Normal` component, which `base.join(key)` cannot escape; the
/// final check proves that rather than assuming it.
pub(crate) fn recording_dir(base: &Path, key: &str) -> Result<PathBuf, RecordingPathError> {
    if key.is_empty() {
        return Err(RecordingPathError::Empty);
    }
    if key.chars().any(char::is_control) {
        return Err(RecordingPathError::ControlCharacter);
    }

    // Exactly one `Normal` component, spelled the same as the key. This is the
    // check that does the work: it rejects an absolute key (`RootDir`), `..`
    // (`ParentDir`), `.` (`CurDir`), and anything holding a separator (more
    // than one component).
    let mut components = Path::new(key).components();
    let one_plain_segment = matches!(
        (components.next(), components.next()),
        (Some(Component::Normal(segment)), None) if segment.to_str() == Some(key)
    );
    if !one_plain_segment {
        return Err(RecordingPathError::NotOneSegment {
            key: key.to_string(),
        });
    }

    let dir = base.join(key);
    if dir.parent() != Some(base) {
        return Err(RecordingPathError::OutsideBase {
            base: base.display().to_string(),
            dir: dir.display().to_string(),
        });
    }

    Ok(dir)
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASE: &str = "/var/lib/siphon/recordings";

    fn derive(key: &str) -> Result<PathBuf, RecordingPathError> {
        recording_dir(Path::new(BASE), key)
    }

    #[test]
    fn a_plain_key_lands_under_the_base() {
        let dir = derive("0123456789abcdef0123456789abcdef").expect("a plain key is accepted");
        assert_eq!(
            dir,
            PathBuf::from("/var/lib/siphon/recordings/0123456789abcdef0123456789abcdef")
        );
        assert_eq!(dir.parent(), Some(Path::new(BASE)));
    }

    #[test]
    fn a_base_with_a_trailing_separator_still_matches() {
        let dir = recording_dir(Path::new("/var/lib/siphon/recordings/"), "abc")
            .expect("a trailing separator on the base is not the key's problem");
        assert_eq!(dir, PathBuf::from("/var/lib/siphon/recordings/abc"));
    }

    #[test]
    fn an_empty_key_is_refused() {
        assert_eq!(derive(""), Err(RecordingPathError::Empty));
    }

    #[test]
    fn an_absolute_key_is_refused() {
        // The one that matters most: `Path::join` with an absolute path
        // discards the base entirely, so this must never reach a join.
        assert!(matches!(
            derive("/etc/siphon"),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
    }

    #[test]
    fn a_parent_directory_key_is_refused() {
        assert!(matches!(
            derive(".."),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
        assert!(matches!(
            derive("../../etc"),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
    }

    #[test]
    fn a_current_directory_key_is_refused() {
        assert!(matches!(
            derive("."),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
    }

    #[test]
    fn a_key_holding_a_separator_is_refused() {
        assert!(matches!(
            derive("a/b"),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
        assert!(matches!(
            derive("trailing/"),
            Err(RecordingPathError::NotOneSegment { .. })
        ));
    }

    #[test]
    fn a_key_holding_a_control_character_is_refused() {
        assert_eq!(
            derive("a\0b"),
            Err(RecordingPathError::ControlCharacter),
            "a NUL is rejected before it can reach a syscall"
        );
        assert_eq!(derive("a\nb"), Err(RecordingPathError::ControlCharacter));
    }

    #[test]
    fn the_error_names_the_rejected_key() {
        // The log line an operator reads has to say which key was refused.
        let error = derive("/etc/siphon").expect_err("an absolute key is refused");
        assert!(
            error.to_string().contains("/etc/siphon"),
            "the message should name the key, got: {error}"
        );
    }
}
