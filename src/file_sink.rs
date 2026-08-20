//! Opening append-only file sinks (log file, CDR file, LI audit log, Diameter
//! event sink).
//!
//! Every one of these paths is operator-configured and every default we ship
//! points inside `/var/log/siphon` or `/var/lib/siphon` — directories the
//! packaged systemd unit materialises through `LogsDirectory=` /
//! `StateDirectory=`, and that nothing creates when siphon is started any other
//! way (a tarball install, `cargo install`, a container, a by-hand run). Opening
//! with `create(true)` creates the *file*, never the directory holding it, so
//! the shipped default failed for everyone not going through the unit: the log
//! file exits the process, the other three log an error per write.
//!
//! So a missing parent directory is created on demand. The directory is only
//! touched when the open actually fails with `NotFound`, which is the sole
//! reason a `create(true).append(true)` open reports it — the happy path stays
//! at one syscall, and a permission error still surfaces as a permission error
//! rather than as a confusing `mkdir` failure.

use std::io;
use std::path::Path;

/// Open `path` for append, creating the file and any missing parent directory.
pub fn open_append(path: impl AsRef<Path>) -> io::Result<std::fs::File> {
    let path = path.as_ref();
    match std::fs::OpenOptions::new().create(true).append(true).open(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::OpenOptions::new().create(true).append(true).open(path)
        }
        result => result,
    }
}

/// [`open_append`] for the async runtime.
pub async fn open_append_async(path: impl AsRef<Path>) -> io::Result<tokio::fs::File> {
    let path = path.as_ref();
    match tokio::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .await
    {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            if let Some(parent) = path.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                tokio::fs::create_dir_all(parent).await?;
            }
            tokio::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await
        }
        result => result,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    fn creates_missing_parent_directories() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var/log/siphon/siphon.log");

        let mut file = open_append(&path).unwrap();
        file.write_all(b"line\n").unwrap();

        assert!(path.exists());
    }

    #[test]
    fn appends_to_an_existing_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cdr.jsonl");
        std::fs::write(&path, "first\n").unwrap();

        let mut file = open_append(&path).unwrap();
        file.write_all(b"second\n").unwrap();
        drop(file);

        let mut contents = String::new();
        std::fs::File::open(&path)
            .unwrap()
            .read_to_string(&mut contents)
            .unwrap();
        assert_eq!(contents, "first\nsecond\n");
    }

    /// A parent that exists as a *file* is a real operator error — it must
    /// surface, not be papered over.
    #[test]
    fn parent_that_is_a_file_still_errors() {
        let dir = tempfile::tempdir().unwrap();
        let not_a_directory = dir.path().join("siphon");
        std::fs::write(&not_a_directory, "").unwrap();

        let result = open_append(not_a_directory.join("siphon.log"));

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn async_creates_missing_parent_directories() {
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("var/log/siphon/cdr.jsonl");

        let mut file = open_append_async(&path).await.unwrap();
        file.write_all(b"{}\n").await.unwrap();

        assert!(path.exists());
    }

    #[tokio::test]
    async fn async_appends_to_an_existing_file() {
        use tokio::io::AsyncWriteExt;

        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.log");
        tokio::fs::write(&path, "first\n").await.unwrap();

        let mut file = open_append_async(&path).await.unwrap();
        file.write_all(b"second\n").await.unwrap();
        drop(file);

        assert_eq!(
            tokio::fs::read_to_string(&path).await.unwrap(),
            "first\nsecond\n"
        );
    }
}
