//! SRS storage backends — persist recording metadata after session ends.
//!
//! Three backends are supported:
//! - **File**: Writes a JSON metadata file per session alongside the audio files.
//! - **HTTP**: POSTs JSON metadata to a webhook endpoint.
//! - **None**: Stores nothing, for a control application (`srs.app`) that stores
//!   each recording itself from `RecordingFinished` / `RecordingSessionEnded`.
//!   This runs after the session's channel has ended, so with `file` a
//!   controller that removed the session's directory would get it back.

use std::path::Path;

use tracing::{error, info, warn};

use super::RecordingRecord;
use crate::config::SrsConfig;

/// Bound on one metadata (or metadata + audio) upload. Generous, because the
/// multipart body can carry a whole recording, but finite.
const HTTP_UPLOAD_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(120);

/// Store a completed recording using the configured backend.
pub async fn store_recording(config: &SrsConfig, record: &RecordingRecord) {
    match config.backend.as_str() {
        "http" => store_http(config, record).await,
        "none" => {}
        // `file`, and anything else a config that skipped `SrsConfig::validate`
        // carries: the default, as before.
        _ => store_file(config, record).await,
    }
}

/// File backend — write JSON metadata to disk.
///
/// The metadata goes in the session's own directory, beside the audio it
/// describes. That directory is named by siphon's storage key; the SRC's
/// `session_id`, which used to name it, could climb out of the configured
/// directory or be shared by two sessions.
async fn store_file(config: &SrsConfig, record: &RecordingRecord) {
    let Some(dir) = record.recording_dir.as_deref().map(Path::new) else {
        error!(session_id = %record.session_id, "SRS: session has no recording directory, metadata not written");
        return;
    };
    // `file.base_dir` used to pick this directory by itself, which let the
    // metadata land in a different tree from the audio.
    if let Some(base_dir) = config.file.as_ref().map(|file| file.base_dir.as_str()) {
        if dir.parent() != Some(Path::new(base_dir)) {
            warn!(
                session_id = %record.session_id,
                base_dir = %base_dir,
                dir = %dir.display(),
                "SRS: srs.file.base_dir no longer selects the metadata directory"
            );
        }
    }

    // Create the directory if it doesn't exist.
    if let Err(error) = tokio::fs::create_dir_all(&dir).await {
        error!(
            session_id = %record.session_id,
            dir = %dir.display(),
            error = %error,
            "SRS: failed to create recording directory"
        );
        return;
    }

    let metadata_path = dir.join("metadata.json");
    match serde_json::to_string_pretty(record) {
        Ok(json) => {
            if let Err(error) = tokio::fs::write(&metadata_path, json.as_bytes()).await {
                error!(
                    session_id = %record.session_id,
                    path = %metadata_path.display(),
                    error = %error,
                    "SRS: failed to write metadata file"
                );
            } else {
                info!(
                    session_id = %record.session_id,
                    path = %metadata_path.display(),
                    "SRS: metadata written"
                );
            }
        }
        Err(error) => {
            error!(
                session_id = %record.session_id,
                error = %error,
                "SRS: failed to serialize metadata"
            );
        }
    }
}

/// HTTP backend — POST metadata (and optionally audio files) to the webhook URL.
///
/// When `upload_audio` is false (or recording_dir is absent), sends a simple
/// `application/json` POST with the metadata.
///
/// When `upload_audio` is true, sends a `multipart/form-data` POST:
///   - Part `metadata`: JSON metadata (application/json)
///   - Part `audio_*`:  Each audio file from the recording directory
///
/// RTPEngine writes recording files (WAV, PCAP, etc.) to the `record-path`
/// directory.  After the session ends, we glob that directory for any files
/// that aren't `metadata.json` and upload them as audio parts.
async fn store_http(config: &SrsConfig, record: &RecordingRecord) {
    let http_config = match &config.http {
        Some(config) => config,
        None => {
            error!("SRS: HTTP backend configured but no `http` section in config");
            return;
        }
    };

    let json = match serde_json::to_string(record) {
        Ok(json) => json,
        Err(error) => {
            error!(
                session_id = %record.session_id,
                error = %error,
                "SRS: failed to serialize metadata for HTTP"
            );
            return;
        }
    };

    // Every other reqwest client in the tree sets a timeout; this one did not,
    // and with `upload_audio` on it posts a multipart body of recorded audio, so
    // an endpoint that accepts and then stalls held the upload open with no
    // bound at all.
    let client = match reqwest::Client::builder()
        .timeout(HTTP_UPLOAD_TIMEOUT)
        .build()
    {
        Ok(client) => client,
        Err(error) => {
            error!(
                session_id = %record.session_id,
                error = %error,
                "SRS: failed to build HTTP client"
            );
            return;
        }
    };

    // Read once: every attempt sends the same files.
    let audio_files = match (http_config.upload_audio, record.recording_dir.as_ref()) {
        (true, Some(recording_dir)) => Some(collect_audio_files(recording_dir).await),
        _ => None,
    };
    let request = || {
        let mut builder = match &audio_files {
            // Multipart upload: metadata JSON + audio files.
            Some(audio_files) => {
                let mut form = reqwest::multipart::Form::new().part(
                    "metadata",
                    reqwest::multipart::Part::text(json.clone())
                        .mime_str("application/json")
                        .unwrap_or_else(|_| reqwest::multipart::Part::text("{}")),
                );
                for (index, (filename, data)) in audio_files.iter().enumerate() {
                    let part = reqwest::multipart::Part::bytes(data.clone())
                        .file_name(filename.clone())
                        .mime_str(&mime_for_extension(filename))
                        .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new()));
                    form = form.part(format!("audio_{index}"), part);
                }
                client.post(&http_config.url).multipart(form)
            }
            // Metadata-only JSON POST.
            None => client
                .post(&http_config.url)
                .header("Content-Type", "application/json")
                .body(json.clone()),
        };
        if let Some(auth_header) = &http_config.auth_header {
            builder = builder.header("Authorization", auth_header);
        }
        builder
    };
    post_with_retry(
        request,
        &HTTP_RETRY_BACKOFF,
        &record.session_id,
        &http_config.url,
    )
    .await;
}

/// The waits between attempts to post a recording: four attempts in all.
const HTTP_RETRY_BACKOFF: [std::time::Duration; 3] = [
    std::time::Duration::from_secs(1),
    std::time::Duration::from_secs(2),
    std::time::Duration::from_secs(4),
];

/// Post `request()` until it succeeds, retrying after each of `backoff` a
/// failure that may pass: no response at all, a 5xx, or a 429. A 4xx otherwise
/// says the request itself is wrong, so it is not sent again. `true` once the
/// endpoint took it.
async fn post_with_retry(
    request: impl Fn() -> reqwest::RequestBuilder,
    backoff: &[std::time::Duration],
    session_id: &str,
    url: &str,
) -> bool {
    let mut waits = backoff.iter();
    loop {
        let retryable = match request().send().await {
            Ok(response) if response.status().is_success() => {
                info!(%session_id, %url, status = %response.status(), "SRS: recording posted to webhook");
                return true;
            }
            Ok(response) => {
                let status = response.status();
                error!(%session_id, %url, %status, "SRS: webhook returned non-success status");
                status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            }
            Err(error) => {
                error!(%session_id, %url, %error, "SRS: failed to POST recording to webhook");
                true
            }
        };
        match waits.next() {
            Some(wait) if retryable => tokio::time::sleep(*wait).await,
            _ => return false,
        }
    }
}

/// Collect audio files from the recording directory.
///
/// Returns `(filename, file_contents)` pairs for every file that isn't
/// `metadata.json`.  RTPEngine writes recording files (WAV, PCAP, etc.)
/// to the `record-path` directory — we pick up everything it left behind.
async fn collect_audio_files(recording_dir: &str) -> Vec<(String, Vec<u8>)> {
    let dir = Path::new(recording_dir);
    if !dir.is_dir() {
        return Vec::new();
    }

    let mut files = Vec::new();
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(entries) => entries,
        Err(error) => {
            error!(
                dir = %dir.display(),
                error = %error,
                "SRS: failed to read recording directory for audio upload"
            );
            return Vec::new();
        }
    };

    while let Ok(Some(entry)) = entries.next_entry().await {
        let path = entry.path();

        // Skip directories and metadata.json.
        if path.is_dir() {
            continue;
        }
        let filename = match path.file_name().and_then(|name| name.to_str()) {
            Some(name) => name.to_string(),
            None => continue,
        };
        if filename == "metadata.json" {
            continue;
        }

        // Read the file contents.
        match tokio::fs::read(&path).await {
            Ok(data) => {
                info!(
                    filename = %filename,
                    size_bytes = data.len(),
                    "SRS: collected audio file for upload"
                );
                files.push((filename, data));
            }
            Err(error) => {
                error!(
                    path = %path.display(),
                    error = %error,
                    "SRS: failed to read audio file"
                );
            }
        }
    }

    files
}

/// Map file extension to MIME type for the upload part.
fn mime_for_extension(filename: &str) -> String {
    let extension = filename
        .rsplit('.')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    match extension.as_str() {
        "wav" => "audio/wav",
        "mp3" => "audio/mpeg",
        "ogg" => "audio/ogg",
        "opus" => "audio/opus",
        "pcm" | "raw" => "audio/L16",
        "pcap" => "application/vnd.tcpdump.pcap",
        "mp4" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        _ => "application/octet-stream",
    }
    .to_string()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::srs::{ParticipantRecord, StreamRecord};

    fn test_record() -> RecordingRecord {
        RecordingRecord {
            session_id: "test-session-001".to_string(),
            recording_call_id: "call-1".to_string(),
            original_call_id: None,
            participants: vec![ParticipantRecord {
                participant_id: "p1".to_string(),
                aor: "sip:alice@example.com".to_string(),
                name: None,
            }],
            streams: vec![StreamRecord {
                stream_id: "s1".to_string(),
                label: "caller-audio".to_string(),
            }],
            state: "completed".to_string(),
            duration_secs: 120,
            recording_dir: Some("/tmp/test/test-session-001".to_string()),
        }
    }

    #[tokio::test]
    async fn file_backend_writes_metadata() {
        // A directory of this test's own: a fixed name under the system temp
        // dir is shared by every process running the test at once, and each
        // one's cleanup removed what another had just written.
        let directory = tempfile::tempdir().expect("temp dir");
        let temp_dir = directory.path().to_path_buf();

        let config = SrsConfig {
            enabled: true,
            recording_dir: temp_dir.display().to_string(),
            max_sessions: 100,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
            app: None,
        };

        // The session's own directory, named by siphon's key: the metadata
        // goes there, never under the SRC's session_id.
        let session_dir = temp_dir.join("0123456789abcdef0123456789abcdef");
        let record = RecordingRecord {
            recording_dir: Some(session_dir.display().to_string()),
            ..test_record()
        };
        store_recording(&config, &record).await;

        let metadata_path = session_dir.join("metadata.json");
        assert!(!temp_dir.join("test-session-001").exists());
        assert!(metadata_path.exists());

        let content = tokio::fs::read_to_string(&metadata_path).await.unwrap();
        assert!(content.contains("test-session-001"));
        assert!(content.contains("alice@example.com"));
        assert!(content.contains("caller-audio"));

        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["session_id"], "test-session-001");
        assert_eq!(parsed["duration_secs"], 120);
    }

    #[tokio::test]
    async fn none_backend_stores_nothing_where_file_would_write_metadata() {
        let directory = tempfile::tempdir().expect("temp dir");
        let temp_dir = directory.path().to_path_buf();
        let session = |key: &str| {
            let dir = temp_dir.join(key);
            (
                dir.clone(),
                RecordingRecord {
                    recording_dir: Some(dir.display().to_string()),
                    ..test_record()
                },
            )
        };
        let config = |backend: &str| SrsConfig {
            enabled: true,
            recording_dir: temp_dir.display().to_string(),
            max_sessions: 100,
            backend: backend.to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
            app: Some("recorder".to_string()),
        };

        // A controller that owns the recording has already imported the audio and removed the
        // session's directory: with `none` nothing brings it back.
        let (removed, record) = session("0123456789abcdef0123456789abcdef");
        store_recording(&config("none"), &record).await;
        assert!(!removed.exists(), "none created {}", removed.display());

        // The control: the same session with `file` gets its directory and metadata.json back,
        // which is exactly what `none` exists to prevent.
        let (written, record) = session("fedcba9876543210fedcba9876543210");
        store_recording(&config("file"), &record).await;
        assert!(written.join("metadata.json").exists());
    }

    #[tokio::test]
    async fn collect_audio_files_skips_metadata() {
        let directory = tempfile::tempdir().expect("temp dir");
        let temp_dir = directory.path().to_path_buf();

        // Create fake audio files and a metadata.json.
        tokio::fs::write(temp_dir.join("metadata.json"), b"{}")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.join("call-123_a_b.wav"), b"RIFF....")
            .await
            .unwrap();
        tokio::fs::write(temp_dir.join("call-123_c_d.wav"), b"RIFF....")
            .await
            .unwrap();

        let files = collect_audio_files(&temp_dir.display().to_string()).await;
        assert_eq!(
            files.len(),
            2,
            "should collect 2 audio files, not metadata.json"
        );
        let names: Vec<&str> = files.iter().map(|(name, _)| name.as_str()).collect();
        assert!(!names.contains(&"metadata.json"));
    }

    #[tokio::test]
    async fn collect_audio_files_empty_dir() {
        let directory = tempfile::tempdir().expect("temp dir");

        let files = collect_audio_files(&directory.path().display().to_string()).await;
        assert!(files.is_empty());
    }

    #[tokio::test]
    async fn collect_audio_files_nonexistent_dir() {
        let files = collect_audio_files("/tmp/siphon-nonexistent-dir-12345").await;
        assert!(files.is_empty());
    }

    #[test]
    fn mime_types_for_common_extensions() {
        assert_eq!(mime_for_extension("call.wav"), "audio/wav");
        assert_eq!(mime_for_extension("call.mp3"), "audio/mpeg");
        assert_eq!(mime_for_extension("call.opus"), "audio/opus");
        assert_eq!(
            mime_for_extension("call.pcap"),
            "application/vnd.tcpdump.pcap"
        );
        assert_eq!(mime_for_extension("call.raw"), "audio/L16");
        assert_eq!(mime_for_extension("call.xyz"), "application/octet-stream");
    }

    #[test]
    fn recording_record_json_structure() {
        let record = test_record();
        let json = serde_json::to_string_pretty(&record).unwrap();

        // Verify key fields are present.
        assert!(json.contains("\"session_id\""));
        assert!(json.contains("\"recording_call_id\""));
        assert!(json.contains("\"participants\""));
        assert!(json.contains("\"streams\""));
        assert!(json.contains("\"duration_secs\""));
        assert!(json.contains("\"state\""));
    }

    /// An endpoint answering `statuses` in turn, one per connection; returns
    /// its URL and how many requests it got.
    async fn scripted_endpoint(
        statuses: Vec<u16>,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/recordings", listener.local_addr().unwrap());
        let served = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = std::sync::Arc::clone(&served);
        tokio::spawn(async move {
            for status in statuses {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let mut buffer = vec![0u8; 65536];
                let _ = stream.read(&mut buffer).await;
                counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let reply = format!(
                    "HTTP/1.1 {status} X\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
                );
                let _ = stream.write_all(reply.as_bytes()).await;
            }
        });
        (url, served)
    }

    fn post(url: &str) -> reqwest::RequestBuilder {
        reqwest::Client::new().post(url).body("{}")
    }

    const NO_WAIT: [std::time::Duration; 3] = [std::time::Duration::ZERO; 3];

    #[tokio::test]
    async fn a_server_error_is_retried_until_the_endpoint_takes_it() {
        let (url, served) = scripted_endpoint(vec![503, 500, 200]).await;
        assert!(post_with_retry(|| post(&url), &NO_WAIT, "s", &url).await);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 3);
    }

    #[tokio::test]
    async fn a_client_error_is_not_sent_again() {
        let (url, served) = scripted_endpoint(vec![400, 200]).await;
        assert!(!post_with_retry(|| post(&url), &NO_WAIT, "s", &url).await);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn too_many_requests_is_retried() {
        let (url, served) = scripted_endpoint(vec![429, 200]).await;
        assert!(post_with_retry(|| post(&url), &NO_WAIT, "s", &url).await);
        assert_eq!(served.load(std::sync::atomic::Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn retries_end_with_the_backoff() {
        let (url, served) = scripted_endpoint(vec![503; 6]).await;
        assert!(!post_with_retry(|| post(&url), &NO_WAIT, "s", &url).await);
        assert_eq!(
            served.load(std::sync::atomic::Ordering::SeqCst),
            4,
            "one attempt and one per wait"
        );
    }
}
