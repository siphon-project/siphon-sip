//! SRS storage backends — persist recording metadata after session ends.
//!
//! Two backends are supported:
//! - **File**: Writes a JSON metadata file per session alongside the audio files.
//! - **HTTP**: POSTs JSON metadata to a webhook endpoint.

use std::path::Path;

use tracing::{error, info};

use super::RecordingRecord;
use crate::config::SrsConfig;

/// Store a completed recording using the configured backend.
pub async fn store_recording(config: &SrsConfig, record: &RecordingRecord) {
    match config.backend.as_str() {
        "http" => store_http(config, record).await,
        _ => store_file(config, record).await,
    }
}

/// File backend — write JSON metadata to disk.
async fn store_file(config: &SrsConfig, record: &RecordingRecord) {
    let base_dir = config
        .file
        .as_ref()
        .map(|file_config| file_config.base_dir.clone())
        .unwrap_or_else(|| config.recording_dir.clone());

    let dir = Path::new(&base_dir).join(&record.session_id);

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

    let client = reqwest::Client::new();

    let should_upload_audio = http_config.upload_audio && record.recording_dir.is_some();

    let request_builder = if should_upload_audio {
        // Multipart upload: metadata JSON + audio files.
        let recording_dir = record.recording_dir.as_ref().unwrap();
        let audio_files = collect_audio_files(recording_dir).await;

        let mut form = reqwest::multipart::Form::new().part(
            "metadata",
            reqwest::multipart::Part::text(json)
                .mime_str("application/json")
                .unwrap_or_else(|_| reqwest::multipart::Part::text("{}")),
        );

        for (index, (filename, data)) in audio_files.into_iter().enumerate() {
            let mime_type = mime_for_extension(&filename);
            let part_name = format!("audio_{index}");
            let part = reqwest::multipart::Part::bytes(data)
                .file_name(filename.clone())
                .mime_str(&mime_type)
                .unwrap_or_else(|_| reqwest::multipart::Part::bytes(Vec::new()));

            form = form.part(part_name, part);
            info!(
                session_id = %record.session_id,
                filename = %filename,
                "SRS: attaching audio file to upload"
            );
        }

        let mut builder = client.post(&http_config.url).multipart(form);
        if let Some(auth_header) = &http_config.auth_header {
            builder = builder.header("Authorization", auth_header);
        }
        builder
    } else {
        // Metadata-only JSON POST.
        let mut builder = client
            .post(&http_config.url)
            .header("Content-Type", "application/json")
            .body(json);
        if let Some(auth_header) = &http_config.auth_header {
            builder = builder.header("Authorization", auth_header);
        }
        builder
    };

    match request_builder.send().await {
        Ok(response) => {
            let status = response.status();
            if status.is_success() {
                info!(
                    session_id = %record.session_id,
                    url = %http_config.url,
                    status = %status,
                    upload_audio = should_upload_audio,
                    "SRS: recording posted to webhook"
                );
            } else {
                error!(
                    session_id = %record.session_id,
                    url = %http_config.url,
                    status = %status,
                    "SRS: webhook returned non-success status"
                );
            }
        }
        Err(error) => {
            error!(
                session_id = %record.session_id,
                url = %http_config.url,
                error = %error,
                "SRS: failed to POST recording to webhook"
            );
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
        let temp_dir = std::env::temp_dir().join("siphon-srs-test");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;

        let config = SrsConfig {
            enabled: true,
            recording_dir: temp_dir.display().to_string(),
            max_sessions: 100,
            backend: "file".to_string(),
            file: None,
            http: None,
            rtpengine_profile: "srs_recording".to_string(),
        };

        let record = test_record();
        store_recording(&config, &record).await;

        let metadata_path = temp_dir.join("test-session-001").join("metadata.json");
        assert!(metadata_path.exists());

        let content = tokio::fs::read_to_string(&metadata_path).await.unwrap();
        assert!(content.contains("test-session-001"));
        assert!(content.contains("alice@example.com"));
        assert!(content.contains("caller-audio"));

        // Verify it's valid JSON.
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["session_id"], "test-session-001");
        assert_eq!(parsed["duration_secs"], 120);

        // Clean up.
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn collect_audio_files_skips_metadata() {
        let temp_dir = std::env::temp_dir().join("siphon-srs-audio-test");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

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

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
    }

    #[tokio::test]
    async fn collect_audio_files_empty_dir() {
        let temp_dir = std::env::temp_dir().join("siphon-srs-audio-empty");
        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
        tokio::fs::create_dir_all(&temp_dir).await.unwrap();

        let files = collect_audio_files(&temp_dir.display().to_string()).await;
        assert!(files.is_empty());

        let _ = tokio::fs::remove_dir_all(&temp_dir).await;
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
}
