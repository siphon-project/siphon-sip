//! Generic batched event sink for Python-emitted signalling events.
//!
//! v1 ships `file` (newline-delimited JSON) and `none` backends. `clickhouse`
//! and `kafka` are feature-gated stubs that degrade to `none` in this build —
//! they are a separable follow-up (heavy C/transport dependencies should not
//! land in the core binary that runs the SIP hot path).
//!
//! Rows are already-serialized JSON strings (the Python binding calls
//! `json.dumps` at the boundary, avoiding a dict→Value converter). `emit` is
//! non-blocking and drops on overflow rather than back-pressuring the dispatch
//! path.

use std::sync::Arc;

use tokio::sync::mpsc;
use tracing::warn;

use crate::config::EventSinkConfig;

/// A pluggable batch writer.
pub trait EventSinkWriter: Send + Sync {
    fn write_batch(&self, rows: &[String]);
}

/// Discards everything (`backend: none`, or unsupported backends in this build).
struct NullWriter;
impl EventSinkWriter for NullWriter {
    fn write_batch(&self, _rows: &[String]) {}
}

/// Appends each row as a line to a file.
struct FileWriter {
    path: String,
}
impl EventSinkWriter for FileWriter {
    fn write_batch(&self, rows: &[String]) {
        use std::io::Write;
        match std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
        {
            Ok(mut file) => {
                for row in rows {
                    if let Err(error) = writeln!(file, "{row}") {
                        warn!(path = %self.path, %error, "event_sink: write failed");
                        break;
                    }
                }
            }
            Err(error) => warn!(path = %self.path, %error, "event_sink: open failed"),
        }
    }
}

/// Build the configured writer. Unsupported (feature-gated) backends warn once
/// and fall back to `none`.
fn build_writer(config: &EventSinkConfig) -> Arc<dyn EventSinkWriter> {
    match config.backend.as_str() {
        "file" => match &config.file {
            Some(file) => Arc::new(FileWriter {
                path: file.path.clone(),
            }),
            None => {
                warn!("event_sink backend 'file' requires a file.path; using none");
                Arc::new(NullWriter)
            }
        },
        "none" => Arc::new(NullWriter),
        "clickhouse" | "kafka" => {
            warn!(
                backend = %config.backend,
                "event_sink backend not supported in this build (feature-gated); using none"
            );
            Arc::new(NullWriter)
        }
        other => {
            warn!(backend = %other, "unknown event_sink backend; using none");
            Arc::new(NullWriter)
        }
    }
}

/// A handle that scripts emit JSON rows to. Cheap to clone.
#[derive(Clone)]
pub struct EventSink {
    sender: mpsc::Sender<String>,
}

impl EventSink {
    /// Build the sink and spawn its background flush task. Must be called from
    /// within a Tokio runtime.
    pub fn spawn(config: &EventSinkConfig) -> EventSink {
        let writer = build_writer(config);
        let (sender, mut receiver) = mpsc::channel::<String>(10_000);
        tokio::spawn(async move {
            let mut batch: Vec<String> = Vec::with_capacity(256);
            while let Some(row) = receiver.recv().await {
                batch.push(row);
                // Opportunistically drain whatever is queued (bounded).
                while batch.len() < 1000 {
                    match receiver.try_recv() {
                        Ok(more) => batch.push(more),
                        Err(_) => break,
                    }
                }
                writer.write_batch(&batch);
                batch.clear();
            }
        });
        EventSink { sender }
    }

    /// Submit a pre-serialized JSON row. Non-blocking; drops on overflow.
    pub fn emit(&self, row: String) {
        if self.sender.try_send(row).is_err() {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics
                    .diameter_request_errors_total
                    .with_label_values(&["event_sink_overflow"])
                    .inc();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EventSinkFileConfig;

    #[tokio::test]
    async fn file_backend_writes_rows() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("siphon-diameter-events-{}.jsonl", std::process::id()));
        let path_str = path.to_string_lossy().to_string();
        let _ = std::fs::remove_file(&path);

        let sink = EventSink::spawn(&EventSinkConfig {
            backend: "file".into(),
            file: Some(EventSinkFileConfig {
                path: path_str.clone(),
            }),
        });
        sink.emit(r#"{"event":"relay","code":2001}"#.to_string());
        sink.emit(r#"{"event":"reject","code":3002}"#.to_string());

        // Give the flush task a moment.
        for _ in 0..50 {
            if std::fs::read_to_string(&path).map(|c| c.lines().count()).unwrap_or(0) >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(contents.lines().count(), 2);
        assert!(contents.contains("\"code\":2001"));
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn none_backend_is_noop() {
        let sink = EventSink::spawn(&EventSinkConfig {
            backend: "none".into(),
            file: None,
        });
        sink.emit("{}".to_string()); // must not panic
    }
}
