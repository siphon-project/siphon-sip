//! Recording and reading the inbound (server role) Diameter metrics.
//!
//! The three series carry a `path` label: `script` for a request
//! `@diameter.on_request` answered (and for one siphon answered in its place),
//! `native` for one a Rust handler answered
//! ([`crate::diameter::native`]).

use std::collections::BTreeMap;

use prometheus::HistogramVec;

use super::{summarise_histogram, try_metrics};

/// `path` of a request the script path answered.
pub const DIAMETER_PATH_SCRIPT: &str = "script";
/// `path` of a request a native handler answered.
pub const DIAMETER_PATH_NATIVE: &str = "native";

/// Record one inbound Diameter transaction siphon served as a server.
///
/// Takes the raw `command_code` and derives both names here rather than at the
/// call site, so the request series is labelled `CCR` and the answer series
/// `CCA` exactly as on the client side — a counter of answers labelled with the
/// request name would be a lie about which half of the exchange it counted, and
/// the two directions must not be able to drift apart on that.
///
/// Called once per dispatched request, at the point the path that answered it
/// sends the answer; `path` names that path.
pub fn record_diameter_inbound(
    command_code: u32,
    result_code: &str,
    elapsed: std::time::Duration,
    path: &'static str,
) {
    let Some(metrics) = try_metrics() else {
        return;
    };
    let request_name = crate::diameter::codec::command_name(command_code, true);
    metrics
        .diameter_inbound_requests_total
        .with_label_values(&[request_name, path])
        .inc();
    metrics
        .diameter_inbound_answers_total
        .with_label_values(&[
            crate::diameter::codec::command_name(command_code, false),
            result_code,
            path,
        ])
        .inc();
    metrics
        .diameter_inbound_duration_seconds
        .with_label_values(&[request_name, path])
        .observe(elapsed.as_secs_f64());
}

/// [`super::histogram_vec_summary_by_label`] for a histogram with more labels
/// than the one it is read by: the series that share a value of `label` are
/// added up first, so a command served on both paths is one row, not
/// whichever series was collected last.
pub fn histogram_vec_summary_merged_by_label(
    vector: &HistogramVec,
    label: &str,
) -> BTreeMap<String, serde_json::Value> {
    use prometheus::core::Collector;
    let mut merged: BTreeMap<String, prometheus::proto::Histogram> = BTreeMap::new();
    for family in vector.collect() {
        for metric in family.get_metric() {
            let key = metric
                .get_label()
                .iter()
                .find(|pair| pair.name() == label)
                .map(|pair| pair.value().to_owned())
                .unwrap_or_default();
            let histogram: &prometheus::proto::Histogram = metric.get_histogram();
            match merged.get_mut(&key) {
                None => {
                    merged.insert(key, histogram.clone());
                }
                Some(total) => {
                    total.set_sample_count(total.get_sample_count() + histogram.get_sample_count());
                    total.set_sample_sum(total.get_sample_sum() + histogram.get_sample_sum());
                    // The series of one vector share their bucket edges.
                    let mut buckets = total.get_bucket().to_vec();
                    for (bucket, other) in buckets.iter_mut().zip(histogram.get_bucket()) {
                        bucket.set_cumulative_count(
                            bucket.cumulative_count() + other.cumulative_count(),
                        );
                    }
                    total.set_bucket(buckets);
                }
            }
        }
    }
    merged
        .into_iter()
        .filter_map(|(key, histogram)| Some((key, summarise_histogram(&histogram)?)))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use prometheus::HistogramOpts;

    fn vector() -> HistogramVec {
        HistogramVec::new(
            HistogramOpts::new("test_inbound_duration_seconds", "test")
                .buckets(vec![0.01, 0.1, 1.0]),
            &["command", "path"],
        )
        .expect("a valid histogram")
    }

    #[test]
    fn series_sharing_a_command_are_one_row() {
        let vector = vector();
        vector
            .with_label_values(&["AIR", DIAMETER_PATH_NATIVE])
            .observe(0.005);
        vector
            .with_label_values(&["AIR", DIAMETER_PATH_SCRIPT])
            .observe(0.05);
        vector
            .with_label_values(&["AIR", DIAMETER_PATH_SCRIPT])
            .observe(0.05);
        vector
            .with_label_values(&["ULR", DIAMETER_PATH_SCRIPT])
            .observe(0.5);

        let summary = histogram_vec_summary_merged_by_label(&vector, "command");
        assert_eq!(summary.len(), 2);
        assert_eq!(summary["AIR"]["count"], 3);
        let sum = summary["AIR"]["sum"].as_f64().expect("a sum");
        assert!((sum - 0.105).abs() < 1e-9, "{sum}");
        // Two of the three samples are in the 0.1 bucket: the 95th
        // percentile is there, not in the bucket of the native series alone.
        let p95 = summary["AIR"]["p95"].as_f64().expect("a p95");
        assert!(p95 > 0.01 && p95 <= 0.1, "{p95}");
        assert_eq!(summary["ULR"]["count"], 1);
    }

    #[test]
    fn a_vector_nothing_was_observed_on_has_no_rows() {
        assert!(histogram_vec_summary_merged_by_label(&vector(), "command").is_empty());
    }
}
