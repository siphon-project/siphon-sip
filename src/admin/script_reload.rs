//! `POST /admin/script/reload`: recompile the script, and read the
//! `script_config` file again, on request.
//!
//! Split out of `admin/mod.rs` to keep that file inside its size budget.

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Json, Response};
use tracing::{error, info};

use super::AdminState;

/// `POST /admin/script/reload` — recompile the Python script now.
///
/// The inotify watcher already reloads on write; this is for the case where an
/// operator cannot rely on it (a config-map mount whose events do not fire, an
/// editor writing through a rename) and, more usefully, gives them the compile
/// error rather than leaving them to find it in the log. A failed reload keeps
/// the previous script live, which is the behaviour the watcher has, so this
/// reports the failure without changing what is running.
///
/// A file-backed `script_config:` is read again too, as `SIGHUP` does, and
/// before the script so module-level code that reads it sees the new document.
/// The reply says what became of it under `script_config` (`reloaded`,
/// `unchanged` or `failed`); a file that does not parse leaves the last good
/// document serving and is reported the way a script that does not compile is.
pub(super) async fn script_reload_handler(State(state): State<AdminState>) -> Response {
    use crate::script::script_config::ReloadOutcome;

    let Some(ref engine) = state.script_engine else {
        return (
            StatusCode::NOT_IMPLEMENTED,
            Json(serde_json::json!({ "error": "no script engine on this node" })),
        )
            .into_response();
    };

    let mut body = serde_json::Map::new();
    let mut failed = false;
    match state.script_config.as_ref().map(|store| store.reload()) {
        None | Some(ReloadOutcome::NotFileBacked) => {}
        Some(ReloadOutcome::Reloaded) => {
            body.insert("script_config".into(), "reloaded".into());
        }
        Some(ReloadOutcome::Unchanged) => {
            body.insert("script_config".into(), "unchanged".into());
        }
        // Already logged at error by the store, with the file and the reason.
        Some(ReloadOutcome::Failed(reason)) => {
            failed = true;
            body.insert("script_config".into(), "failed".into());
            body.insert("script_config_error".into(), reason.into());
        }
    }

    match engine.reload() {
        Ok(()) => {
            info!("admin: script reloaded");
            body.insert("reloaded".into(), true.into());
        }
        Err(error) => {
            let detail = error.to_string();
            error!(%detail, "admin: script reload failed; previous script stays live");
            failed = true;
            body.insert("reloaded".into(), false.into());
            body.insert("error".into(), detail.into());
            body.insert(
                "detail".into(),
                "the previously loaded script is still running".into(),
            );
        }
    }

    let status = if failed {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };
    (status, Json(serde_json::Value::Object(body))).into_response()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::super::AdminFeatures;
    use super::*;

    /// Call the handler, returning the status and the JSON body.
    async fn post_script_reload(state: AdminState) -> (StatusCode, serde_json::Value) {
        let response = script_reload_handler(State(state)).await;
        let status = response.status();
        let body = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .unwrap();
        (status, serde_json::from_slice(&body).unwrap())
    }

    fn test_state() -> AdminState {
        AdminState {
            registrar: Arc::new(crate::registrar::Registrar::new(
                crate::registrar::RegistrarConfig::default(),
            )),
            start_time: std::time::Instant::now(),
            draining: None,
            auth_token: None,
            protect_reads: false,
            instance_id: None,
            features: AdminFeatures::default(),
            script_engine: None,
            script_config: None,
            ui_enabled: false,
        }
    }

    /// The admin reload reads the `script_config` file again, as SIGHUP does:
    /// an operator who cannot rely on the watcher has one call that picks up
    /// both the script and the table it walks.
    #[tokio::test(flavor = "multi_thread")]
    async fn script_reload_rereads_the_script_config_file() {
        use crate::script::script_config::{lookup, ScriptConfigStore};

        pyo3::Python::initialize();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("admin_reload_script.py");
        std::fs::write(
            &script,
            concat!(
                "from siphon import proxy\n",
                "\n",
                "@proxy.on_request\n",
                "def handle(request):\n",
                "    pass\n",
            ),
        )
        .unwrap();
        let engine = Arc::new(
            crate::script::engine::ScriptEngine::new(&crate::config::ScriptConfig {
                path: script.to_str().unwrap().to_owned(),
                reload: crate::config::ReloadMode::Sighup,
                async_pool_size: None,
                sync_pool_size: None,
                sync_pool_max: None,
                handler_stall_abort_secs: 30,
                handler_timeout_secs: None,
                executor_queue_capacity: 1024,
                include_paths: Vec::new(),
            })
            .expect("the script loads"),
        );
        let table = directory.path().join("routes.yaml");
        std::fs::write(&table, "gateway: carrier-a\n").unwrap();
        let store = Arc::new(ScriptConfigStore::from_file(&table).unwrap());
        let state = || AdminState {
            script_engine: Some(Arc::clone(&engine)),
            script_config: Some(Arc::clone(&store)),
            ..test_state()
        };
        let gateway = || {
            lookup(&store.snapshot(), "gateway")
                .unwrap()
                .as_str()
                .map(str::to_owned)
        };

        // Nothing changed on disk.
        let (status, body) = post_script_reload(state()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["reloaded"], true);
        assert_eq!(body["script_config"], "unchanged");

        // The table changes; no watcher and no signal, only the admin call.
        std::fs::write(&table, "gateway: carrier-b\n").unwrap();
        let (status, body) = post_script_reload(state()).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["reloaded"], true);
        assert_eq!(body["script_config"], "reloaded");
        assert_eq!(gateway().as_deref(), Some("carrier-b"));

        // A table that does not parse is reported, the script still reloads,
        // and the last good table keeps serving.
        std::fs::write(&table, "gateway: [unterminated\n").unwrap();
        let (status, body) = post_script_reload(state()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(body["reloaded"], true);
        assert_eq!(body["script_config"], "failed");
        assert!(
            body["script_config_error"]
                .as_str()
                .is_some_and(|reason| !reason.is_empty()),
            "{body}"
        );
        assert_eq!(gateway().as_deref(), Some("carrier-b"));
    }

    /// Without a file-backed `script_config` the reply says nothing about one.
    #[tokio::test(flavor = "multi_thread")]
    async fn script_reload_without_a_script_config_file_does_not_mention_it() {
        use crate::script::script_config::ScriptConfigStore;

        pyo3::Python::initialize();
        let directory = tempfile::tempdir().unwrap();
        let script = directory.path().join("admin_reload_plain_script.py");
        std::fs::write(&script, "from siphon import proxy\n").unwrap();
        let engine = Arc::new(
            crate::script::engine::ScriptEngine::new(&crate::config::ScriptConfig {
                path: script.to_str().unwrap().to_owned(),
                reload: crate::config::ReloadMode::Sighup,
                async_pool_size: None,
                sync_pool_size: None,
                sync_pool_max: None,
                handler_stall_abort_secs: 30,
                handler_timeout_secs: None,
                executor_queue_capacity: 1024,
                include_paths: Vec::new(),
            })
            .expect("the script loads"),
        );
        let (status, body) = post_script_reload(AdminState {
            script_engine: Some(engine),
            script_config: Some(Arc::new(ScriptConfigStore::empty())),
            ..test_state()
        })
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, serde_json::json!({ "reloaded": true }));
    }
}
