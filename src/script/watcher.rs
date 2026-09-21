//! Hot-reload triggers: the inotify watcher, and the SIGHUP handler.
//!
//! Both end at the same place, [`ScriptEngine::reload`], and both are governed
//! by what a reload *costs*: the script is re-executed in a fresh namespace and
//! every helper module under the script directories is purged from
//! `sys.modules`, so module-level state starts empty. A reload nobody asked for
//! is not free — it is a process losing whatever it was holding.
//!
//! That is why the watcher asks [`ScriptEngine::reloads_for`] rather than
//! reloading for any `.py` file in a watched directory. Two siphon processes
//! whose scripts share a directory used to reload each other, and the one that
//! had not changed paid the whole cost.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tracing::{debug, error, info, warn};

use super::engine::ScriptEngine;

/// How long the watcher waits for the events of one write burst to stop
/// arriving before it reloads.
///
/// An editor saving a file emits several events, and a deploy writing three
/// helpers emits three bursts of them; each used to be a full recompile of the
/// script tree. 250 ms is comfortably longer than an editor's write-rename
/// sequence and short enough to feel immediate.
const COALESCE_WINDOW: Duration = Duration::from_millis(250);

/// Spawn a background task that watches the script directories and reloads the
/// script when something it actually runs changes. Returns immediately.
///
/// A no-op under `reload: sighup`, which is the whole of that mode's meaning —
/// see [`spawn_sighup_reloader`], which is what makes it reload at all.
pub fn spawn_file_watcher(engine: Arc<ScriptEngine>) {
    use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    if !engine.auto_reload() {
        info!("script auto-reload disabled (mode: sighup); SIGHUP reloads the script");
        return;
    }

    let path = engine.script_path().to_owned();
    let watch_dirs = engine.watch_dirs();

    // `notify` v8 uses std channels for sync, we bridge to tokio via spawn_blocking.
    tokio::task::spawn_blocking(move || {
        let (sender, receiver) = mpsc::channel::<notify::Result<Event>>();

        let mut watcher = match RecommendedWatcher::new(sender, Config::default()) {
            Ok(watcher) => watcher,
            Err(error) => {
                error!(%error, "failed to create file watcher");
                return;
            }
        };

        // Watch the script directory (and any include dirs) so we catch both the
        // main script and sibling helper `.py` files, and renames/recreates
        // (editors like vim write to a temp file then rename). NonRecursive: only
        // direct children fire events, so a helper laid out as a package
        // (`lib/mypkg/__init__.py`) under an include dir does not.
        let mut watched_any = false;
        for watch_dir in &watch_dirs {
            match watcher.watch(watch_dir, RecursiveMode::NonRecursive) {
                Ok(()) => {
                    watched_any = true;
                    info!(path = %watch_dir.display(), "watching script directory");
                }
                Err(error) => {
                    // A missing include dir is not fatal — keep watching the rest.
                    warn!(%error, path = %watch_dir.display(), "failed to watch directory");
                }
            }
        }
        if !watched_any {
            error!("no script directories could be watched; hot-reload disabled");
            return;
        }

        info!(path = %path.display(), "file watcher started");

        while let Ok(event) = receiver.recv() {
            let Some(changed) = relevant_path(&engine, event) else {
                continue;
            };

            // Absorb the rest of the burst before reloading. Without this an
            // editor's several events per save, or a deploy writing three
            // helpers, each cost a full recompile of the script tree.
            let mut absorbed = 0usize;
            while let Ok(further) = receiver.recv_timeout(COALESCE_WINDOW) {
                if relevant_path(&engine, further).is_some() {
                    absorbed += 1;
                }
            }

            info!(
                path = %changed.display(),
                coalesced = absorbed,
                "script source changed; reloading"
            );
            if let Err(error) = engine.reload() {
                warn!(%error, "hot-reload failed");
            }
        }
    });
}

/// The changed path a watcher event carries, when it is one this engine should
/// reload for; `None` for anything else.
fn relevant_path(
    engine: &Arc<ScriptEngine>,
    event: notify::Result<notify::Event>,
) -> Option<PathBuf> {
    use notify::{Event, EventKind};

    match event {
        Ok(Event {
            kind: EventKind::Modify(_) | EventKind::Create(_),
            paths,
            ..
        }) => {
            let changed = paths.into_iter().find(|path| engine.reloads_for(path));
            if changed.is_none() {
                debug!("file change is not this script's; not reloading");
            }
            changed
        }
        Ok(_) => None, // Remove / Access / Other are not a new source to load
        Err(error) => {
            warn!(%error, "file watcher error");
            None
        }
    }
}

/// Reload the script on `SIGHUP`, for the life of the process.
///
/// Installed in **both** reload modes, not only `sighup`. `reload: sighup` was
/// documented as "only reload on SIGHUP" and no SIGHUP handler existed
/// anywhere, so choosing it meant never reloading — silently, and with `kill
/// -HUP` terminating the process on the default disposition. That is the worst
/// of the three possible behaviours: an operator picks the mode precisely to
/// control *when* module state is wiped, and gets a script frozen at boot.
///
/// Under `auto` it is a second trigger beside the watcher, which costs nothing
/// and removes a surprise: `POST /admin/script/reload` already reloads
/// regardless of mode, so a signal that worked in one mode and not the other
/// would be the same class of trap this replaces.
#[cfg(unix)]
pub fn spawn_sighup_reloader(engine: Arc<ScriptEngine>) {
    use tokio::signal::unix::{signal, SignalKind};

    tokio::spawn(async move {
        let mut hangup = match signal(SignalKind::hangup()) {
            Ok(stream) => stream,
            Err(error) => {
                error!(%error, "failed to install the SIGHUP handler; SIGHUP will terminate siphon");
                return;
            }
        };
        info!("SIGHUP reloads the script");
        while hangup.recv().await.is_some() {
            info!("SIGHUP received; reloading script");
            if let Err(error) = engine.reload() {
                warn!(%error, "SIGHUP reload failed");
            }
        }
    });
}

#[cfg(not(unix))]
pub fn spawn_sighup_reloader(_engine: Arc<ScriptEngine>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{CreateKind, ModifyKind};
    use notify::{Event, EventKind};
    use std::path::Path;

    /// An engine over a real script on disk, plus the helper it imports and a
    /// sibling it does not — the two-processes-one-directory shape.
    ///
    /// The helper's module name is unique per call. `sys.modules` is
    /// process-global and keyed by name, so two fixtures sharing one would have
    /// the second import resolve to the first's already-cached module, whose
    /// `__file__` points into a temp directory the second engine knows nothing
    /// about. That is an artefact of running many engines in one process; a
    /// deployment runs one script and cannot hit it.
    fn engine_with_sibling() -> (tempfile::TempDir, Arc<ScriptEngine>, PathBuf, PathBuf) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);

        pyo3::Python::initialize();
        let dir = tempfile::TempDir::new().unwrap();
        let module = format!("watcher_imported_{unique}");
        let imported = dir.path().join(format!("{module}.py"));
        let stranger = dir.path().join("watcher_stranger.py");
        let script = dir.path().join("watcher_main.py");

        std::fs::write(&imported, "VALUE = 1\n").unwrap();
        std::fs::write(&stranger, "VALUE = 2\n").unwrap();
        std::fs::write(
            &script,
            format!(
                concat!(
                    "from siphon import proxy\n",
                    "import {}\n",
                    "\n",
                    "@proxy.on_request\n",
                    "def handle(request):\n",
                    "    pass\n",
                ),
                module
            ),
        )
        .unwrap();

        let config = crate::config::ScriptConfig {
            path: script.to_str().unwrap().to_owned(),
            reload: crate::config::ReloadMode::Auto,
            async_pool_size: None,
            sync_pool_size: None,
            sync_pool_max: None,
            handler_stall_abort_secs: 30,
            handler_timeout_secs: None,
            executor_queue_capacity: 1024,
            include_paths: Vec::new(),
        };
        let engine = Arc::new(ScriptEngine::new(&config).expect("initial load"));
        (dir, engine, imported, stranger)
    }

    fn modify_event(path: &Path) -> notify::Result<Event> {
        Ok(Event {
            kind: EventKind::Modify(ModifyKind::Any),
            paths: vec![path.to_path_buf()],
            attrs: Default::default(),
        })
    }

    #[test]
    fn a_change_to_an_imported_helper_is_a_reload() {
        let (_dir, engine, imported, _stranger) = engine_with_sibling();
        assert_eq!(
            relevant_path(&engine, modify_event(&imported)),
            Some(imported)
        );
    }

    #[test]
    fn a_change_to_a_sibling_the_script_never_imported_is_not() {
        let (_dir, engine, _imported, stranger) = engine_with_sibling();
        assert!(relevant_path(&engine, modify_event(&stranger)).is_none());
    }

    #[test]
    fn a_create_of_the_script_itself_is_a_reload() {
        // Editors write a temp file and rename it into place, so the event that
        // carries a save is often a Create rather than a Modify.
        let (_dir, engine, _imported, _stranger) = engine_with_sibling();
        let script = engine.script_path().to_path_buf();
        assert_eq!(
            relevant_path(
                &engine,
                Ok(Event {
                    kind: EventKind::Create(CreateKind::Any),
                    paths: vec![script.clone()],
                    attrs: Default::default(),
                })
            ),
            Some(script)
        );
    }

    #[test]
    fn a_removal_is_not_a_reload() {
        // There is no new source to load, and reloading would fail and keep the
        // previous version anyway — a warn per delete and nothing else.
        let (_dir, engine, imported, _stranger) = engine_with_sibling();
        assert!(relevant_path(
            &engine,
            Ok(Event {
                kind: EventKind::Remove(notify::event::RemoveKind::Any),
                paths: vec![imported],
                attrs: Default::default(),
            })
        )
        .is_none());
    }

    #[test]
    fn a_watcher_error_is_reported_and_is_not_a_reload() {
        let (_dir, engine, _imported, _stranger) = engine_with_sibling();
        assert!(relevant_path(
            &engine,
            Err(notify::Error::generic("the watch was dropped"))
        )
        .is_none());
    }

    /// The coalescing contract, exercised against the same channel shape the
    /// watcher drains: a burst of events inside the window makes one reload.
    ///
    /// Drives the loop's own draining rather than the spawned task, so the test
    /// needs no inotify and no timing slack beyond the window itself.
    #[test]
    fn a_burst_of_events_inside_the_window_coalesces_into_one_reload() {
        let (_dir, engine, imported, stranger) = engine_with_sibling();
        let (sender, receiver) = std::sync::mpsc::channel::<notify::Result<Event>>();

        // A deploy writing the helper three times, with an unrelated sibling's
        // event in the middle — which must neither trigger nor extend anything.
        for _ in 0..3 {
            sender.send(modify_event(&imported)).unwrap();
        }
        sender.send(modify_event(&stranger)).unwrap();
        drop(sender);

        let mut reloads = 0usize;
        let mut absorbed_total = 0usize;
        while let Ok(event) = receiver.recv() {
            if relevant_path(&engine, event).is_none() {
                continue;
            }
            reloads += 1;
            while let Ok(further) = receiver.recv_timeout(COALESCE_WINDOW) {
                if relevant_path(&engine, further).is_some() {
                    absorbed_total += 1;
                }
            }
        }

        assert_eq!(reloads, 1, "three writes must recompile the script once");
        assert_eq!(
            absorbed_total, 2,
            "the other two relevant events were absorbed, the stranger ignored"
        );
    }
}
