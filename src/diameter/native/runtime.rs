//! What the Diameter server is configured with, for Rust handlers: the
//! identity of each tenant and the event sink, each the one the script path
//! has.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};

use crate::config::DiameterConfig;
use crate::diameter::event_sink::EventSink;

/// Built once at startup from the `diameter:` block.
pub(crate) struct ServerRuntime {
    /// Origin-Host and Origin-Realm by tenant name.
    identities: HashMap<String, (String, String)>,
    /// The tenant names, in the order the configuration lists them.
    tenants: Vec<String>,
    event_sink: Option<Arc<EventSink>>,
}

impl ServerRuntime {
    /// The identities of `config`'s tenants (the flat single-domain form is
    /// the tenant `default`), with `event_sink`.
    pub(crate) fn new(config: &DiameterConfig, event_sink: Option<Arc<EventSink>>) -> Self {
        let effective = config.effective_tenants();
        let tenants = effective.keys().cloned().collect();
        let identities = effective
            .into_iter()
            .map(|(name, tenant)| {
                (
                    name,
                    (tenant.identity.origin_host, tenant.identity.origin_realm),
                )
            })
            .collect();
        Self {
            identities,
            tenants,
            event_sink,
        }
    }

    pub(crate) fn tenant_identity(&self, tenant: &str) -> Option<(&str, &str)> {
        self.identities
            .get(tenant)
            .map(|(origin_host, origin_realm)| (origin_host.as_str(), origin_realm.as_str()))
    }
}

static RUNTIME: OnceLock<ServerRuntime> = OnceLock::new();

/// Whether `config` makes this node a Diameter server (`listen`, or a
/// tenant): the nodes whose script has `diameter.event_sink`.
fn is_server(config: &DiameterConfig) -> bool {
    config.listen.is_some() || !config.effective_tenants().is_empty()
}

/// Start the event sink `config` asks for and keep it, with the tenant
/// identities, for this process. Returns the sink, which is also the one
/// `diameter.event_sink` gets. Called once, on the runtime, where the
/// Diameter namespace is built; a later call changes nothing and returns the
/// sink already kept.
pub(crate) fn install(config: &DiameterConfig) -> Option<Arc<EventSink>> {
    RUNTIME
        .get_or_init(|| {
            let event_sink = config
                .event_sink
                .as_ref()
                .filter(|_| is_server(config))
                .map(|sink| Arc::new(EventSink::spawn(sink)));
            ServerRuntime::new(config, event_sink)
        })
        .event_sink
        .clone()
}

/// The Origin-Host and Origin-Realm configured for `tenant`
/// (`diameter.tenants.<name>.identity`; the tenant `default` of a
/// single-domain server has the top-level `origin_host` / `origin_realm`).
/// None for a tenant the configuration does not have, and before the server
/// has read its configuration.
///
/// This is the configured identity. A connection on which
/// `@diameter.on_inbound_cer` chose another one answers with that:
/// [`NativeRequest::origin_host`](super::NativeRequest::origin_host).
pub fn tenant_identity(tenant: &str) -> Option<(&'static str, &'static str)> {
    RUNTIME.get()?.tenant_identity(tenant)
}

/// The names of the configured tenants, in the order the configuration lists
/// them under `diameter.tenants`; `["default"]` for a single-domain server.
/// Empty on a node that is not a Diameter server, and before the server has
/// read its configuration.
pub fn tenants() -> Vec<&'static str> {
    RUNTIME
        .get()
        .map(|runtime| runtime.tenants.iter().map(String::as_str).collect())
        .unwrap_or_default()
}

/// The event sink of `diameter.event_sink`, the one a script emits to with
/// `diameter.event_sink.emit(row)`: a row a handler emits here lands in the
/// same place. [`EventSink::emit`] takes the row as serialized JSON, does not
/// block, and drops the row when the sink's queue is full. None when no
/// event sink is configured, and on a node that is not a Diameter server
/// (no `diameter.listen` and no tenant), where a script has none either.
pub fn event_sink() -> Option<Arc<EventSink>> {
    RUNTIME.get()?.event_sink.clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(yaml: &str) -> DiameterConfig {
        serde_saphyr::from_str(yaml).expect("the configuration parses")
    }

    #[test]
    fn each_tenant_has_its_own_identity() {
        let runtime = ServerRuntime::new(
            &config(concat!(
                "tenants:\n",
                "  alpha:\n",
                "    identity:\n",
                "      origin_host: agent.alpha.example.com\n",
                "      origin_realm: alpha.example.com\n",
                "  beta:\n",
                "    identity:\n",
                "      origin_host: agent.beta.example.com\n",
                "      origin_realm: beta.example.com\n",
            )),
            None,
        );
        assert_eq!(
            runtime.tenant_identity("alpha"),
            Some(("agent.alpha.example.com", "alpha.example.com"))
        );
        assert_eq!(
            runtime.tenant_identity("beta"),
            Some(("agent.beta.example.com", "beta.example.com"))
        );
        assert_eq!(runtime.tenant_identity("gamma"), None);
        assert_eq!(runtime.tenant_identity("default"), None);
    }

    #[test]
    fn a_single_domain_server_is_the_tenant_default() {
        let runtime = ServerRuntime::new(
            &config(concat!(
                "origin_host: agent.example.com\n",
                "origin_realm: example.com\n",
                "clients:\n",
                "  - name: mme\n",
                "    allowed_ips: [\"192.0.2.0/24\"]\n",
            )),
            None,
        );
        assert_eq!(
            runtime.tenant_identity("default"),
            Some(("agent.example.com", "example.com"))
        );
    }

    #[test]
    fn a_client_only_configuration_has_no_tenant() {
        let runtime = ServerRuntime::new(
            &config("origin_host: scscf.example.com\norigin_realm: example.com\n"),
            None,
        );
        assert_eq!(runtime.tenant_identity("default"), None);
    }

    /// A node that only dials out has no `diameter.event_sink` in its script,
    /// so a configured sink is not started for Rust either.
    #[test]
    fn only_a_server_has_an_event_sink() {
        let sink = "event_sink:\n  backend: none\n";
        assert!(!is_server(&config(&format!(
            "origin_host: scscf.example.com\norigin_realm: example.com\n{sink}"
        ))));
        assert!(is_server(&config(&format!(
            "listen:\n  tcp: \"192.0.2.1:3868\"\n{sink}"
        ))));
        assert!(is_server(&config(&format!(
            "tenants:\n  alpha:\n    identity:\n      origin_host: a.example.com\n{sink}"
        ))));
    }

    /// The process-wide accessors, the way the server sets them up: the sink
    /// `install` returns is the one handed to the script namespace, and a row
    /// a Rust handler emits lands in the file a script's row lands in.
    #[test]
    fn a_handler_and_a_script_emit_to_the_same_sink() {
        crate::own_process::run(
            concat!(
                module_path!(),
                "::a_handler_and_a_script_emit_to_the_same_sink"
            ),
            handler_and_script_emit_to_the_same_sink,
        );
    }

    fn handler_and_script_emit_to_the_same_sink() {
        use crate::diameter::native::tests::{request, TEST_APPLICATION, TEST_COMMAND};
        use crate::diameter::native::{
            event_sink, tenant_identity, NativeHandlers, NativeHarness, NativeOutcome,
        };
        use pyo3::prelude::*;

        let directory = tempfile::tempdir().expect("a temporary directory");
        let path = directory.path().join("events.jsonl");
        let yaml = format!(
            concat!(
                "tenants:\n",
                "  alpha:\n",
                "    identity:\n",
                "      origin_host: agent.alpha.example.com\n",
                "      origin_realm: alpha.example.com\n",
                "  beta:\n",
                "    identity:\n",
                "      origin_host: agent.beta.example.com\n",
                "      origin_realm: beta.example.com\n",
                "event_sink:\n",
                "  backend: file\n",
                "  file:\n",
                "    path: {}\n",
            ),
            path.display()
        );

        assert!(event_sink().is_none(), "nothing before the server starts");
        assert!(tenant_identity("alpha").is_none());

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("a runtime");
        runtime.block_on(async {
            let for_script = install(&config(&yaml)).expect("a sink is configured");
            let for_rust = event_sink().expect("the same sink");
            assert!(Arc::ptr_eq(&for_script, &for_rust));
            assert_eq!(
                tenant_identity("alpha"),
                Some(("agent.alpha.example.com", "alpha.example.com"))
            );
            assert_eq!(
                tenant_identity("beta"),
                Some(("agent.beta.example.com", "beta.example.com"))
            );
            assert_eq!(tenant_identity("gamma"), None);

            // The script's row, through `diameter.event_sink.emit`.
            pyo3::Python::initialize();
            Python::attach(|python| {
                let namespace = crate::script::api::diameter::PyDiameter::new(Arc::new(
                    crate::diameter::DiameterManager::new(),
                ))
                .with_server_runtime("{}".to_owned(), Some(for_script));
                let namespace = Py::new(python, namespace).expect("the namespace");
                let row = pyo3::types::PyDict::new(python);
                row.set_item("path", "script").expect("a row");
                namespace
                    .bind(python)
                    .getattr("event_sink")
                    .and_then(|sink| sink.call_method1("emit", (row,)))
                    .expect("the script emits");
            });

            // The handler's row.
            let handlers = NativeHandlers::new()
                .handle(TEST_APPLICATION, TEST_COMMAND, |request| async move {
                    let sink = event_sink().ok_or("no event sink")?;
                    sink.emit(
                        serde_json::json!({
                            "path": "native",
                            "tenant": request.tenant(),
                            "identity": tenant_identity("beta").map(|identity| identity.0),
                        })
                        .to_string(),
                    );
                    Ok(NativeOutcome::Answer(request.answer(2001)))
                })
                .expect("a first handler");
            let outcome = NativeHarness::new(handlers)
                .with_peer("mme", "beta")
                .call(&request(TEST_APPLICATION, TEST_COMMAND))
                .await;
            assert!(outcome.answer().is_some());

            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
            let rows = loop {
                let rows: Vec<serde_json::Value> = std::fs::read_to_string(&path)
                    .unwrap_or_default()
                    .lines()
                    .map(|line| serde_json::from_str(line).expect("a JSON row"))
                    .collect();
                if rows.len() >= 2 {
                    break rows;
                }
                assert!(
                    std::time::Instant::now() < deadline,
                    "the rows never reached the file: {rows:?}"
                );
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            assert_eq!(rows.len(), 2);
            assert_eq!(rows[0]["path"], "script");
            assert_eq!(rows[1]["path"], "native");
            assert_eq!(rows[1]["tenant"], "beta");
            assert_eq!(rows[1]["identity"], "agent.beta.example.com");
        });
    }
}
