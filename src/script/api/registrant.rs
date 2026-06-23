//! PyO3 wrapper for outbound registration — exposed to Python as `registration`.
//!
//! Scripts use:
//! ```python
//! from siphon import registration
//!
//! registration.add("sip:bob@carrier.com", "sip:registrar.carrier.com",
//!                   user="bob", password="pass123", interval=3600)
//! registration.remove("sip:bob@carrier.com")
//! registration.refresh("sip:bob@carrier.com")
//!
//! for reg in registration.list():
//!     log.info(f"{reg['aor']}: {reg['state']} expires_in={reg['expires_in']}")
//! ```

use std::sync::Arc;

use pyo3::prelude::*;
use pyo3::types::PyDict;

use crate::ipsec::{EncryptionAlgorithm, IntegrityAlgorithm};
use crate::registrant::{RegistrantCredentials, RegistrantEntry, RegistrantManager, UeIpsec};
use crate::transport::Transport;

/// Python-visible registration namespace.
#[pyclass(name = "RegistrationNamespace", skip_from_py_object)]
pub struct PyRegistration {
    inner: Arc<RegistrantManager>,
    _local_addr: std::net::SocketAddr,
}

impl PyRegistration {
    pub fn new(manager: Arc<RegistrantManager>, local_addr: std::net::SocketAddr) -> Self {
        Self {
            inner: manager,
            _local_addr: local_addr,
        }
    }
}

#[pymethods]
impl PyRegistration {
    /// Add a new outbound registration.
    ///
    /// Args:
    ///     aor: Address-of-Record (e.g. "sip:alice@carrier.com"). For IMS AKA
    ///         this is the IMPU (e.g. "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org").
    ///     registrar: Registrar URI (e.g. "sip:registrar.carrier.com:5060"). For
    ///         IMS this is the P-CSCF.
    ///     user: Authentication username. For IMS AKA this is the IMPI.
    ///     password: Authentication password (digest only; unused for AKA).
    ///     interval: Registration interval in seconds (default: manager default).
    ///     realm: Optional realm hint (derived from 401 if omitted; the home
    ///         domain for IMS).
    ///     contact: Optional Contact URI (auto-generated if omitted).
    ///     transport: Transport protocol: "udp" (default), "tcp", "tls".
    ///     auth: "digest" (default) or "aka" for IMS AKAv1-MD5 (RFC 3310 / TS 33.203).
    ///     k: Subscriber key K as 32 hex chars (required when auth="aka").
    ///     op: Operator variant OP as 32 hex chars (supply op OR opc for AKA).
    ///     opc: Pre-computed OPc as 32 hex chars (supply op OR opc for AKA).
    ///     amf: Authentication Management Field as 4 hex chars (default "8000").
    ///     sqn: Initial stored sequence number SQN_MS as 12 hex chars
    ///         (default all-zeros — correct for a fresh soft-UE).
    ///     ipsec: True to establish IPsec sec-agree with the P-CSCF
    ///         (3GPP TS 33.203). Requires auth="aka", ue_port_c, ue_port_s.
    ///     ue_port_c: UE protected client port (must also be a listen.udp port).
    ///     ue_port_s: UE protected server port (must also be a listen.udp port).
    ///     ipsec_alg: Offered integrity algorithm — "hmac-sha-1-96" (default),
    ///         "hmac-md5-96", or "hmac-sha-256-128".
    ///     ipsec_ealg: Offered encryption algorithm — "null" (default) or "aes-cbc".
    ///     imei: IMEI for the Contact +sip.instance (urn:gsma:imei). None → no
    ///         instance tag.
    ///     ims_features: Contact feature tags to advertise so the S-CSCF
    ///         registers the implied services — any of "mmtel", "video", "smsip".
    #[allow(clippy::too_many_arguments)]
    #[pyo3(signature = (aor, registrar, *, user, password="", interval=None, realm=None, contact=None, transport=None, auth=None, k=None, op=None, opc=None, amf=None, sqn=None, ipsec=false, ue_port_c=None, ue_port_s=None, ipsec_alg=None, ipsec_ealg=None, imei=None, ims_features=None))]
    fn add(
        &self,
        aor: &str,
        registrar: &str,
        user: &str,
        password: &str,
        interval: Option<u32>,
        realm: Option<String>,
        contact: Option<String>,
        transport: Option<&str>,
        auth: Option<&str>,
        k: Option<&str>,
        op: Option<&str>,
        opc: Option<&str>,
        amf: Option<&str>,
        sqn: Option<&str>,
        ipsec: bool,
        ue_port_c: Option<u16>,
        ue_port_s: Option<u16>,
        ipsec_alg: Option<&str>,
        ipsec_ealg: Option<&str>,
        imei: Option<String>,
        ims_features: Option<Vec<String>>,
    ) -> PyResult<()> {
        let transport_type = match transport {
            Some("tcp") => Transport::Tcp,
            Some("tls") => Transport::Tls,
            _ => Transport::Udp,
        };

        // Resolve registrar address from URI — supports both IP:port and hostname
        let registrar_host = registrar
            .strip_prefix("sip:")
            .or_else(|| registrar.strip_prefix("sips:"))
            .unwrap_or(registrar);

        let host_with_port = if registrar_host.contains(':') {
            registrar_host.to_string()
        } else {
            format!("{registrar_host}:5060")
        };

        let destination: std::net::SocketAddr = host_with_port
            .parse()
            .or_else(|_| {
                // Not a raw IP:port — try DNS resolution
                use std::net::ToSocketAddrs;
                host_with_port
                    .to_socket_addrs()
                    .map_err(|e| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "cannot resolve registrar address '{registrar}': {e}"
                        ))
                    })
                    .and_then(|mut addrs| {
                        addrs.next().ok_or_else(|| {
                            pyo3::exceptions::PyValueError::new_err(format!(
                                "DNS returned no addresses for '{registrar}'"
                            ))
                        })
                    })
            })?;

        let entry = RegistrantEntry::new(
            aor.to_string(),
            registrar.to_string(),
            destination,
            transport_type,
            RegistrantCredentials {
                username: user.to_string(),
                password: password.to_string(),
                realm,
            },
            interval.unwrap_or(self.inner.default_interval),
            contact,
        );

        // IMS AKAv1-MD5: attach the USIM secrets so the 401 challenge runs
        // through Milenage instead of password digest (RFC 3310 / TS 33.203).
        let entry = if auth.is_some_and(|mode| mode.eq_ignore_ascii_case("aka")) {
            let k = k.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("auth='aka' requires the subscriber key `k`")
            })?;
            let credentials =
                crate::registrant::aka::AkaCredentials::from_hex(k, op, opc, amf.unwrap_or("8000"))
                    .map_err(|error| {
                        pyo3::exceptions::PyValueError::new_err(format!(
                            "invalid AKA credentials: {error}"
                        ))
                    })?;
            let initial_sqn = parse_sqn(sqn.unwrap_or("000000000000"))?;
            entry.with_aka(credentials, initial_sqn)
        } else {
            entry
        };

        // IPsec sec-agree (3GPP TS 33.203): the protected ports must also be
        // declared as listen.udp entries so the protected REGISTER can egress
        // from ue_port_c and MT requests arrive on ue_port_s.
        let entry = if ipsec {
            if entry.auth_mode != crate::registrant::AuthMode::Aka {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "ipsec=True requires auth='aka'",
                ));
            }
            let port_c = ue_port_c.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("ipsec=True requires ue_port_c")
            })?;
            let port_s = ue_port_s.ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("ipsec=True requires ue_port_s")
            })?;
            let alg_token = ipsec_alg.unwrap_or("hmac-sha-1-96");
            let aalg = IntegrityAlgorithm::from_sec_agree_name(alg_token).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!("unknown ipsec_alg '{alg_token}'"))
            })?;
            let ealg_token = ipsec_ealg.unwrap_or("null");
            let ealg = EncryptionAlgorithm::from_sec_agree_name(ealg_token).ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err(format!("unknown ipsec_ealg '{ealg_token}'"))
            })?;
            entry.with_ipsec(UeIpsec::new(port_c, port_s, aalg, ealg))
        } else {
            entry
        };

        // IMS Contact feature tags (instance ID + MMTel/video/SMS) so the
        // S-CSCF registers the implied services (TS 24.229 / GSMA IR.92).
        let entry = if imei.is_some() || ims_features.is_some() {
            let features = ims_features.unwrap_or_default();
            let has = |tag: &str| features.iter().any(|f| f.eq_ignore_ascii_case(tag));
            entry.with_ims_contact(crate::registrant::ImsContactParams {
                instance_id: imei,
                mmtel: has("mmtel"),
                video: has("video"),
                smsip: has("smsip"),
            })
        } else {
            entry
        };

        self.inner.add(entry);
        Ok(())
    }

    /// Remove an outbound registration by AoR.
    fn remove(&self, aor: &str) -> bool {
        self.inner.remove(aor).is_some()
    }

    /// Force an immediate re-registration for an AoR.
    fn refresh(&self, aor: &str) -> bool {
        self.inner.refresh(aor)
    }

    /// List all registrations with their current state.
    ///
    /// Returns a list of dicts with keys: aor, state, expires_in.
    fn list<'py>(&self, python: Python<'py>) -> PyResult<Vec<Bound<'py, PyDict>>> {
        let entries = self.inner.list();
        let mut result = Vec::with_capacity(entries.len());
        for (aor, state, expires_in) in entries {
            let dict = PyDict::new(python);
            dict.set_item("aor", aor)?;
            dict.set_item("state", state.to_string())?;
            dict.set_item("expires_in", expires_in)?;
            result.push(dict);
        }
        Ok(result)
    }

    /// Get the state of a specific registration.
    ///
    /// Returns state string or None if not found.
    fn status(&self, aor: &str) -> Option<String> {
        self.inner.state(aor).map(|state| state.to_string())
    }

    /// Number of configured registrations.
    fn count(&self) -> usize {
        self.inner.len()
    }

    /// The Service-Route set (RFC 3608) the S-CSCF granted this AoR on the
    /// 200 OK — the Route a B2BUA prepends to MO requests so they traverse the
    /// originating S-CSCF. Empty until the registration succeeds.
    fn service_route(&self, aor: &str) -> Vec<String> {
        self.inner.service_route(aor)
    }

    /// The P-Associated-URI list (implicit registration set) for this AoR.
    fn associated_uris(&self, aor: &str) -> Vec<String> {
        self.inner.associated_uris(aor)
    }

    /// A `Flow` over the established UE→P-CSCF IPsec SA for MO B2BUA calls.
    ///
    /// Pass the result to ``call.dial(flow=...)``: the B-leg INVITE is sent to
    /// the P-CSCF protected server port sourced from the UE protected client
    /// port, so it rides the SA. `ue_ip` is siphon's own address on the SA
    /// (the IP its protected ports are bound to). Returns ``None`` until the
    /// sec-agree handshake has completed (no Security-Server recorded yet).
    fn flow(&self, aor: &str, ue_ip: &str) -> PyResult<Option<crate::script::api::registrar::PyFlow>> {
        let ue_ip: std::net::IpAddr = ue_ip.parse().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("ue_ip '{ue_ip}' is not an IP address"))
        })?;
        Ok(self
            .inner
            .ue_flow_components(aor)
            .map(|(pcscf_addr, pcscf_port_s, ue_port_c)| {
                crate::script::api::registrar::PyFlow {
                    transport: "udp".to_string(),
                    // dial(flow=) routes to source_addr, sourced from local_addr.
                    source_addr: std::net::SocketAddr::new(pcscf_addr, pcscf_port_s),
                    local_addr: std::net::SocketAddr::new(ue_ip, ue_port_c),
                    // UDP egress is selected by source_local_addr, not conn id.
                    connection_id: 0,
                }
            }))
    }

    /// Decorator to register a handler for outbound-registration state changes.
    ///
    /// The handler receives (aor, event_type, state) where:
    ///   - aor: str — Address of Record (e.g. "sip:trunk@carrier.com")
    ///   - event_type: str — "registered", "refreshed", "failed", or "deregistered"
    ///   - state: dict — {"expires_in": int, "failure_count": int,
    ///     "registrar": str, "status_code": int (only present when
    ///     event_type is "failed")}
    ///
    /// Mirrors `registrar.on_change`. The dispatcher invokes these handlers on
    /// `RegistrantManager` state changes (`HandlerKind::RegistrantOnChange`).
    /// Registering under the same `"registration.on_change"` key as the
    /// pre-startup `_RegistrationStub` keeps both code paths consistent — the
    /// stub had this method but the real Rust namespace did not, so once the
    /// real namespace shadowed the stub (`registrant` configured) the decorator
    /// raised `AttributeError`.
    #[staticmethod]
    fn on_change(python: Python<'_>, func: Py<PyAny>) -> PyResult<Py<PyAny>> {
        let asyncio = python.import("asyncio")?;
        let is_async = asyncio
            .call_method1("iscoroutinefunction", (func.bind(python),))?
            .is_truthy()?;
        let registry = python.import("_siphon_registry")?;
        registry.call_method1(
            "register",
            (
                "registration.on_change",
                python.None(),
                func.bind(python),
                is_async,
            ),
        )?;
        Ok(func)
    }
}

/// Parse an initial SQN_MS from a 12-hex-char string into 6 bytes.
fn parse_sqn(hex: &str) -> PyResult<[u8; 6]> {
    let bytes = crate::ipsec::milenage::hex_to_bytes(hex)
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("sqn must be hex"))?;
    if bytes.len() != 6 {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "sqn must be 6 bytes (12 hex chars)",
        ));
    }
    let mut out = [0u8; 6];
    out.copy_from_slice(&bytes);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn make_manager() -> Arc<RegistrantManager> {
        Arc::new(RegistrantManager::new(
            3600,
            Duration::from_secs(60),
            Duration::from_secs(300),
            None,
        ))
    }

    #[test]
    fn py_registration_count_empty() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert_eq!(py_reg.count(), 0);
    }

    #[test]
    fn py_registration_status_none_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(py_reg.status("sip:nobody@example.com").is_none());
    }

    #[test]
    fn py_registration_remove_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.remove("sip:nobody@example.com"));
    }

    #[test]
    fn py_registration_refresh_returns_false_for_missing() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(!py_reg.refresh("sip:nobody@example.com"));
    }

    // 3GPP test IMSI range (MCC 001 / MNC 01) + TS 35.208 Test Set 1 secrets.
    const AKA_AOR: &str = "sip:001010000000001@ims.mnc01.mcc001.3gppnetwork.org";
    const AKA_K: &str = "465b5ce8b199b49faa5f0a2ee238a6bc";
    const AKA_OPC: &str = "cd63cb71954a9f4e48a5994e37a02baf";

    #[allow(clippy::too_many_arguments)]
    fn add_aka(
        py_reg: &PyRegistration,
        k: Option<&str>,
        op: Option<&str>,
        opc: Option<&str>,
    ) -> PyResult<()> {
        // Use an IP:port registrar so the test never hits DNS.
        py_reg.add(
            AKA_AOR,
            "sip:10.0.0.1:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            Some("aka"),
            k,
            op,
            opc,
            Some("b9b9"),
            None,
            false,
            None,
            None,
            None,
            None,
            None,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn add_aka_ipsec(
        py_reg: &PyRegistration,
        ue_port_c: Option<u16>,
        ue_port_s: Option<u16>,
        auth: Option<&str>,
    ) -> PyResult<()> {
        py_reg.add(
            AKA_AOR,
            "sip:10.0.0.1:5060",
            "001010000000001@ims.mnc01.mcc001.3gppnetwork.org",
            "",
            None,
            None,
            None,
            None,
            auth,
            Some(AKA_K),
            None,
            Some(AKA_OPC),
            Some("b9b9"),
            None,
            true,
            ue_port_c,
            ue_port_s,
            None,
            None,
            None,
            None,
        )
    }

    #[test]
    fn py_registration_add_aka_sets_aka_mode() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka(&py_reg, Some(AKA_K), None, Some(AKA_OPC)).unwrap();

        assert_eq!(py_reg.count(), 1);
        assert_eq!(
            manager.auth_mode(AKA_AOR),
            Some(crate::registrant::AuthMode::Aka)
        );
    }

    #[test]
    fn py_registration_add_aka_with_op_computes_opc() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka(&py_reg, Some(AKA_K), Some("cdc202d5123e20f62b6d676ac72cb318"), None).unwrap();
        assert_eq!(
            manager.auth_mode(AKA_AOR),
            Some(crate::registrant::AuthMode::Aka)
        );
    }

    #[test]
    fn py_registration_add_aka_requires_k() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        assert!(add_aka(&py_reg, None, None, Some(AKA_OPC)).is_err());
    }

    #[test]
    fn py_registration_add_aka_rejects_bad_key() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
        // K too short → AkaConfigError surfaces as ValueError.
        assert!(add_aka(&py_reg, Some("465b5ce8"), None, Some(AKA_OPC)).is_err());
    }

    #[test]
    fn py_registration_add_digest_stays_digest() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());
        py_reg
            .add(
                "sip:alice@carrier.com",
                "sip:10.0.0.1:5060",
                "alice",
                "secret",
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                None,
                false,
                None,
                None,
                None,
                None,
                None,
                None,
            )
            .unwrap();
        assert_eq!(
            manager.auth_mode("sip:alice@carrier.com"),
            Some(crate::registrant::AuthMode::Digest)
        );
    }

    #[test]
    fn py_registration_add_aka_ipsec_sets_ipsec_entry() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        add_aka_ipsec(&py_reg, Some(6100), Some(6101), Some("aka")).unwrap();

        assert!(manager.is_ipsec_entry(AKA_AOR));
        assert_eq!(manager.ue_protected_client_port(AKA_AOR), Some(6100));
    }

    #[test]
    fn py_registration_ipsec_requires_ports_and_aka() {
        let manager = make_manager();
        let py_reg = PyRegistration::new(Arc::clone(&manager), "127.0.0.1:5060".parse().unwrap());

        // Missing ue_port_s.
        assert!(add_aka_ipsec(&py_reg, Some(6100), None, Some("aka")).is_err());
        // ipsec without auth='aka'.
        assert!(add_aka_ipsec(&py_reg, Some(6100), Some(6101), None).is_err());
    }

    /// Regression: the real Rust `registration` namespace must expose
    /// `on_change`, not just the pre-startup `_RegistrationStub`. Once a
    /// `registrant` is configured the singleton shadows the stub, and a script
    /// using `@registration.on_change` (e.g. the BGCF trunk-registration app)
    /// hit `AttributeError` because the method lived only on the stub.
    ///
    /// Mirrors `subscribe_state::tests::rust_namespace_replaces_stub_when_singleton_set_first`.
    #[test]
    fn rust_namespace_has_on_change_when_singleton_set_first() {
        use pyo3::Python;

        Python::initialize();
        Python::attach(|python| {
            // Idempotent: another test may have populated the OnceLock already;
            // we only need the real namespace bound when install runs.
            let manager = make_manager();
            let namespace = PyRegistration::new(manager, "127.0.0.1:5060".parse().unwrap());
            let _ = crate::script::api::set_registration_singleton(python, namespace);

            crate::script::api::ensure_registry(python).expect("ensure registry");
            crate::script::api::install_siphon_module(python).expect("install siphon module");

            let script = r#"
import siphon
import _siphon_registry

ns = siphon.registration
# The real Rust namespace must be bound, not the pre-startup stub.
assert type(ns).__name__ != '_RegistrationStub', type(ns).__name__
assert hasattr(ns, 'on_change'), 'on_change'

# Exercise the decorator end-to-end — before the fix this raised
# AttributeError on the real namespace.
@ns.on_change
def on_trunk_change(aor, event_type, state):
    pass

# Decorator returns the function unchanged...
assert on_trunk_change.__name__ == 'on_trunk_change'
# ...and registers under the registrant kind. Membership check only —
# the registry is process-global and shared with parallel tests.
kinds = [entry[0] for entry in _siphon_registry.entries()]
assert 'registration.on_change' in kinds, kinds
"#;
            let assertions = std::ffi::CString::new(script).expect("CString");
            python
                .run(assertions.as_c_str(), None, None)
                .expect("Rust registration namespace must expose on_change");
        });
    }

    #[test]
    fn parse_sqn_validates_length() {
        assert_eq!(parse_sqn("000000000000").unwrap(), [0u8; 6]);
        assert_eq!(
            parse_sqn("ff9bb4d0b607").unwrap(),
            [0xff, 0x9b, 0xb4, 0xd0, 0xb6, 0x07]
        );
        assert!(parse_sqn("00").is_err());
        assert!(parse_sqn("zz").is_err());
    }
}
