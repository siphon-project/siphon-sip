//! `call.refer_replaces_call`: the facts `b2bua.adopt_replaced` compares, as
//! the script reads them.

use pyo3::prelude::*;

use crate::b2bua::actor::DialogParty;

/// `party` as a dict, or `None`.
pub(super) fn party_dict(
    python: Python<'_>,
    party: Option<&DialogParty>,
) -> PyResult<Option<Py<PyAny>>> {
    let Some(party) = party else {
        return Ok(None);
    };
    let dict = pyo3::types::PyDict::new(python);
    dict.set_item("call_id", &party.sip_call_id)?;
    dict.set_item("leg", if party.on_a_leg { "caller" } else { "callee" })?;
    dict.set_item("source", party.source.to_string())?;
    dict.set_item("transport", party.transport.label().to_ascii_lowercase())?;
    dict.set_item("from_uri", party.uri.as_deref())?;
    dict.set_item("auth_user", party.auth_user.as_deref())?;
    Ok(Some(dict.into_any().unbind()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{ConnectionId, Transport};

    #[test]
    fn the_facts_reach_the_script_as_a_dict() {
        let party = DialogParty {
            internal_call_id: "internal".into(),
            sip_call_id: "held@192.0.2.10".into(),
            on_a_leg: false,
            source: "192.0.2.10:5060".parse().expect("a literal address"),
            transport: Transport::Udp,
            connection_id: ConnectionId::default(),
            uri: Some("<sip:1001@example.com>".into()),
            auth_user: None,
        };
        Python::initialize();
        Python::attach(|python| {
            let dict = party_dict(python, Some(&party))
                .expect("built")
                .expect("a dict");
            let dict = dict.bind(python);
            let get = |key: &str| dict.get_item(key).expect("the key").to_string();
            assert_eq!(get("call_id"), "held@192.0.2.10");
            assert_eq!(get("leg"), "callee");
            assert_eq!(get("source"), "192.0.2.10:5060");
            assert_eq!(get("transport"), "udp");
            assert_eq!(get("from_uri"), "<sip:1001@example.com>");
            assert_eq!(get("auth_user"), "None");
            assert!(party_dict(python, None).expect("built").is_none());
        });
    }
}
