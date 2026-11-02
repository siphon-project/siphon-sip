//! The conference roster as a script reads it: `b2bua.conference_roster`,
//! `call.conference` and the `roster` argument of `@b2bua.on_conference_change`.
//! The state is [`crate::rtpengine::conference_roster`]'s; this only shapes it.

use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::rtpengine::conference_roster::RosterSeat;

/// One seat as a dict: `call_id`, `from_tag`, `party_uri`, `role`,
/// `joined_at` (unix seconds), `kind` (`"joined"` or `"adopted"`) and
/// `owner_call_id` (`None` for a joined seat).
pub(crate) fn seat_dict<'py>(
    python: Python<'py>,
    seat: &RosterSeat,
) -> PyResult<Bound<'py, PyDict>> {
    let dict = PyDict::new(python);
    dict.set_item("call_id", &seat.call_id)?;
    dict.set_item("from_tag", &seat.from_tag)?;
    dict.set_item("party_uri", seat.party_uri.as_deref())?;
    dict.set_item("role", &seat.role)?;
    dict.set_item("joined_at", seat.joined_at)?;
    dict.set_item("kind", seat.kind.label())?;
    dict.set_item("owner_call_id", seat.owner_call_id.as_deref())?;
    Ok(dict)
}

/// A room as a list of seat dicts.
pub(crate) fn roster_list(python: Python<'_>, seats: &[RosterSeat]) -> PyResult<Py<PyAny>> {
    let list = PyList::empty(python);
    for seat in seats {
        list.append(seat_dict(python, seat)?)?;
    }
    Ok(list.into_any().unbind())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtpengine::conference_roster::SeatKind;

    fn seat(kind: SeatKind, owner: Option<&str>) -> RosterSeat {
        RosterSeat {
            conference_id: "room".into(),
            call_id: "far@192.0.2.2".into(),
            from_tag: "far-tag".into(),
            party_uri: Some("sip:15550100042@example.com".into()),
            role: "talker".into(),
            joined_at: 1_700_000_000.5,
            kind,
            owner_call_id: owner.map(str::to_string),
            engine_call_id: Some("engine".into()),
            internal_call_id: Some("internal".into()),
            end_owner_on_last: false,
        }
    }

    #[test]
    fn a_seat_reads_as_the_documented_dict_and_nothing_internal_leaks() {
        Python::initialize();
        Python::attach(|python| {
            let list = roster_list(
                python,
                &[
                    seat(SeatKind::Adopted, Some("owner@192.0.2.1")),
                    seat(SeatKind::Joined, None),
                ],
            )
            .expect("built");
            let list = list.bind(python).cast::<PyList>().expect("a list").clone();
            assert_eq!(list.len(), 2);
            let adopted = list.get_item(0).expect("first");
            let adopted = adopted.cast::<PyDict>().expect("a dict");
            let mut keys: Vec<String> = adopted
                .keys()
                .iter()
                .map(|key| key.extract().expect("a string key"))
                .collect();
            keys.sort();
            assert_eq!(
                keys,
                [
                    "call_id",
                    "from_tag",
                    "joined_at",
                    "kind",
                    "owner_call_id",
                    "party_uri",
                    "role"
                ]
            );
            fn get<'py>(dict: &Bound<'py, PyDict>, key: &str) -> Bound<'py, PyAny> {
                dict.get_item(key).expect("key").expect("present")
            }
            assert_eq!(get(adopted, "kind").to_string(), "adopted");
            assert_eq!(get(adopted, "owner_call_id").to_string(), "owner@192.0.2.1");
            assert_eq!(
                get(adopted, "joined_at").extract::<f64>().expect("float"),
                1_700_000_000.5
            );
            let joined = list.get_item(1).expect("second");
            let joined = joined.cast::<PyDict>().expect("a dict");
            assert_eq!(get(joined, "kind").to_string(), "joined");
            assert!(get(joined, "owner_call_id").is_none());
        });
    }
}
