//! The `repeat=` argument of `rtpengine.play_media` / `play_overlay`.

use pyo3::prelude::*;
use siphon_rtp_proto::PlayRepeat;

/// Read `repeat=`: a total play count, or `"inf"` to play until stopped.
///
/// `"inf"` is the token the tone cadence grammar already uses for "endless"
/// (`"425/1000,0/4000*inf"`), so one spelling means it everywhere. Anything
/// else is a `ValueError` rather than a play of the default length: music that
/// was meant to loop and plays once is silence afterwards, with nothing to say
/// why.
pub(super) fn parse_repeat(value: Option<&Bound<'_, PyAny>>) -> PyResult<Option<PlayRepeat>> {
    let Some(value) = value.filter(|value| !value.is_none()) else {
        return Ok(None);
    };
    if let Ok(times) = value.extract::<u64>() {
        return Ok(Some(PlayRepeat::Times(times)));
    }
    match value.extract::<String>() {
        Ok(token) if token.eq_ignore_ascii_case("inf") => Ok(Some(PlayRepeat::Forever)),
        _ => Err(pyo3::exceptions::PyValueError::new_err(
            "repeat must be a total play count (a non-negative integer) or \"inf\" to play until stopped",
        )),
    }
}

/// An endless play has no end to wait for: `wait=True` would park the handler
/// until the call is torn down.
pub(super) fn refuse_endless_wait(repeat: Option<PlayRepeat>, wait: bool) -> PyResult<()> {
    if wait && repeat == Some(PlayRepeat::Forever) {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "repeat=\"inf\" never finishes, so wait=True would never return — pass wait=False",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::types::{PyFloat, PyInt, PyString};

    #[test]
    fn a_count_or_inf_is_read_and_anything_else_is_refused() {
        Python::initialize();
        Python::attach(|python| {
            assert_eq!(parse_repeat(None).expect("absent"), None);
            let none = python.None().into_bound(python);
            assert_eq!(parse_repeat(Some(&none)).expect("None"), None);

            let three = PyInt::new(python, 3).into_any();
            assert_eq!(
                parse_repeat(Some(&three)).expect("a count"),
                Some(PlayRepeat::Times(3))
            );
            for token in ["inf", "INF"] {
                let endless = PyString::new(python, token).into_any();
                assert_eq!(
                    parse_repeat(Some(&endless)).expect("endless"),
                    Some(PlayRepeat::Forever)
                );
            }

            let negative = PyInt::new(python, -1).into_any();
            let forever = PyString::new(python, "forever").into_any();
            let fraction = PyFloat::new(python, 1.5).into_any();
            for refused in [&negative, &forever, &fraction] {
                let error = parse_repeat(Some(refused)).expect_err("refused");
                assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
            }
        });
    }

    #[test]
    fn an_endless_play_cannot_be_waited_for() {
        Python::initialize();
        Python::attach(|python| {
            assert!(refuse_endless_wait(Some(PlayRepeat::Forever), false).is_ok());
            assert!(refuse_endless_wait(Some(PlayRepeat::Times(2)), true).is_ok());
            assert!(refuse_endless_wait(None, true).is_ok());
            let error = refuse_endless_wait(Some(PlayRepeat::Forever), true).expect_err("refused");
            assert!(error.is_instance_of::<pyo3::exceptions::PyValueError>(python));
        });
    }
}
