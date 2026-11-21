//! `siphon_registrar_backend_up`: whether the registrar's persistence backend
//! has been reached ([`crate::registrar::backend::status`]).

use std::sync::OnceLock;

use prometheus::{IntGauge, Registry};

static BACKEND_UP: OnceLock<Option<IntGauge>> = OnceLock::new();

/// The gauge, created on first use so that a backend connected before
/// [`super::init`] still reports.
fn gauge() -> Option<&'static IntGauge> {
    BACKEND_UP
        .get_or_init(|| {
            IntGauge::new(
                "siphon_registrar_backend_up",
                "Whether the registrar's persistence backend (redis or postgres) has been connected (1) or is still being retried since start-up (0); absent with the memory backend",
            )
            .ok()
        })
        .as_ref()
}

/// Register the gauge. Called once from [`super::init`].
pub(super) fn init(registry: &Registry) -> Result<(), prometheus::Error> {
    if let Some(gauge) = gauge() {
        registry.register(Box::new(gauge.clone()))?;
    }
    Ok(())
}

/// Publish whether the registrar backend is connected.
pub fn set_backend_up(up: bool) {
    if let Some(gauge) = gauge() {
        gauge.set(i64::from(up));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gauge_is_registered_under_its_name() {
        let registry = Registry::new();
        init(&registry).expect("registers");
        assert!(registry
            .gather()
            .iter()
            .any(|family| family.name() == "siphon_registrar_backend_up"));
    }
}
