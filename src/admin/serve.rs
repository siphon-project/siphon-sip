//! Binding and listening for the admin API.
//!
//! Split out of `admin/mod.rs` so the route table and the handlers stay one
//! file and the transport choice stays another: the plaintext path, the TLS
//! path, and nothing else.

use std::net::SocketAddr;

use axum::Router;
use tracing::{error, info};

use super::{router, AdminState};
use crate::config::CorsConfig;

/// Start the HTTP admin API server.
///
/// `cors` optionally attaches an `Access-Control-Allow-Origin` policy so a
/// browser dashboard served from another origin can `fetch()` the admin API
/// (and the `/metrics` it also serves). `None` = no CORS headers.
///
/// `ui_enabled` serves the embedded web dashboard at `/` (and its assets),
/// same-origin with the API. It only has an effect on a binary built with the
/// `ui` cargo feature; without that feature a `true` here is a loud warning and
/// nothing is served.
///
/// Returns only when the listener could not be set up or stopped serving. The
/// error says which; the caller decides what that means for the process.
pub async fn serve(
    listen_addr: SocketAddr,
    state: AdminState,
    cors: Option<CorsConfig>,
    ui_enabled: bool,
    tls: Option<crate::config::TlsServerConfig>,
) -> Result<(), String> {
    #[cfg(not(feature = "ui"))]
    if ui_enabled {
        tracing::warn!(
            "admin.ui.enabled is set but this binary was built without the `ui` \
             feature; no dashboard will be served (rebuild with --features ui)"
        );
    }

    #[cfg(feature = "ui")]
    if ui_enabled {
        tracing::warn!(
            "admin web UI enabled — this is an EXPERIMENTAL feature and may change \
             or be removed in a future release"
        );
    }

    let app = router(state, cors.as_ref(), ui_enabled);

    if let Some(tls) = tls {
        return serve_tls(listen_addr, app, &tls).await;
    }

    let listener = match tokio::net::TcpListener::bind(listen_addr).await {
        Ok(listener) => listener,
        Err(error) => {
            error!("Failed to bind admin API on {}: {}", listen_addr, error);
            return Err(format!("cannot bind {listen_addr}: {error}"));
        }
    };
    info!("Admin API listening on {}", listen_addr);

    // `into_make_service_with_connect_info` so the auth layer can attribute a
    // failed token to a source address and feed the auto-ban, the way the
    // control listener does.
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .map_err(|error| {
        error!("Admin API server error: {}", error);
        format!("server error: {error}")
    })
}

/// The TLS half of [`serve`].
///
/// The acceptor hot-reloads, so a certificate replaced under a running process
/// is served by the next handshake — the same behaviour the SIP listeners have,
/// and the reason an `admin.tls` node needs no restart for a renewal. Built
/// here as well as at config load: the files can change underneath a running
/// process, and a key that has become unreadable must stop the listener rather
/// than serve the admin API in the clear.
async fn serve_tls(
    listen_addr: SocketAddr,
    app: Router,
    tls: &crate::config::TlsServerConfig,
) -> Result<(), String> {
    let acceptor = match crate::transport::tls::build_hot_reload_acceptor(tls) {
        Ok(acceptor) => acceptor,
        Err(error) => {
            error!(%listen_addr, %error, "admin.tls is configured but unusable — not listening");
            return Err(format!("admin.tls unusable: {error}"));
        }
    };
    let listener =
        match crate::transport::tls_listener::TlsListener::bind(listen_addr, acceptor, "admin API")
            .await
        {
            Ok(listener) => listener,
            Err(error) => {
                error!("Failed to bind admin API on {}: {}", listen_addr, error);
                return Err(format!("cannot bind {listen_addr}: {error}"));
            }
        };
    info!(
        %listen_addr,
        mutual = tls.verify_client,
        "Admin API listening (TLS)"
    );
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<crate::transport::tls_listener::TlsPeer>(),
    )
    .await
    .map_err(|error| {
        error!("Admin API server error: {}", error);
        format!("server error: {error}")
    })
}
