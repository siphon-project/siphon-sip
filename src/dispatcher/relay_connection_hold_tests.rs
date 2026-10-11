//! A request relayed over TCP holds the pooled connection it left on until
//! its client transaction ends.
//!
//! The outbound pool closes a TCP connection that has been silent for its idle
//! timeout. A callee that rings for longer than that is silent for exactly
//! that long, and its answer is owed on the connection the INVITE went out on
//! (RFC 3261 §18.2.2). So the relay takes a hold on that connection for the
//! client transaction, and the pool leaves a held connection alone
//! ([`crate::transport::pool::ConnectionPool::hold`]).
//!
//! Driven through the dispatcher with a script that relays or forks to a real
//! TCP listener, and read back from the pool the dispatcher sends through.

use std::time::Duration;

use tokio::io::AsyncReadExt;

use super::proxy_cancel_awaits_provisional_tests::{caller_invite, CALLER};
use super::proxy_dialog_state_tests::{response_to, Proxy};
use super::test_dispatcher::test_dispatcher_with_script;
use super::*;

/// A proxy running `routing` as the body of its request handler, whose pool
/// connects from the loopback address the callee listens on.
fn proxy_routing(routing: &str) -> Proxy {
    let script = format!(
        concat!(
            "from siphon import proxy\n",
            "\n",
            "@proxy.on_request\n",
            "def route(request):\n",
            "    {routing}\n",
        ),
        routing = routing,
    );
    let mut dispatcher = test_dispatcher_with_script(&script);
    dispatcher.state.connection_pool = Arc::new(ConnectionPool::new(
        Arc::new(DashMap::new()),
        flume::unbounded().0,
        "127.0.0.1:5060".parse().expect("a literal address"),
        None,
        None,
        None,
        crate::transport::pool::build_outbound_tls_config(
            None,
            crate::config::TlsMethod::default(),
        )
        .expect("an outbound TLS config"),
    ));
    Proxy {
        state: Arc::new(dispatcher.state),
        udp: dispatcher.udp,
    }
}

/// The request the callee is sent on the next connection to `listener`. The
/// socket comes back too: dropping it would close the connection under test.
async fn relayed_to(listener: &tokio::net::TcpListener) -> (SipMessage, tokio::net::TcpStream) {
    let (mut socket, _) = tokio::time::timeout(Duration::from_secs(5), listener.accept())
        .await
        .expect("the proxy connects to the callee")
        .expect("accept");
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    loop {
        let size = tokio::time::timeout(Duration::from_secs(5), socket.read(&mut chunk))
            .await
            .expect("the relayed request arrives")
            .expect("read");
        assert_ne!(size, 0, "the proxy closed the connection");
        received.extend_from_slice(&chunk[..size]);
        if let Ok(message) = parse_sip_message_bytes(&received) {
            return (message, socket);
        }
    }
}

/// The connection the client transaction of `relayed` holds, as the
/// transaction recorded it.
fn connection_of(proxy: &Proxy, relayed: &SipMessage) -> ConnectionId {
    let client_key = TransactionManager::key_from_message(relayed).expect("a client key");
    proxy
        .state
        .transaction_manager
        .client_hop(&client_key)
        .expect("the transaction records where its INVITE went")
        .connection_id
}

fn answer(proxy: &Proxy, callee: SocketAddr, relayed: &SipMessage, status_code: u16, reason: &str) {
    proxy.response(
        &callee.to_string(),
        response_to(
            relayed,
            status_code,
            reason,
            "callee-tag",
            &format!("sip:callee@{callee}"),
            "",
        ),
    );
}

/// The INVITE is relayed to a TCP callee; while the callee rings the pooled
/// connection is held, and the answer releases it.
async fn a_ringing_call_holds_its_connection(
    routing: impl Fn(SocketAddr) -> String,
    call_id: &str,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener binds");
    let callee = listener.local_addr().expect("a bound address");
    let proxy = proxy_routing(&routing(callee));
    let pool = Arc::clone(&proxy.state.connection_pool);

    proxy.request(CALLER, &caller_invite(call_id));
    let (relayed, _callee_socket) = relayed_to(&listener).await;
    assert_eq!(relayed.method(), Some(&Method::Invite));
    let connection_id = connection_of(&proxy, &relayed);
    assert_ne!(connection_id, ConnectionId::default());
    assert!(
        pool.is_held(connection_id),
        "the connection a relayed INVITE left on is free to idle out before it is answered"
    );

    answer(&proxy, callee, &relayed, 180, "Ringing");
    assert!(
        pool.is_held(connection_id),
        "a provisional released the connection of a ringing call"
    );

    answer(&proxy, callee, &relayed, 200, "OK");
    assert!(
        !pool.is_held(connection_id),
        "an answered call still holds its connection"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_invite_holds_its_tcp_connection_until_it_is_answered() {
    a_ringing_call_holds_its_connection(
        |callee| format!("request.relay(\"sip:callee@{callee};transport=tcp\")"),
        "relay-hold@example.com",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_forked_invite_holds_its_tcp_connection_until_it_is_answered() {
    a_ringing_call_holds_its_connection(
        |callee| {
            format!("request.fork([\"sip:callee@{callee};transport=tcp\"], strategy=\"parallel\")")
        },
        "fork-hold@example.com",
    )
    .await;
}

/// A failure releases the connection as well, once the transaction has sent
/// its ACK on it and ended.
#[tokio::test(flavor = "multi_thread")]
async fn a_relayed_invite_that_fails_releases_its_tcp_connection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a listener binds");
    let callee = listener.local_addr().expect("a bound address");
    let proxy = proxy_routing(&format!(
        "request.relay(\"sip:callee@{callee};transport=tcp\")"
    ));
    let pool = Arc::clone(&proxy.state.connection_pool);

    proxy.request(CALLER, &caller_invite("relay-hold-failed@example.com"));
    let (relayed, _callee_socket) = relayed_to(&listener).await;
    let connection_id = connection_of(&proxy, &relayed);
    assert!(pool.is_held(connection_id));

    answer(&proxy, callee, &relayed, 486, "Busy Here");
    // Timer D is zero over a reliable transport: fire whatever the failure
    // left on the wheel for this transaction.
    let client_key = TransactionManager::key_from_message(&relayed).expect("a client key");
    if proxy.state.transaction_manager.contains(&client_key) {
        let _ = proxy.state.transaction_manager.process_client_event(
            &client_key,
            crate::transaction::ClientEvent::Ict(crate::transaction::state::IctEvent::TimerD),
        );
    }
    assert!(
        !pool.is_held(connection_id),
        "a call that failed still holds its connection"
    );
}
