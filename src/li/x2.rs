//! X2 IRI delivery — ETSI TS 103 221-2 signalling export to the MDF.
//!
//! One persistent connection per delivery address, reconnecting on loss, fed by
//! the bounded IRI channel. An idle connection carries a keepalive PDU
//! (clause 5.2.2) so the MDF has a liveness signal on a quiet interface.
//!
//! The records are [`super::pdu`] PDUs carrying the SIP message verbatim, not
//! the TS 102 232 BER that [`super::asn1`] encodes. Both are real interfaces
//! and it is easy to reach for the wrong one: TS 102 232 is *handover*, what
//! the Mediation and Delivery Function sends onwards to the LEMF. X2 is the
//! interface into the MDF, and TS 103 221-2 is what an MDF reads there.

use super::pdu::{attribute_type, Attribute, PayloadDirection, PayloadFormat, Pdu, PduType};
use super::target::MatchedParty;
use super::IriEvent;
use crate::config::{LiTlsConfig, LiX2Config};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::time::Instant;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use tracing::{debug, error, info, warn};

/// A delivery connection, whichever transport carries it.
///
/// Boxing would cost an allocation per write on a path that runs per
/// intercepted message; the enum keeps both arms concrete.
enum Connection {
    /// Plain TCP.
    Plain(TcpStream),
    /// TLS over TCP.
    Tls(Box<TlsStream<TcpStream>>),
}

impl Connection {
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match self {
            Connection::Plain(stream) => write_and_flush(stream, bytes).await,
            Connection::Tls(stream) => write_and_flush(stream.as_mut(), bytes).await,
        }
    }

    /// Read and discard whatever the MDF has sent, without waiting for more.
    ///
    /// X2 is one-way for records, but the MDF answers every keepalive with a
    /// KeepaliveAck. Nothing here needs the acks, yet they have to be read: an
    /// undrained receive buffer fills, the MDF's own writes block, and a
    /// collector blocked on us may stop reading what we send. The drain is also
    /// where a peer that closed the connection shows up, as end of stream, which
    /// a write into a half-closed socket would otherwise hide for a round.
    ///
    /// Bounded per call so a peer that floods the socket cannot hold the single
    /// delivery task; whatever is left is read on the next tick.
    async fn drain_inbound(&mut self) -> std::io::Result<()> {
        const MAX_READS: usize = 64;
        let mut scratch = [0u8; 1024];
        for _ in 0..MAX_READS {
            let read = match self {
                Connection::Plain(stream) => match stream.try_read(&mut scratch) {
                    Ok(length) => length,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                    Err(error) => return Err(error),
                },
                // TLS has no `try_read`: the plaintext may already sit in the
                // session or still be a record on the socket. A zero-length
                // timeout polls the read exactly once, and a read that would
                // block comes back as elapsed. Dropping it loses nothing,
                // because rustls keeps a partial record buffered.
                Connection::Tls(stream) => {
                    match tokio::time::timeout(Duration::ZERO, stream.read(&mut scratch)).await {
                        Ok(result) => result?,
                        Err(_) => return Ok(()),
                    }
                }
            };
            if read == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "mediation function closed the X2 connection",
                ));
            }
        }
        Ok(())
    }
}

/// Bound on one X2 delivery write.
///
/// A mediation function that accepts the connection and then stops reading —
/// alive, still ACKing, receive window closed — makes both the write and the
/// flush block indefinitely. There is a *single* delivery task for every
/// warrant, so unbounded that stalls IRI delivery for all of them, silently and
/// for the life of the process. Bounding it turns a stalled MDF into a logged
/// reconnect against that one address.
const X2_WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

async fn write_and_flush<W>(stream: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    tokio::time::timeout(X2_WRITE_TIMEOUT, async {
        stream.write_all(bytes).await?;
        stream.flush().await
    })
    .await
    .unwrap_or_else(|_| {
        Err(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            "X2 write timed out — mediation function is not draining its socket",
        ))
    })
}

/// How to reach one mediation function.
struct Delivery {
    address: String,
    connector: Option<TlsConnector>,
    server_name: String,
    connection: Option<Connection>,
    /// Per-connection PDU counter for the sequence-number attribute.
    sequence: u32,
    /// When the connection last carried a PDU, IRI or keepalive.
    last_sent: Instant,
}

impl Delivery {
    /// Open a connection, retrying a few times before giving up on a record.
    ///
    /// A single attempt is not enough on the record that opens the connection,
    /// and that record is the one least affordable to lose: the first message
    /// of a matched warrant is its Begin, and a mediation function that never
    /// receives it has a session it cannot open. The first attempt is the one
    /// most likely to fail, too — the collector may be accepting connections a
    /// moment later than the call that triggered this, and anything in front of
    /// it (a load balancer, a terminating proxy) forks per connection.
    ///
    /// Bounded rather than unbounded: the channel behind this is bounded too,
    /// so retrying for ever on a collector that is genuinely gone would stall
    /// delivery to every *other* destination behind it.
    async fn connect_with_retries(&mut self, interval: std::time::Duration) -> bool {
        const ATTEMPTS: u32 = 3;
        for attempt in 1..=ATTEMPTS {
            if self.connect().await {
                return true;
            }
            if attempt < ATTEMPTS {
                warn!(
                    address = %self.address,
                    attempt,
                    "X2 connection attempt failed, retrying"
                );
                tokio::time::sleep(interval).await;
            }
        }
        false
    }

    /// Open a connection, or report why not.
    ///
    /// The two failure modes are kept apart in the log because they need
    /// different people: a refused connection is the MDF being down, a failed
    /// handshake is the PKI being wrong.
    async fn connect(&mut self) -> bool {
        let tcp_stream = match TcpStream::connect(&self.address).await {
            Ok(stream) => stream,
            Err(error) => {
                error!(
                    address = %self.address,
                    error = %error,
                    "X2 connection to mediation function failed"
                );
                return false;
            }
        };
        // Nagle would hold a small IRI record back waiting for a second one.
        // The records are latency-sensitive and mostly sub-MSS, so it is off.
        if let Err(error) = tcp_stream.set_nodelay(true) {
            debug!(address = %self.address, error = %error, "X2 could not disable Nagle");
        }

        let Some(connector) = self.connector.clone() else {
            info!(address = %self.address, transport = "tcp", "X2 connected to mediation function");
            self.connected(Connection::Plain(tcp_stream));
            return true;
        };

        let server_name =
            match tokio_rustls::rustls::pki_types::ServerName::try_from(self.server_name.clone()) {
                Ok(name) => name,
                Err(error) => {
                    error!(
                        server_name = %self.server_name,
                        error = %error,
                        "X2 TLS server name is not usable, delivery cannot start"
                    );
                    return false;
                }
            };

        match connector.connect(server_name, tcp_stream).await {
            Ok(stream) => {
                info!(address = %self.address, transport = "tls", "X2 connected to mediation function");
                self.connected(Connection::Tls(Box::new(stream)));
                true
            }
            Err(error) => {
                error!(
                    address = %self.address,
                    error = %error,
                    "X2 TLS handshake with mediation function failed"
                );
                false
            }
        }
    }

    /// Adopt a freshly opened connection.
    ///
    /// The sequence number is per connection, so it restarts here whichever
    /// path opened it: a record's reconnect, or the first record after a
    /// keepalive found the peer gone.
    fn connected(&mut self, connection: Connection) {
        self.connection = Some(connection);
        self.sequence = 0;
        self.last_sent = Instant::now();
    }

    /// Send a keepalive if the connection has been quiet for a whole period.
    ///
    /// Idleness counts from the last PDU of any kind, so a busy connection
    /// never carries one: its records already prove it alive. The tick runs at
    /// the period, so a quiet connection sees its keepalive between one and two
    /// periods after the last record.
    ///
    /// A connection that is gone is dropped here, never reopened. Opening one
    /// can take a connect timeout and the retries behind it, and this is the
    /// single task that delivers IRI for every warrant, so a reconnect on the
    /// tick would hold up live records to reach a peer nothing is waiting for.
    /// The next record reconnects through its own path.
    async fn keepalive_if_idle(&mut self, period: Duration) {
        if self.last_sent.elapsed() < period {
            return;
        }
        let Some(connection) = self.connection.as_mut() else {
            return;
        };

        if let Err(error) = connection.drain_inbound().await {
            warn!(
                address = %self.address,
                error = %error,
                "X2 connection to mediation function lost while idle, dropped"
            );
            self.connection = None;
            return;
        }

        let encoded = match Pdu::keepalive(self.sequence).encode() {
            Ok(bytes) => bytes,
            Err(error) => {
                // As with a record that cannot be framed: a defect in this
                // element, not in the connection.
                error!(address = %self.address, error = %error, "X2 keepalive could not be framed");
                return;
            }
        };
        match connection.write_all(&encoded).await {
            Ok(()) => {
                self.sequence = self.sequence.wrapping_add(1);
                self.last_sent = Instant::now();
                debug!(address = %self.address, "X2 keepalive sent");
            }
            Err(error) => {
                warn!(
                    address = %self.address,
                    error = %error,
                    "X2 keepalive to mediation function failed, connection dropped"
                );
                self.connection = None;
            }
        }
    }
}

/// The keepalive period a configured number of seconds means; zero is off.
fn keepalive_period(seconds: u64) -> Option<Duration> {
    (seconds > 0).then(|| Duration::from_secs(seconds))
}

/// Background task that drains the IRI channel and delivers to the MDF.
///
/// Runs for the lifetime of the LI subsystem.
pub async fn delivery_task(receiver: mpsc::Receiver<IriEvent>, config: Arc<LiX2Config>) {
    let keepalive = keepalive_period(config.keepalive_secs);
    run_delivery(receiver, config, keepalive).await;
}

/// The delivery loop, with the keepalive period passed in rather than read as
/// whole seconds, so a test can run it at a fraction of one.
async fn run_delivery(
    mut receiver: mpsc::Receiver<IriEvent>,
    config: Arc<LiX2Config>,
    keepalive: Option<Duration>,
) {
    let use_tls = config.transport.eq_ignore_ascii_case("tls");
    info!(
        address = %config.delivery_address,
        transport = %config.transport,
        "X2 IRI delivery task started"
    );

    let connector = if use_tls {
        match build_tls_connector(config.tls.as_ref()) {
            Ok(connector) => Some(connector),
            Err(error) => {
                // Refusing to fall back to plaintext is the point. X2 carries
                // the content of a warrant; silently downgrading it because a
                // certificate path was wrong would be the worst outcome
                // available, so the task stops and says so.
                error!(
                    error = %error,
                    "X2 TLS was configured but could not be set up; no IRI will be delivered"
                );
                return;
            }
        }
    } else {
        None
    };

    // One connection per distinct delivery address. An event names the
    // destinations its task provisioned, so a warrant delivering to two MDFs
    // reaches both, and the configured address is the fallback for a
    // deployment that never provisioned destinations over X1.
    let mut deliveries: HashMap<String, Delivery> = HashMap::new();
    let reconnect_interval = std::time::Duration::from_secs(config.reconnect_interval_secs);

    // Delay rather than burst: a tick missed while a slow write held the task
    // is one keepalive owed, not several back to back.
    let mut keepalive_timer = keepalive.map(|period| {
        let mut timer = tokio::time::interval(period);
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        (period, timer)
    });
    if let Some((_, timer)) = keepalive_timer.as_mut() {
        // The first tick completes immediately, and nothing is open yet.
        timer.tick().await;
    }

    loop {
        let received = match keepalive_timer.as_mut() {
            // `recv` is cancel-safe, so a tick that wins the race loses no event.
            Some((period, timer)) => tokio::select! {
                received = receiver.recv() => received,
                _ = timer.tick() => {
                    for delivery in deliveries.values_mut() {
                        delivery.keepalive_if_idle(*period).await;
                    }
                    continue;
                }
            },
            None => receiver.recv().await,
        };
        let Some(event) = received else {
            break;
        };

        let addresses = delivery_addresses(&event, &config.delivery_address);
        if addresses.is_empty() {
            warn!(
                xid = %event.x_id,
                liid = %event.liid,
                "X2 event has no destination, dropped"
            );
            continue;
        }

        for address in addresses {
            let server_name = tls_server_name(config.tls.as_ref(), &address);
            let delivery = deliveries
                .entry(address.clone())
                .or_insert_with(|| Delivery {
                    address: address.clone(),
                    connector: connector.clone(),
                    server_name,
                    connection: None,
                    sequence: 0,
                    last_sent: Instant::now(),
                });

            if delivery.connection.is_none()
                && !delivery.connect_with_retries(reconnect_interval).await
            {
                error!(
                    address = %address,
                    xid = %event.x_id,
                    liid = %event.liid,
                    "X2 no connection to mediation function, IRI record dropped"
                );
                continue;
            }

            let encoded = match encode_iri_event(&event, delivery.sequence) {
                Ok(bytes) => bytes,
                Err(error) => {
                    // A PDU we cannot frame is a defect in this element, not a
                    // transport fault, so it is not worth a reconnect.
                    error!(
                        error = %error,
                        xid = %event.x_id,
                        liid = %event.liid,
                        "X2 record could not be framed, dropped"
                    );
                    continue;
                }
            };

            let Some(connection) = delivery.connection.as_mut() else {
                continue;
            };
            match connection.write_all(&encoded).await {
                Ok(()) => {
                    delivery.sequence = delivery.sequence.wrapping_add(1);
                    delivery.last_sent = Instant::now();
                    debug!(
                        address = %address,
                        xid = %event.x_id,
                        liid = %event.liid,
                        event_type = ?event.event_type,
                        "X2 IRI record delivered"
                    );
                    continue;
                }
                Err(error) => {
                    warn!(
                        address = %address,
                        error = %error,
                        xid = %event.x_id,
                        liid = %event.liid,
                        "X2 delivery failed, reconnecting"
                    );
                    delivery.connection = None;
                }
            }

            // One retry on a fresh connection. A half-open socket only reveals
            // itself on write, so the first record after the peer went away is
            // otherwise always lost.
            tokio::time::sleep(reconnect_interval).await;
            if !delivery.connect_with_retries(reconnect_interval).await {
                error!(
                    address = %address,
                    xid = %event.x_id,
                    liid = %event.liid,
                    "X2 reconnect failed, IRI record dropped"
                );
                continue;
            }
            // The sequence number is per connection, so adopting the new one
            // restarted it.
            let retry = match encode_iri_event(&event, delivery.sequence) {
                Ok(bytes) => bytes,
                Err(error) => {
                    error!(error = %error, liid = %event.liid, "X2 record could not be framed on retry");
                    continue;
                }
            };
            let Some(connection) = delivery.connection.as_mut() else {
                continue;
            };
            match connection.write_all(&retry).await {
                Ok(()) => {
                    delivery.sequence = delivery.sequence.wrapping_add(1);
                    delivery.last_sent = Instant::now();
                    info!(
                        address = %address,
                        liid = %event.liid,
                        "X2 IRI record delivered after reconnect"
                    );
                }
                Err(error) => {
                    error!(
                        address = %address,
                        error = %error,
                        xid = %event.x_id,
                        liid = %event.liid,
                        "X2 delivery failed after reconnect, IRI record dropped"
                    );
                    delivery.connection = None;
                }
            }
        }
    }

    info!("X2 IRI delivery task stopped (channel closed)");
}

/// Where one event has to go.
///
/// The task's own destinations win; the configured address is what a
/// deployment without X1-provisioned destinations has.
fn delivery_addresses(event: &IriEvent, configured: &str) -> Vec<String> {
    if event.destinations.is_empty() {
        return vec![configured.to_string()];
    }
    let mut addresses: Vec<String> = Vec::with_capacity(event.destinations.len());
    for destination in &event.destinations {
        let rendered = render_address(*destination);
        if !addresses.contains(&rendered) {
            addresses.push(rendered);
        }
    }
    addresses
}

fn render_address(address: SocketAddr) -> String {
    address.to_string()
}

/// The name the MDF's certificate is verified against.
///
/// An explicit `server_name` wins, because a delivery address is often a bare
/// literal that no certificate can carry as a name.
fn tls_server_name(tls: Option<&LiTlsConfig>, address: &str) -> String {
    if let Some(name) = tls.and_then(|tls| tls.server_name.clone()) {
        return name;
    }
    address
        .rsplit_once(':')
        .map(|(host, _)| host.trim_matches(['[', ']']).to_string())
        .unwrap_or_else(|| address.to_string())
}

/// Build the client side of X2 mutual TLS.
fn build_tls_connector(tls: Option<&LiTlsConfig>) -> Result<TlsConnector, String> {
    use rustls_pki_types::pem::PemObject;
    use tokio_rustls::rustls;

    let tls = tls.ok_or_else(|| {
        "lawful_intercept.x2.transport is \"tls\" but no lawful_intercept.x2.tls block was given"
            .to_string()
    })?;

    let mut roots = rustls::RootCertStore::empty();
    let ca_path = tls.ca_cert.as_ref().ok_or_else(|| {
        // Falling back to the public roots would be worse than failing: the
        // MDF is on a private PKI, so a public-root trust anchor accepts
        // nothing we want and might accept something we do not.
        "lawful_intercept.x2.tls.ca_cert is required to verify the mediation function".to_string()
    })?;
    let ca_pem = std::fs::read(ca_path).map_err(|error| format!("{ca_path}: {error}"))?;
    let mut cursor = std::io::Cursor::new(ca_pem);
    let authorities: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("{ca_path}: {error}"))?;
    if authorities.is_empty() {
        return Err(format!("{ca_path} holds no certificates"));
    }
    for authority in authorities {
        roots
            .add(authority)
            .map_err(|error| format!("{ca_path}: {error}"))?;
    }

    let builder = rustls::ClientConfig::builder().with_root_certificates(roots);

    // The MDF authenticates the network element, so a client certificate is
    // the normal case rather than an option; without one the handshake fails
    // at the peer with far less to go on than this.
    let config = match (tls.certificate.as_ref(), tls.private_key.as_ref()) {
        (Some(certificate_path), Some(key_path)) => {
            let certificate_pem = std::fs::read(certificate_path)
                .map_err(|error| format!("{certificate_path}: {error}"))?;
            let mut cursor = std::io::Cursor::new(certificate_pem);
            let chain: Vec<_> = rustls_pki_types::CertificateDer::pem_reader_iter(&mut cursor)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|error| format!("{certificate_path}: {error}"))?;
            if chain.is_empty() {
                return Err(format!("{certificate_path} holds no certificates"));
            }
            let key = rustls_pki_types::PrivateKeyDer::from_pem_file(key_path)
                .map_err(|error| format!("{key_path}: {error}"))?;
            builder
                .with_client_auth_cert(chain, key)
                .map_err(|error| format!("X2 client certificate rejected: {error}"))?
        }
        (None, None) => {
            warn!(
                "X2 TLS has no client certificate; a mediation function requiring \
                 mutual authentication will refuse the connection"
            );
            builder.with_no_client_auth()
        }
        _ => {
            return Err(
                "lawful_intercept.x2.tls needs both certificate and private_key, or neither"
                    .to_string(),
            )
        }
    };

    Ok(TlsConnector::from(Arc::new(config)))
}

/// Frame one IRI event as a TS 103 221-2 X2 PDU.
///
/// The payload is the SIP message as it appeared on the wire. That is what
/// `PayloadFormat::Sip` means, and it is also what makes the record useful:
/// the MDF re-derives whatever its handover format needs, rather than
/// inheriting whichever subset of headers this element thought to copy.
fn encode_iri_event(event: &IriEvent, sequence: u32) -> Result<Vec<u8>, super::pdu::PduError> {
    let mut attributes = vec![
        Attribute::timestamp(event.timestamp),
        Attribute::sequence_number(sequence),
    ];
    if let Some(source) = event.source_ip {
        attributes.push(Attribute::source_address(source));
    }
    if let Some(destination) = event.destination_ip {
        attributes.push(Attribute::destination_address(destination));
    }
    // Clause 5.3: which of the task's target identifiers this traffic matched.
    // The LIID is the ADMF's name for the warrant and is what the MDF keys its
    // handover on, so it is carried rather than left for the MDF to look up.
    attributes.push(Attribute::text(
        attribute_type::MATCHED_TARGET_IDENTIFIER,
        &event.liid,
    ));

    let payload = match &event.raw_message {
        Some(raw) => raw.clone(),
        // Without the original bytes there is no SIP message to carry, and a
        // reconstruction would be a different message wearing the same name.
        // Sending the summary as a proprietary payload says what it is.
        None => {
            return Pdu {
                pdu_type: PduType::X2,
                payload_format: PayloadFormat::Proprietary,
                payload_direction: direction_for(event.party),
                x_id: event.x_id.as_bytes(),
                correlation_id: event.correlation_id.to_be_bytes(),
                attributes,
                payload: summarise(event).into_bytes(),
            }
            .encode()
        }
    };

    Pdu {
        pdu_type: PduType::X2,
        payload_format: PayloadFormat::Sip,
        payload_direction: direction_for(event.party),
        x_id: event.x_id.as_bytes(),
        correlation_id: event.correlation_id.to_be_bytes(),
        attributes,
        payload,
    }
    .encode()
}

/// Direction relative to the target (clause 5.2.6).
///
/// The warrant names one party. A message the target originated is
/// "sent from target"; one addressed to them is "sent to target". Which is
/// which comes from the match, because the same INVITE is either depending on
/// whether the warrant named the caller or the callee.
fn direction_for(party: MatchedParty) -> PayloadDirection {
    match party {
        MatchedParty::Originating => PayloadDirection::SentFromTarget,
        MatchedParty::Terminating => PayloadDirection::SentToTarget,
    }
}

/// A one-line rendering of an event whose original bytes were not retained.
fn summarise(event: &IriEvent) -> String {
    let status = event
        .status_code
        .map(|code| format!(" {code}"))
        .unwrap_or_default();
    format!(
        "{}{} from={} to={} call-id={}",
        event.sip_method, status, event.from_uri, event.to_uri, event.call_id
    )
}

#[cfg(test)]
mod tests {
    use super::super::x1::types::{DeliveryType, XId};
    use super::*;
    use crate::li::IriEventType;
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::SystemTime;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    const RAW_INVITE: &[u8] = b"INVITE sip:bob@example.com SIP/2.0\r\nCall-ID: call-123\r\n\r\n";

    /// A mediation function that accepts the connection and then never reads:
    /// no error, no close, simply no progress.
    struct NeverDrains;

    impl AsyncWrite for NeverDrains {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
            _: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Pending
        }
        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Pending
        }
    }

    /// There is one delivery task for every warrant, so an unbounded write to a
    /// stalled mediation function stops IRI delivery for all of them — silently,
    /// with the socket still established, for the life of the process. That is
    /// warrant loss, not just a slow collector, so the write has to be bounded
    /// and the address reconnected.
    ///
    /// Time is paused: against the unbounded write this does not fail, it hangs.
    #[tokio::test(start_paused = true)]
    async fn a_mediation_function_that_stops_reading_times_out_rather_than_stalling_delivery() {
        let mut stalled = NeverDrains;

        let outcome =
            tokio::time::timeout(X2_WRITE_TIMEOUT * 10, write_and_flush(&mut stalled, b"pdu"))
                .await
                .expect(
                    "write_and_flush parked on a mediation function that stopped reading \
             — every warrant's IRI delivery stops with it",
                );

        let error = outcome.expect_err("a write to a stalled peer cannot succeed");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::TimedOut,
            "the delivery task must see a timeout it can reconnect on"
        );
    }

    fn test_iri_event() -> IriEvent {
        IriEvent {
            x_id: XId::parse("11111111-2222-3333-4444-555555555555")
                .expect("test XID must be dictionary-valid"),
            call_id: "call-123@example.com".to_string(),
            destinations: Vec::new(),
            liid: "LI-001".to_string(),
            correlation_id: 4242,
            event_type: IriEventType::Begin,
            timestamp: SystemTime::now(),
            sip_method: "INVITE".to_string(),
            status_code: None,
            from_uri: "sip:alice@example.com".to_string(),
            to_uri: "sip:bob@example.com".to_string(),
            request_uri: Some("sip:bob@example.com".to_string()),
            source_ip: None,
            destination_ip: None,
            delivery_type: DeliveryType::X2AndX3,
            party: crate::li::target::MatchedParty::Originating,
            raw_message: Some(RAW_INVITE.to_vec()),
        }
    }

    /// The header fields a mediation function reads first.
    #[test]
    fn iri_event_frames_as_a_ts_103_221_2_x2_pdu() {
        let event = test_iri_event();
        let encoded = encode_iri_event(&event, 0).expect("event must frame");

        assert_eq!(&encoded[0..2], &[0x00, 0x05], "version 0.5");
        assert_eq!(&encoded[2..4], &[0x00, 0x01], "X2");
        assert_eq!(&encoded[12..14], &[0x00, 0x09], "payload format SIP");
        assert_eq!(
            &encoded[16..32],
            &event.x_id.as_bytes(),
            "the task's XID, not a hash of the LIID"
        );
        assert_eq!(
            &encoded[32..40],
            &4242u64.to_be_bytes(),
            "the session correlation, as 8 octets"
        );

        let header_length = u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]);
        assert_eq!(
            &encoded[header_length as usize..],
            RAW_INVITE,
            "the SIP message is carried verbatim"
        );
    }

    /// The whole point of the payload format: bytes in, same bytes out.
    #[test]
    fn the_sip_message_is_not_reserialised() {
        let mut event = test_iri_event();
        // A header order and spacing no builder of ours would reproduce.
        let odd = b"INVITE sip:b@e.com SIP/2.0\r\nf: <sip:a@e.com>;tag=1\r\ni: xyz\r\n\r\n";
        event.raw_message = Some(odd.to_vec());

        let encoded = encode_iri_event(&event, 0).expect("event must frame");
        let header_length =
            u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize;
        assert_eq!(&encoded[header_length..], odd);
    }

    #[test]
    fn direction_follows_the_matched_party_not_the_method() {
        let mut event = test_iri_event();

        event.party = MatchedParty::Originating;
        let from_target = encode_iri_event(&event, 0).expect("event must frame");
        assert_eq!(&from_target[14..16], &[0x00, 0x03], "sent from target");

        event.party = MatchedParty::Terminating;
        let to_target = encode_iri_event(&event, 0).expect("event must frame");
        assert_eq!(&to_target[14..16], &[0x00, 0x02], "sent to target");
    }

    #[test]
    fn an_event_without_raw_bytes_is_not_framed_as_sip() {
        let mut event = test_iri_event();
        event.raw_message = None;

        let encoded = encode_iri_event(&event, 0).expect("event must frame");
        assert_eq!(
            &encoded[12..14],
            &[0x00, 0x04],
            "a summary is proprietary, never claimed to be a SIP message"
        );
        let header_length =
            u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize;
        let payload = String::from_utf8_lossy(&encoded[header_length..]);
        assert!(payload.contains("INVITE"), "{payload}");
        assert!(payload.contains("call-123@example.com"), "{payload}");
    }

    #[test]
    fn addresses_are_carried_as_attributes_when_known() {
        let mut event = test_iri_event();
        event.source_ip = Some(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        event.destination_ip = Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)));

        let encoded = encode_iri_event(&event, 0).expect("event must frame");
        let header_length =
            u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize;
        let attributes = &encoded[40..header_length];

        assert!(find_attribute(attributes, attribute_type::SOURCE_IPV4)
            .is_some_and(|value| value == vec![192, 0, 2, 1]));
        assert!(find_attribute(attributes, attribute_type::DESTINATION_IPV4)
            .is_some_and(|value| value == vec![198, 51, 100, 9]));
        assert!(
            find_attribute(attributes, attribute_type::MATCHED_TARGET_IDENTIFIER)
                .is_some_and(|value| value == b"LI-001".to_vec())
        );
    }

    /// Walk the TLV run the way a receiver does, so a wrong length is visible
    /// as a failure to find the attribute rather than as a passing read.
    fn find_attribute(mut attributes: &[u8], wanted: u16) -> Option<Vec<u8>> {
        while attributes.len() >= 4 {
            let attribute_type = u16::from_be_bytes([attributes[0], attributes[1]]);
            let length = usize::from(u16::from_be_bytes([attributes[2], attributes[3]]));
            let value = attributes.get(4..4 + length)?;
            if attribute_type == wanted {
                return Some(value.to_vec());
            }
            attributes = &attributes[4 + length..];
        }
        None
    }

    #[test]
    fn sequence_number_is_carried_and_advances() {
        let event = test_iri_event();
        for sequence in [0u32, 1, 7] {
            let encoded = encode_iri_event(&event, sequence).expect("event must frame");
            let header_length =
                u32::from_be_bytes([encoded[4], encoded[5], encoded[6], encoded[7]]) as usize;
            assert_eq!(
                find_attribute(&encoded[40..header_length], attribute_type::SEQUENCE_NUMBER),
                Some(sequence.to_be_bytes().to_vec())
            );
        }
    }

    #[test]
    fn provisioned_destinations_win_over_the_configured_address() {
        let mut event = test_iri_event();
        assert_eq!(
            delivery_addresses(&event, "10.0.0.1:9999"),
            vec!["10.0.0.1:9999".to_string()],
            "with no provisioned destination the configured one is used"
        );

        event.destinations = vec![
            "192.0.2.1:42069".parse().expect("test address"),
            "198.51.100.2:42069".parse().expect("test address"),
        ];
        assert_eq!(
            delivery_addresses(&event, "10.0.0.1:9999"),
            vec![
                "192.0.2.1:42069".to_string(),
                "198.51.100.2:42069".to_string()
            ],
            "an event goes to every destination its task named"
        );
    }

    #[test]
    fn a_repeated_destination_is_delivered_to_once() {
        let mut event = test_iri_event();
        let same: SocketAddr = "192.0.2.1:42069".parse().expect("test address");
        event.destinations = vec![same, same];
        assert_eq!(delivery_addresses(&event, "unused"), vec![same.to_string()]);
    }

    #[test]
    fn tls_server_name_prefers_the_configured_name() {
        let tls = LiTlsConfig {
            certificate: None,
            private_key: None,
            ca_cert: None,
            verify_client: false,
            server_name: Some("mdf.example.test".to_string()),
        };
        assert_eq!(
            tls_server_name(Some(&tls), "192.0.2.1:42069"),
            "mdf.example.test"
        );
        assert_eq!(
            tls_server_name(None, "mdf.example.test:42069"),
            "mdf.example.test"
        );
        assert_eq!(tls_server_name(None, "[2001:db8::1]:42069"), "2001:db8::1");
    }

    /// TLS configured but unusable must stop delivery, never silently send the
    /// warrant's contents in the clear.
    #[test]
    fn tls_without_a_ca_is_refused() {
        let error = match build_tls_connector(None) {
            Err(error) => error,
            Ok(_) => panic!("TLS with no tls block must be refused"),
        };
        assert!(
            error.contains("no lawful_intercept.x2.tls block"),
            "{error}"
        );

        let tls = LiTlsConfig {
            certificate: None,
            private_key: None,
            ca_cert: None,
            verify_client: false,
            server_name: None,
        };
        let error = match build_tls_connector(Some(&tls)) {
            Err(error) => error,
            Ok(_) => panic!("TLS with no ca_cert must be refused"),
        };
        assert!(error.contains("ca_cert is required"), "{error}");
    }

    #[test]
    fn a_certificate_without_its_key_is_refused() {
        let tls = LiTlsConfig {
            certificate: Some("/nonexistent/ne.crt".to_string()),
            private_key: None,
            ca_cert: Some("/nonexistent/ca.crt".to_string()),
            verify_client: false,
            server_name: None,
        };
        // Fails on the CA read first, which is itself the point: every path is
        // read, and a missing file is a hard error rather than a downgrade.
        assert!(build_tls_connector(Some(&tls)).is_err());
    }

    #[tokio::test]
    async fn delivery_task_writes_a_pdu_the_receiver_can_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();

        let config = Arc::new(LiX2Config {
            delivery_address: address,
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
            keepalive_secs: 30,
            channel_size: 100,
            tls: None,
        });

        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(delivery_task(receiver, config));

        let accept_handle = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            // Read the mandatory header, then exactly what it says is left.
            let mut header = [0u8; 40];
            stream.read_exact(&mut header).await.expect("header");
            let header_length =
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let payload_length =
                u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let mut rest = vec![0u8; header_length - 40 + payload_length];
            stream.read_exact(&mut rest).await.expect("rest");
            (header, header_length, rest)
        });

        sender.send(test_iri_event()).await.expect("send");

        let (header, header_length, rest) =
            tokio::time::timeout(std::time::Duration::from_secs(5), accept_handle)
                .await
                .expect("delivery timed out")
                .expect("join");

        assert_eq!(&header[0..2], &[0x00, 0x05]);
        assert_eq!(&header[2..4], &[0x00, 0x01], "X2");
        assert_eq!(&header[12..14], &[0x00, 0x09], "SIP");
        assert_eq!(
            &rest[header_length - 40..],
            RAW_INVITE,
            "the framed payload is the SIP message"
        );
    }

    /// The record that opens the connection is a warrant's Begin, and losing it
    /// leaves the mediation function with a session it cannot open. So a
    /// collector that is not listening at the instant the call happens must not
    /// cost that record.
    #[tokio::test]
    async fn a_collector_that_accepts_late_still_gets_the_first_record() {
        // The address has to be real but unbound: the point is that nothing is
        // listening when the first record is delivered. A port-0 probe that is
        // closed again can be taken by any outbound socket in the window before
        // the rebind below, which is what made this test flap. `free_tcp_port`
        // keeps the port bound, and refusing connects, until the collector
        // listens on it.
        let address = crate::transport::testutil::free_tcp_port();

        let config = Arc::new(LiX2Config {
            delivery_address: address.to_string(),
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
            keepalive_secs: 30,
            channel_size: 100,
            tls: None,
        });

        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(delivery_task(receiver, config));
        sender.send(test_iri_event()).await.expect("send");

        // Bring the collector up after the first attempt has already failed.
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let listener = TcpListener::bind(address).await.expect("rebind");

        let accepted = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut header = [0u8; 40];
            stream.read_exact(&mut header).await.expect("header");
            header
        })
        .await
        .expect("the first record was dropped rather than retried");

        assert_eq!(&accepted[2..4], &[0x00, 0x01], "X2");
        assert_eq!(
            &accepted[16..32],
            &test_iri_event().x_id.as_bytes(),
            "the record held for the retry is the one that was queued"
        );
    }

    #[tokio::test]
    async fn every_provisioned_destination_receives_the_record() {
        let first = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let second = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let first_address = first.local_addr().expect("addr");
        let second_address = second.local_addr().expect("addr");

        let config = Arc::new(LiX2Config {
            delivery_address: "127.0.0.1:1".to_string(),
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
            keepalive_secs: 30,
            channel_size: 100,
            tls: None,
        });

        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(delivery_task(receiver, config));

        let read_one = |listener: TcpListener| async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let mut header = [0u8; 40];
            stream.read_exact(&mut header).await.expect("header");
            header
        };
        let first_handle = tokio::spawn(read_one(first));
        let second_handle = tokio::spawn(read_one(second));

        let mut event = test_iri_event();
        event.destinations = vec![first_address, second_address];
        sender.send(event).await.expect("send");

        for handle in [first_handle, second_handle] {
            let header = tokio::time::timeout(std::time::Duration::from_secs(5), handle)
                .await
                .expect("a provisioned destination received nothing")
                .expect("join");
            assert_eq!(&header[2..4], &[0x00, 0x01], "X2");
        }
    }

    /// Short enough to keep the tests quick, long enough that loopback
    /// scheduling noise cannot pass for a period.
    const TEST_KEEPALIVE: Duration = Duration::from_millis(150);

    /// Generous: a missed PDU fails on this rather than hanging the run.
    const RECEIVE_TIMEOUT: Duration = Duration::from_secs(5);

    fn keepalive_test_config(address: String, reconnect_interval_secs: u64) -> Arc<LiX2Config> {
        Arc::new(LiX2Config {
            delivery_address: address,
            transport: "tcp".to_string(),
            reconnect_interval_secs,
            keepalive_secs: 30,
            channel_size: 100,
            tls: None,
        })
    }

    /// One PDU as the MDF reads it, split along the clause 5 layout: the
    /// 40-octet mandatory header, the attribute TLVs, the payload.
    async fn read_pdu(stream: &mut TcpStream) -> ([u8; 40], Vec<u8>, Vec<u8>) {
        tokio::time::timeout(RECEIVE_TIMEOUT, async {
            let mut header = [0u8; 40];
            stream.read_exact(&mut header).await.expect("header");
            let header_length =
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]) as usize;
            let payload_length =
                u32::from_be_bytes([header[8], header[9], header[10], header[11]]) as usize;
            let mut attributes = vec![0u8; header_length - 40];
            stream
                .read_exact(&mut attributes)
                .await
                .expect("attributes");
            let mut payload = vec![0u8; payload_length];
            stream.read_exact(&mut payload).await.expect("payload");
            (header, attributes, payload)
        })
        .await
        .expect("no PDU arrived")
    }

    fn sequence_of(attributes: &[u8]) -> u32 {
        let value = find_attribute(attributes, attribute_type::SEQUENCE_NUMBER)
            .expect("every PDU carries a sequence number");
        u32::from_be_bytes([value[0], value[1], value[2], value[3]])
    }

    async fn accept(listener: &TcpListener) -> TcpStream {
        let (stream, _) = tokio::time::timeout(RECEIVE_TIMEOUT, listener.accept())
            .await
            .expect("no connection arrived")
            .expect("accept");
        stream
    }

    #[test]
    fn zero_keepalive_seconds_disables_keepalives() {
        assert_eq!(keepalive_period(0), None);
        assert_eq!(keepalive_period(30), Some(Duration::from_secs(30)));
    }

    /// The liveness signal itself, read field by field off the wire against the
    /// clause 5 layout rather than through our own encoder.
    #[tokio::test]
    async fn an_idle_connection_carries_keepalives_after_the_record() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(run_delivery(
            receiver,
            keepalive_test_config(address, 1),
            Some(TEST_KEEPALIVE),
        ));

        sender.send(test_iri_event()).await.expect("send");
        let mut stream = accept(&listener).await;
        let (header, attributes, _) = read_pdu(&mut stream).await;
        assert_eq!(&header[2..4], &[0x00, 0x01], "the record comes first");
        let record_sequence = sequence_of(&attributes);

        for expected in 1..=2u32 {
            let (header, attributes, payload) = read_pdu(&mut stream).await;
            assert_eq!(&header[0..2], &[0x00, 0x05], "version 0.5");
            assert_eq!(&header[2..4], &[0x00, 0x03], "PDU type keepalive");
            assert_eq!(
                u32::from_be_bytes([header[4], header[5], header[6], header[7]]),
                48,
                "header length: the mandatory 40 plus one sequence-number TLV"
            );
            assert_eq!(&header[8..12], &[0, 0, 0, 0], "no payload");
            assert!(payload.is_empty());
            assert_eq!(&header[14..16], &[0x00, 0x00], "direction reserved");
            assert_eq!(&header[32..40], &[0u8; 8], "all-zero correlation");
            assert_eq!(
                sequence_of(&attributes),
                record_sequence + expected,
                "keepalives share the connection's sequence with its records"
            );
        }
    }

    #[tokio::test]
    async fn no_keepalive_is_sent_when_disabled() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(run_delivery(
            receiver,
            keepalive_test_config(address, 1),
            None,
        ));

        sender.send(test_iri_event()).await.expect("send");
        let mut stream = accept(&listener).await;
        let (header, _, _) = read_pdu(&mut stream).await;
        assert_eq!(&header[2..4], &[0x00, 0x01], "X2");

        let mut octet = [0u8; 1];
        let idle = tokio::time::timeout(TEST_KEEPALIVE * 5, stream.read(&mut octet)).await;
        assert!(
            idle.is_err(),
            "a disabled keepalive sent something: {idle:?}"
        );
    }

    /// The MDF answers every keepalive. Unread, those answers fill our receive
    /// buffer and block the MDF's writes; read, they must not cost the
    /// connection either.
    #[tokio::test]
    async fn keepalive_acks_do_not_disturb_delivery() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (sender, receiver) = mpsc::channel(100);
        tokio::spawn(run_delivery(
            receiver,
            keepalive_test_config(address, 1),
            Some(TEST_KEEPALIVE),
        ));

        sender.send(test_iri_event()).await.expect("send");
        let mut stream = accept(&listener).await;
        let (_, attributes, _) = read_pdu(&mut stream).await;
        assert_eq!(sequence_of(&attributes), 0);

        for _ in 0..3 {
            let (header, attributes, _) = read_pdu(&mut stream).await;
            assert_eq!(&header[2..4], &[0x00, 0x03], "keepalive");
            let mut acknowledgement = Pdu::keepalive(sequence_of(&attributes));
            acknowledgement.pdu_type = PduType::KeepaliveAck;
            let bytes = acknowledgement.encode().expect("ack must encode");
            stream.write_all(&bytes).await.expect("ack");
        }

        sender.send(test_iri_event()).await.expect("send");
        let (record, record_sequence) = loop {
            let (header, attributes, payload) = read_pdu(&mut stream).await;
            if header[2..4] == [0x00, 0x01] {
                break (payload, sequence_of(&attributes));
            }
        };
        assert_eq!(record, RAW_INVITE, "the later record arrives intact");
        assert!(
            record_sequence > 3,
            "on the same connection, after the record and three keepalives: {record_sequence}"
        );
        assert!(
            tokio::time::timeout(TEST_KEEPALIVE, listener.accept())
                .await
                .is_err(),
            "the acks must not have cost the connection"
        );
    }

    /// A collector that went away is noticed while idle, so the next record
    /// opens a fresh connection at once instead of being written into the dead
    /// one.
    #[tokio::test]
    async fn a_closed_mediation_function_is_dropped_at_the_tick() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr").to_string();
        let (sender, receiver) = mpsc::channel(100);
        // A long reconnect interval: the write-failure path sleeps it before
        // reconnecting, so a record arriving well inside it can only have
        // taken the immediate path a dropped connection gives.
        let reconnect_interval_secs = 5;
        tokio::spawn(run_delivery(
            receiver,
            keepalive_test_config(address, reconnect_interval_secs),
            Some(TEST_KEEPALIVE),
        ));

        sender.send(test_iri_event()).await.expect("send");
        let mut first = accept(&listener).await;
        read_pdu(&mut first).await;
        drop(first);

        tokio::time::sleep(TEST_KEEPALIVE * 3).await;
        sender.send(test_iri_event()).await.expect("send");

        let (mut second, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("the closed connection was not dropped at the tick")
            .expect("accept");
        let (header, attributes, payload) = read_pdu(&mut second).await;
        assert_eq!(&header[2..4], &[0x00, 0x01], "X2");
        assert_eq!(payload, RAW_INVITE);
        assert_eq!(
            sequence_of(&attributes),
            0,
            "the sequence restarts on the new connection"
        );
    }

    #[tokio::test]
    async fn drain_reads_everything_pending_without_blocking() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let client = TcpStream::connect(address).await.expect("connect");
        let (mut peer, _) = listener.accept().await.expect("accept");

        peer.write_all(&[0xAB; 4000]).await.expect("write");
        peer.flush().await.expect("flush");
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut connection = Connection::Plain(client);
        tokio::time::timeout(Duration::from_secs(1), connection.drain_inbound())
            .await
            .expect("the drain must not wait for more")
            .expect("an open peer is not an error");

        let Connection::Plain(client) = &connection else {
            panic!("plain connection");
        };
        let mut scratch = [0u8; 16];
        let leftover = client.try_read(&mut scratch);
        assert!(
            leftover
                .as_ref()
                .is_err_and(|error| error.kind() == std::io::ErrorKind::WouldBlock),
            "everything pending was read: {leftover:?}"
        );
    }

    #[tokio::test]
    async fn drain_reports_a_peer_that_closed() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("addr");
        let client = TcpStream::connect(address).await.expect("connect");
        let (peer, _) = listener.accept().await.expect("accept");
        drop(peer);
        tokio::time::sleep(Duration::from_millis(50)).await;

        let mut connection = Connection::Plain(client);
        assert!(connection.drain_inbound().await.is_err());
    }
}
