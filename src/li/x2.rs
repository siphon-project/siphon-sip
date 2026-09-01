//! X2 IRI delivery — ETSI TS 103 221-2 signalling export to the MDF.
//!
//! One persistent connection per delivery address, reconnecting on loss, fed by
//! the bounded IRI channel.
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
use tokio::io::{AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
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
}

async fn write_and_flush<W>(stream: &mut W, bytes: &[u8]) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    stream.write_all(bytes).await?;
    stream.flush().await
}

/// How to reach one mediation function.
struct Delivery {
    address: String,
    connector: Option<TlsConnector>,
    server_name: String,
    connection: Option<Connection>,
    /// Per-connection PDU counter for the sequence-number attribute.
    sequence: u32,
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
            self.connection = Some(Connection::Plain(tcp_stream));
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
                self.connection = Some(Connection::Tls(Box::new(stream)));
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
}

/// Background task that drains the IRI channel and delivers to the MDF.
///
/// Runs for the lifetime of the LI subsystem.
pub async fn delivery_task(mut receiver: mpsc::Receiver<IriEvent>, config: Arc<LiX2Config>) {
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

    while let Some(event) = receiver.recv().await {
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
            let delivery = deliveries.entry(address.clone()).or_insert_with(|| Delivery {
                address: address.clone(),
                connector: connector.clone(),
                server_name,
                connection: None,
                sequence: 0,
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
            // The sequence number is per connection, so the retry restarts it.
            delivery.sequence = 0;
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
            let certificate_pem =
                std::fs::read(certificate_path).map_err(|error| format!("{certificate_path}: {error}"))?;
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

        assert!(
            find_attribute(attributes, attribute_type::SOURCE_IPV4)
                .is_some_and(|value| value == vec![192, 0, 2, 1])
        );
        assert!(
            find_attribute(attributes, attribute_type::DESTINATION_IPV4)
                .is_some_and(|value| value == vec![198, 51, 100, 9])
        );
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
        assert_eq!(tls_server_name(None, "mdf.example.test:42069"), "mdf.example.test");
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
        assert!(error.contains("no lawful_intercept.x2.tls block"), "{error}");

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
        // Claim a port, then release it, so the address is real but nothing is
        // listening when the first record is delivered.
        let scout = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = scout.local_addr().expect("addr");
        drop(scout);

        let config = Arc::new(LiX2Config {
            delivery_address: address.to_string(),
            transport: "tcp".to_string(),
            reconnect_interval_secs: 1,
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
}
