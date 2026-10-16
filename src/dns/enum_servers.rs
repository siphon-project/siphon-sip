//! The ENUM servers a query names (`proxy.enum_query(..., servers=[...])`):
//! asked in the order given, each with its own timeout and attempt count, a
//! server that timed out or answered with an error held down for a while.
//!
//! An operator's ENUM service is usually a pair of dedicated servers, not the
//! resolvers the node uses for everything else, so these are asked directly
//! rather than through the system resolver list. The first server that
//! answers (with records, NXDOMAIN or NODATA) is the answer; SERVFAIL,
//! REFUSED, any other error response and a timeout move on to the next. A
//! server that failed is skipped for the hold-down (`enum.server_hold_down_secs`,
//! default 30 s): servers still in use are asked first, a held-down one only
//! after all of them, and it is back in the order once its hold-down runs out.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use hickory_resolver::config::{ConnectionConfig, NameServerConfig, ResolveHosts, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use hickory_resolver::net::{DnsError, NetError};
use hickory_resolver::proto::op::ResponseCode;
use hickory_resolver::proto::rr::{RData, RecordType};
use hickory_resolver::TokioResolver;
use tracing::{debug, error, warn};

use super::enum_naptr::NaptrRule;
use super::enum_query::{NaptrAnswer, NaptrLookup, NaptrSource};

/// How long a server that failed is passed over, by default.
pub const DEFAULT_HOLD_DOWN: Duration = Duration::from_secs(30);
/// How long one attempt at one server may take, by default.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
/// How many attempts one server gets, by default.
pub const DEFAULT_ATTEMPTS: usize = 2;

/// The most per-server resolvers kept. They are keyed by server and bounds,
/// which come from the script, so a script that varies `timeout_ms` per call
/// must not grow the map without end: past this the map starts over.
const MAX_RESOLVERS: usize = 64;

/// The most servers whose hold-down is remembered. Past this the ones whose
/// hold-down has run out are forgotten, and if that is not enough, all.
const MAX_HELD_SERVERS: usize = 1024;

/// The text form of a NAPTR record's fields.
pub(crate) fn naptr_rule(naptr: &hickory_resolver::proto::rr::rdata::NAPTR) -> NaptrRule {
    NaptrRule {
        order: naptr.order,
        preference: naptr.preference,
        flags: String::from_utf8_lossy(&naptr.flags).into_owned(),
        services: String::from_utf8_lossy(&naptr.services).into_owned(),
        regexp: String::from_utf8_lossy(&naptr.regexp).into_owned(),
        replacement: naptr.replacement.to_string(),
    }
}

/// What a NAPTR lookup came to: records, or which kind of nothing.
///
/// NXDOMAIN and NODATA are answers ("the name is not there"); an error
/// response code (SERVFAIL, REFUSED, ...) and a timeout are failures of the
/// server, and so is anything else that stopped the lookup short of a response.
pub(crate) fn classify(result: Result<hickory_resolver::lookup::Lookup, NetError>) -> NaptrLookup {
    match result {
        Ok(lookup) => NaptrLookup::Records(
            lookup
                .answers()
                .iter()
                .filter_map(|record| match &record.data {
                    RData::NAPTR(naptr) => Some(naptr_rule(naptr)),
                    _ => None,
                })
                .collect(),
        ),
        Err(NetError::Dns(DnsError::NoRecordsFound(no_records))) => {
            match no_records.response_code {
                ResponseCode::NXDomain => NaptrLookup::NoSuchName,
                _ => NaptrLookup::NoRecords,
            }
        }
        Err(NetError::Timeout) => NaptrLookup::Timeout,
        Err(error) => {
            debug!(%error, "NAPTR lookup failed");
            NaptrLookup::ServerFailure
        }
    }
}

/// Server state and per-server resolvers, shared by every query of a node.
#[derive(Debug)]
pub struct EnumServers {
    hold_down: Duration,
    /// Servers held down, until when.
    held_until: DashMap<SocketAddr, Instant>,
    /// One resolver per server and bound, built on first use.
    resolvers: DashMap<(SocketAddr, Duration, usize), TokioResolver>,
}

impl Default for EnumServers {
    fn default() -> Self {
        Self::new(DEFAULT_HOLD_DOWN)
    }
}

impl EnumServers {
    pub fn new(hold_down: Duration) -> Self {
        Self {
            hold_down,
            held_until: DashMap::new(),
            resolvers: DashMap::new(),
        }
    }

    /// Whether `server` is held down at `now`.
    pub fn is_held_down(&self, server: SocketAddr, now: Instant) -> bool {
        self.held_until
            .get(&server)
            .is_some_and(|until| now < *until)
    }

    /// `servers` in the order they are asked at `now`: those in use first,
    /// then those held down, each group in the order given.
    pub fn order(&self, servers: &[SocketAddr], now: Instant) -> Vec<SocketAddr> {
        let (held, in_use): (Vec<SocketAddr>, Vec<SocketAddr>) = servers
            .iter()
            .copied()
            .partition(|server| self.is_held_down(*server, now));
        in_use.into_iter().chain(held).collect()
    }

    fn mark(&self, server: SocketAddr, failed: bool, now: Instant) {
        if failed {
            if self.held_until.len() >= MAX_HELD_SERVERS {
                self.held_until.retain(|_, until| now < *until);
                if self.held_until.len() >= MAX_HELD_SERVERS {
                    // Every one still held: forgetting them only means each is
                    // asked once more before it is held down again.
                    self.held_until.clear();
                }
            }
            if !self.is_held_down(server, now) {
                warn!(%server, hold_down_secs = self.hold_down.as_secs(), "ENUM server failed, held down");
            }
            self.held_until.insert(server, now + self.hold_down);
        } else {
            self.held_until.remove(&server);
        }
        crate::metrics::enum_servers::record_server(server, !failed);
    }

    /// The resolver that asks `server` alone, with these bounds. `None`, said
    /// at `error`, when it cannot be built: the server then counts as failed.
    fn resolver(
        &self,
        server: SocketAddr,
        timeout: Duration,
        attempts: usize,
    ) -> Option<TokioResolver> {
        let key = (server, timeout, attempts);
        if let Some(resolver) = self.resolvers.get(&key) {
            return Some(resolver.clone());
        }
        let mut udp = ConnectionConfig::udp();
        udp.port = server.port();
        let mut tcp = ConnectionConfig::tcp();
        tcp.port = server.port();
        let config = ResolverConfig::from_parts(
            None,
            Vec::new(),
            vec![NameServerConfig::new(server.ip(), true, vec![udp, tcp])],
        );
        let mut builder =
            TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
        builder.options_mut().timeout = timeout;
        // hickory's `attempts` counts the retries after the first try.
        builder.options_mut().attempts = attempts.max(1) - 1;
        // No search list and no hosts file: the name asked is the name the
        // ENUM service is asked.
        builder.options_mut().ndots = 0;
        builder.options_mut().use_hosts_file = ResolveHosts::Never;
        match builder.build() {
            Ok(resolver) => {
                if self.resolvers.len() >= MAX_RESOLVERS {
                    self.resolvers.clear();
                }
                self.resolvers.insert(key, resolver.clone());
                Some(resolver)
            }
            Err(error) => {
                error!(%server, %error, "could not build a resolver for the ENUM server");
                None
            }
        }
    }

    /// Ask `servers` for the NAPTR records of `name`, as the module says.
    pub async fn naptr(
        &self,
        servers: &[SocketAddr],
        name: &str,
        timeout: Duration,
        attempts: usize,
    ) -> NaptrAnswer {
        let mut every_failure_timed_out = true;
        for server in self.order(servers, Instant::now()) {
            // Bounded here as well, so one server can never take more than
            // its share, whatever the resolver does with its attempts.
            let budget = timeout * attempts.max(1) as u32 + Duration::from_millis(250);
            let lookup = match self.resolver(server, timeout, attempts) {
                Some(resolver) => {
                    match tokio::time::timeout(budget, resolver.lookup(name, RecordType::NAPTR))
                        .await
                    {
                        Ok(result) => classify(result),
                        Err(_) => NaptrLookup::Timeout,
                    }
                }
                None => NaptrLookup::ServerFailure,
            };
            match lookup {
                NaptrLookup::ServerFailure | NaptrLookup::Timeout => {
                    every_failure_timed_out &= lookup == NaptrLookup::Timeout;
                    debug!(%server, query = %name, ?lookup, "ENUM server did not answer the query");
                    self.mark(server, true, Instant::now());
                }
                answered => {
                    self.mark(server, false, Instant::now());
                    return NaptrAnswer {
                        lookup: answered,
                        server: Some(server),
                    };
                }
            }
        }
        NaptrAnswer {
            lookup: if every_failure_timed_out && !servers.is_empty() {
                NaptrLookup::Timeout
            } else {
                NaptrLookup::ServerFailure
            },
            server: None,
        }
    }
}

/// A query over a list of servers with the bounds it was given.
pub struct ServerList<'a> {
    pub servers: &'a EnumServers,
    pub list: &'a [SocketAddr],
    pub timeout: Duration,
    pub attempts: usize,
}

impl NaptrSource for ServerList<'_> {
    fn naptr(&self, name: &str) -> impl std::future::Future<Output = NaptrAnswer> + Send {
        self.servers
            .naptr(self.list, name, self.timeout, self.attempts)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::enum_query::{enum_query, EnumOutcome};
    use hickory_resolver::proto::op::{Message, OpCode};
    use hickory_resolver::proto::rr::rdata::NAPTR;
    use hickory_resolver::proto::rr::{Name, Record};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    /// How an in-process DNS server answers.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Behaviour {
        /// One terminal `E2U+sip` record whose URI names `tag`.
        Answer(&'static str),
        NxDomain,
        NoData,
        ServFail,
        Refused,
        /// Never answers (a black hole).
        Silent,
    }

    struct Server {
        address: SocketAddr,
        asked: Arc<AtomicUsize>,
    }

    /// A UDP DNS server on loopback answering every query as `behaviour`.
    async fn server(behaviour: Behaviour) -> Server {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback socket");
        let address = socket.local_addr().expect("its address");
        let asked = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&asked);
        tokio::spawn(async move {
            let mut buffer = vec![0u8; 4096];
            while let Ok((size, peer)) = socket.recv_from(&mut buffer).await {
                counter.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_vec(&buffer[..size]) else {
                    continue;
                };
                if behaviour == Behaviour::Silent {
                    continue;
                }
                let mut response = Message::response(query.metadata.id, OpCode::Query);
                response.metadata.authoritative = true;
                response.metadata.recursion_desired = query.metadata.recursion_desired;
                for question in &query.queries {
                    response.add_query(question.clone());
                }
                match behaviour {
                    Behaviour::Answer(tag) => {
                        let name = query
                            .queries
                            .first()
                            .map(|question| question.name().clone())
                            .unwrap_or_else(Name::root);
                        let naptr = NAPTR::new(
                            10,
                            10,
                            b"u".to_vec().into_boxed_slice(),
                            b"E2U+sip".to_vec().into_boxed_slice(),
                            format!("!^.*$!sip:{tag}@example.com!")
                                .into_bytes()
                                .into_boxed_slice(),
                            Name::root(),
                        );
                        response.add_answer(Record::from_rdata(name, 60, RData::NAPTR(naptr)));
                    }
                    Behaviour::NxDomain => {
                        response.metadata.response_code = ResponseCode::NXDomain;
                    }
                    Behaviour::NoData => {}
                    Behaviour::ServFail => {
                        response.metadata.response_code = ResponseCode::ServFail;
                    }
                    Behaviour::Refused => {
                        response.metadata.response_code = ResponseCode::Refused;
                    }
                    Behaviour::Silent => {}
                }
                if let Ok(bytes) = response.to_vec() {
                    let _ = socket.send_to(&bytes, peer).await;
                }
            }
        });
        Server { address, asked }
    }

    const NUMBER: &str = "+15550100106";
    const TIMEOUT: Duration = Duration::from_millis(200);

    async fn ask(
        servers: &EnumServers,
        list: &[SocketAddr],
        number: &str,
    ) -> crate::dns::enum_query::EnumAnswer {
        let source = ServerList {
            servers,
            list,
            timeout: TIMEOUT,
            attempts: 1,
        };
        enum_query(&source, number, "e164.arpa.", "E2U+sip", true)
            .await
            .expect("the query starts")
    }

    /// Each kind of nothing a server can answer with has its own outcome.
    #[tokio::test]
    async fn each_answer_from_a_server_has_its_own_outcome() {
        for (behaviour, outcome) in [
            (Behaviour::Answer("first"), EnumOutcome::Ok),
            (Behaviour::NxDomain, EnumOutcome::NoSuchName),
            (Behaviour::NoData, EnumOutcome::NoRecords),
            (Behaviour::ServFail, EnumOutcome::ServerFailure),
            (Behaviour::Refused, EnumOutcome::ServerFailure),
            (Behaviour::Silent, EnumOutcome::Timeout),
        ] {
            let server = server(behaviour).await;
            let servers = EnumServers::default();
            let answer = ask(&servers, &[server.address], NUMBER).await;
            assert_eq!(answer.outcome, outcome, "{behaviour:?}");
            if outcome == EnumOutcome::Ok {
                assert_eq!(answer.uris, ["sip:first@example.com"]);
                assert_eq!(answer.server, Some(server.address));
            }
        }
    }

    /// Two servers, the first a black hole: the answer comes from the second
    /// within one timeout; the next query within the hold-down goes to the
    /// second first; after the hold-down the first is asked again.
    #[tokio::test]
    async fn a_silent_server_is_passed_over_for_its_hold_down() {
        let dead = server(Behaviour::Silent).await;
        let live = server(Behaviour::Answer("second")).await;
        let servers = EnumServers::new(Duration::from_millis(400));
        let list = [dead.address, live.address];

        let started = Instant::now();
        let answer = ask(&servers, &list, "+15550100107").await;
        assert_eq!(answer.outcome, EnumOutcome::Ok);
        assert_eq!(answer.server, Some(live.address));
        assert!(
            started.elapsed() < Duration::from_millis(1500),
            "answered within the dead server's bound, not the default's: {:?}",
            started.elapsed()
        );
        assert_eq!(dead.asked.load(Ordering::SeqCst), 1);
        assert!(servers.is_held_down(dead.address, Instant::now()));

        // Within the hold-down the live one is asked first, and answers.
        let answer = ask(&servers, &list, "+15550100108").await;
        assert_eq!(answer.server, Some(live.address));
        assert_eq!(dead.asked.load(Ordering::SeqCst), 1, "not asked again yet");
        assert_eq!(
            servers.order(&list, Instant::now()),
            [live.address, dead.address]
        );

        // After it, the first server is first again.
        tokio::time::sleep(Duration::from_millis(450)).await;
        assert_eq!(
            servers.order(&list, Instant::now()),
            [dead.address, live.address]
        );
        ask(&servers, &list, "+15550100109").await;
        assert_eq!(dead.asked.load(Ordering::SeqCst), 2);
    }

    /// An error response moves on to the next server, like a timeout.
    #[tokio::test]
    async fn a_refusing_server_moves_on_to_the_next() {
        let refusing = server(Behaviour::Refused).await;
        let live = server(Behaviour::Answer("next")).await;
        let servers = EnumServers::default();
        let answer = ask(&servers, &[refusing.address, live.address], NUMBER).await;
        assert_eq!(answer.uris, ["sip:next@example.com"]);
        assert!(servers.is_held_down(refusing.address, Instant::now()));
    }

    /// NXDOMAIN is an answer: the next server is not asked.
    #[tokio::test]
    async fn no_such_name_from_the_first_server_is_the_answer() {
        let first = server(Behaviour::NxDomain).await;
        let second = server(Behaviour::Answer("unused")).await;
        let servers = EnumServers::default();
        let answer = ask(&servers, &[first.address, second.address], NUMBER).await;
        assert_eq!(answer.outcome, EnumOutcome::NoSuchName);
        assert_eq!(answer.server, Some(first.address));
        assert_eq!(second.asked.load(Ordering::SeqCst), 0);
        assert!(!servers.is_held_down(first.address, Instant::now()));
    }

    /// Every server failing: `timeout` only when each of them timed out.
    #[tokio::test]
    async fn every_server_failing_is_a_failure() {
        let silent = server(Behaviour::Silent).await;
        let failing = server(Behaviour::ServFail).await;
        let servers = EnumServers::default();
        let answer = ask(&servers, &[silent.address, failing.address], NUMBER).await;
        assert_eq!(answer.outcome, EnumOutcome::ServerFailure);
        assert_eq!(answer.server, None);

        let other = server(Behaviour::Silent).await;
        let servers = EnumServers::default();
        let answer = ask(&servers, &[silent.address, other.address], "+15550100110").await;
        assert_eq!(answer.outcome, EnumOutcome::Timeout);
    }

    /// Per-server resolvers are built once per server and bound.
    #[tokio::test]
    async fn resolvers_are_kept_per_server_and_bound() {
        let live = server(Behaviour::Answer("kept")).await;
        let servers = EnumServers::default();
        for number in ["+15550100111", "+15550100112"] {
            ask(&servers, &[live.address], number).await;
        }
        assert_eq!(servers.resolvers.len(), 1);
    }

    /// Leak gate: a script varying its bounds call by call, or naming many
    /// servers that fail, does not grow the state without end.
    #[tokio::test]
    async fn varying_bounds_and_failing_servers_stay_bounded() {
        let live = server(Behaviour::Answer("bounded")).await;
        let servers = EnumServers::new(Duration::from_millis(1));
        for timeout_ms in 1..=(MAX_RESOLVERS as u64 * 3) {
            servers
                .naptr(
                    &[live.address],
                    "1.0.0.0.5.5.5.1.e164.arpa.",
                    Duration::from_millis(100 + timeout_ms),
                    1,
                )
                .await;
            assert!(servers.resolvers.len() <= MAX_RESOLVERS);
        }
        let now = Instant::now();
        for port in 0..(MAX_HELD_SERVERS as u16 * 2) {
            let failed = SocketAddr::from(([192, 0, 2, 1], 1000 + port));
            servers.mark(failed, true, now - Duration::from_secs(1));
            assert!(servers.held_until.len() <= MAX_HELD_SERVERS);
        }
    }
}
