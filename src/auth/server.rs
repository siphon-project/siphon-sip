//! The SQL credential source behind `auth.backend: database`.
//!
//! This is the server (UAS) side of digest authentication: siphon holds the
//! credential and verifies what the peer sent, rather than answering a
//! challenge itself (that is [`crate::auth`]'s client half).
//!
//! The query belongs to the operator. Schemas differ enough that a fixed one
//! would mean every deployment maintaining a view for us, so
//! [`DatabaseAuthConfig::query`] is passed through as a prepared statement with
//! the digest username bound to `$1` — never interpolated, so a crafted
//! username is a parameter and not SQL.

use crate::config::DatabaseAuthConfig;

/// What a credential source said about a username.
///
/// `NotFound` and `Unavailable` are deliberately distinct. `NotFound` is
/// evidence about the peer — the subscriber does not exist — and counts toward
/// the auto-ban. `Unavailable` is evidence about *us*: the database did not
/// answer, so the peer has told us nothing, and counting it would turn an
/// outage of our own credential store into a wave of bans on legitimate
/// subscribers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CredentialLookup {
    /// The stored credential: an H(A1) hex string or a plaintext password,
    /// per `auth.database.ha1`.
    Found(String),
    /// The query ran and matched no row.
    NotFound,
    /// The credential source could not be reached or errored.
    Unavailable,
}

/// Column holding the H(A1) for `algorithm`, by convention `ha1_<hash>`.
///
/// A stored H(A1) is bound to the hash it was computed with (RFC 7616 §3.4.3),
/// so a table with one `ha1` column can only serve clients that answer with
/// that one algorithm. RFC 8760 exists because that is a problem: a deployment
/// moving to SHA-256 has to serve both while its phones catch up. One column
/// per hash lets the same row answer either, and the credential never has to be
/// stored as a password that would register as the subscriber.
///
/// The `-sess` variants share the base hash's column: the session H(A1) folds
/// in a per-request cnonce, so it is not a thing a table can hold.
pub(crate) fn ha1_column_for(algorithm: crate::auth::DigestAlgorithm) -> &'static str {
    use crate::auth::DigestAlgorithm;
    // `stored_ha1_hash` owns the "which hash is a stored H(A1) bound to"
    // mapping, including folding the `-sess` variants into their base and
    // ranking AKAv1-MD5 (a computed RES, never a stored secret) with MD5.
    match algorithm.stored_ha1_hash() {
        DigestAlgorithm::Sha256 => "ha1_sha256",
        DigestAlgorithm::Sha512_256 => "ha1_sha512_256",
        _ => "ha1_md5",
    }
}

#[cfg(feature = "postgres-backend")]
pub(crate) use postgres::DatabaseCredentials;

#[cfg(feature = "postgres-backend")]
mod postgres {
    use super::{CredentialLookup, DatabaseAuthConfig};
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::sync::Mutex;
    use tracing::{debug, warn};

    /// A PostgreSQL credential source, reconnecting on demand.
    ///
    /// The connection is lazy and self-healing rather than established once at
    /// start-up: `tokio_postgres` ends its connection task when the socket
    /// drops, and a client that outlives it fails every query afterwards. Held
    /// as a single connection because a credential lookup is one short
    /// statement and the cache in front of it (`auth.database.cache_ttl_secs`)
    /// is what absorbs a registration storm.
    #[derive(Debug)]
    pub(crate) struct DatabaseCredentials {
        config: DatabaseAuthConfig,
        /// `None` until the first lookup, and again after a connection dies.
        client: Arc<Mutex<Option<Arc<tokio_postgres::Client>>>>,
        /// Whether the statement references `$2`, so the realm is bound only
        /// when the operator's query asks for it — passing a parameter a
        /// statement does not use is an error, not a no-op.
        binds_realm: bool,
    }

    impl DatabaseCredentials {
        /// Prepare a credential source. Does not connect: the first lookup does,
        /// so a database that is slow to come up does not hold up start-up.
        pub(crate) fn new(config: DatabaseAuthConfig) -> Self {
            let binds_realm = config.query.contains("$2");
            Self {
                config,
                client: Arc::new(Mutex::new(None)),
                binds_realm,
            }
        }

        /// Seconds a cached lookup stays valid.
        pub(crate) fn cache_ttl_secs(&self) -> u64 {
            self.config.cache_ttl_secs
        }

        /// Whether the stored credential is a pre-hashed H(A1).
        pub(crate) fn stores_ha1(&self) -> bool {
            self.config.ha1
        }

        /// Look up `username` (and `realm`, when the query binds it).
        ///
        /// Blocking, called from the Python executor: the interpreter is
        /// released for the whole exchange via
        /// [`crate::script::detach_block_on`], which is mandatory on
        /// free-threaded CPython — blocking while attached stalls the GC
        /// stop-the-world and wedges the engine.
        pub(crate) fn lookup(
            &self,
            username: &str,
            realm: &str,
            ha1_column: &str,
        ) -> CredentialLookup {
            crate::script::detach_block_on(self.lookup_async(username, realm, ha1_column))
        }

        /// The awaitable core of [`Self::lookup`].
        ///
        /// Two entry points because the callers differ in what they may block:
        /// siphon's dispatcher reaches this from a sync worker, while a script
        /// API reaches it from an asyncio driver many coroutines share.
        pub(crate) async fn lookup_async(
            &self,
            username: &str,
            realm: &str,
            ha1_column: &str,
        ) -> CredentialLookup {
            let timeout = Duration::from_millis(self.config.timeout_ms);
            {
                match tokio::time::timeout(timeout, self.query(username, realm, ha1_column)).await {
                    Ok(outcome) => outcome,
                    Err(_) => {
                        warn!(
                            username = %username,
                            timeout_ms = self.config.timeout_ms,
                            "database auth: lookup timed out"
                        );
                        self.drop_client().await;
                        Self::backend_error()
                    }
                }
            }
        }

        async fn query(&self, username: &str, realm: &str, ha1_column: &str) -> CredentialLookup {
            let client = match self.client().await {
                Ok(client) => client,
                Err(error) => {
                    warn!(error = %error, "database auth: connect failed");
                    return Self::backend_error();
                }
            };

            let rows = if self.binds_realm {
                client.query(&self.config.query, &[&username, &realm]).await
            } else {
                client.query(&self.config.query, &[&username]).await
            };

            match rows {
                Ok(rows) => match rows.first() {
                    Some(row) => {
                        // One column is the credential, whatever it is called.
                        // Several means one H(A1) per hash (RFC 8760), selected
                        // by the algorithm the client actually answered with —
                        // picking the first would verify MD5 against a SHA-256
                        // hash and reject every SHA-256 phone.
                        let column = if self.config.ha1 && row.columns().len() > 1 {
                            if !row.columns().iter().any(|c| c.name() == ha1_column) {
                                warn!(
                                    wanted = %ha1_column,
                                    "database auth: the client's algorithm has no column in the \
                                     result — auth.database.query must select ha1_md5 / \
                                     ha1_sha256 / ha1_sha512_256 for the algorithms served"
                                );
                                return Self::backend_error();
                            }
                            ha1_column
                        } else {
                            row.columns()
                                .first()
                                .map(|c| c.name())
                                .unwrap_or(ha1_column)
                        };
                        match row.try_get::<_, String>(column) {
                            Ok(credential) => {
                                debug!(
                                    username = %username,
                                    column = %column,
                                    "database auth: credential found"
                                );
                                CredentialLookup::Found(credential)
                            }
                            Err(error) => {
                                // A column that is not text is a schema mistake,
                                // not a verdict on the subscriber.
                                warn!(
                                    error = %error,
                                    column = %column,
                                    "database auth: the credential column is not text"
                                );
                                Self::backend_error()
                            }
                        }
                    }
                    None => {
                        debug!(username = %username, "database auth: no such subscriber");
                        CredentialLookup::NotFound
                    }
                },
                Err(error) => {
                    warn!(error = %error, "database auth: query failed");
                    // The socket may be gone rather than the statement bad;
                    // drop it so the next lookup reconnects instead of failing
                    // for the life of the process.
                    self.drop_client().await;
                    Self::backend_error()
                }
            }
        }

        /// Count a backend failure and report it as telling us nothing about
        /// the peer.
        fn backend_error() -> CredentialLookup {
            if let Some(metrics) = crate::metrics::try_metrics() {
                metrics.auth_backend_errors_total.inc();
            }
            CredentialLookup::Unavailable
        }

        /// The live client, connecting if there is none or the last one closed.
        async fn client(&self) -> Result<Arc<tokio_postgres::Client>, String> {
            let mut guard = self.client.lock().await;
            if let Some(client) = guard.as_ref() {
                if !client.is_closed() {
                    return Ok(Arc::clone(client));
                }
                debug!("database auth: connection closed, reconnecting");
                *guard = None;
            }

            let (client, connection) =
                tokio_postgres::connect(&self.config.url, tokio_postgres::NoTls)
                    .await
                    .map_err(|error| error.to_string())?;
            tokio::spawn(async move {
                if let Err(error) = connection.await {
                    warn!(error = %error, "database auth: connection ended");
                }
            });
            let client = Arc::new(client);
            *guard = Some(Arc::clone(&client));
            debug!("database auth: connected");
            Ok(client)
        }

        async fn drop_client(&self) {
            *self.client.lock().await = None;
        }

        /// Whether the configured statement binds the realm. Exposed so the
        /// binding layer's tests can assert the rule without a database.
        #[cfg(test)]
        pub(crate) fn binds_realm_for_test(&self) -> bool {
            self.binds_realm
        }
    }
}

/// Stand-in when the `postgres-backend` feature is off.
///
/// Config load refuses `auth.backend: database` without the feature, so this
/// exists to keep the call sites compiling rather than to be used.
#[cfg(not(feature = "postgres-backend"))]
#[derive(Debug)]
pub(crate) struct DatabaseCredentials {
    config: DatabaseAuthConfig,
}

#[cfg(not(feature = "postgres-backend"))]
impl DatabaseCredentials {
    pub(crate) fn new(config: DatabaseAuthConfig) -> Self {
        Self { config }
    }

    pub(crate) fn cache_ttl_secs(&self) -> u64 {
        self.config.cache_ttl_secs
    }

    pub(crate) fn stores_ha1(&self) -> bool {
        self.config.ha1
    }

    #[cfg(test)]
    pub(crate) fn binds_realm_for_test(&self) -> bool {
        self.config.query.contains("$2")
    }

    pub(crate) fn lookup(
        &self,
        _username: &str,
        _realm: &str,
        _ha1_column: &str,
    ) -> CredentialLookup {
        Self::unsupported()
    }

    /// The awaitable twin, so the script APIs compile without the feature too.
    pub(crate) async fn lookup_async(
        &self,
        _username: &str,
        _realm: &str,
        _ha1_column: &str,
    ) -> CredentialLookup {
        Self::unsupported()
    }

    fn unsupported() -> CredentialLookup {
        tracing::warn!(
            "auth.backend: database needs the postgres-backend feature, which this binary \
             was built without"
        );
        CredentialLookup::Unavailable
    }
}
