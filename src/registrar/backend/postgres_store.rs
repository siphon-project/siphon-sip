//! PostgreSQL registrar backend.
//!
//! Split out of `backend.rs` beside the Redis backend, for the same reason.

use super::*;
use std::sync::Arc;

/// PostgreSQL registrar backend.
///
/// Stores contacts in a table with `(aor, contact_uri)` as the primary key.
/// Contact data is stored as TEXT (JSON string). Expired rows are filtered
/// on read and deleted by [`purge_expired`](RegistrarBackend::purge_expired),
/// which the writer task runs periodically: rows here have no TTL of their
/// own, so without it every expired binding and its auxiliary state stayed.
///
/// Supports optional auto-sharding across multiple PostgreSQL instances.
#[derive(Debug)]
pub struct PostgresBackend {
    config: PostgresBackendConfig,
    /// Clients — single element when not sharding, multiple when sharding.
    clients: Vec<Arc<tokio_postgres::Client>>,
    /// The longest binding the registrar grants. An auxiliary-state row with
    /// no live binding is purged once it has gone unwritten this long plus
    /// `expired_row_grace_secs`.
    max_binding_lifetime_secs: u64,
    /// How long an expired contact row stays before the purge deletes it:
    /// the margin `ttl_slack_secs` gives a Redis key.
    expired_row_grace_secs: u64,
}

/// [`PostgresBackend::expired_row_grace_secs`]: the Redis backend's default
/// `ttl_slack_secs`.
const EXPIRED_ROW_GRACE_SECS: u64 = 30;

impl PostgresBackend {
    /// Connect to PostgreSQL and create the registrations table if needed.
    pub async fn connect(config: PostgresBackendConfig) -> Result<Self, BackendError> {
        let clients = if config.shard_count > 0 {
            if config.urls.len() != config.shard_count {
                return Err(BackendError::Connection(format!(
                    "shard_count is {} but {} URLs provided",
                    config.shard_count,
                    config.urls.len()
                )));
            }
            let mut clients = Vec::with_capacity(config.shard_count);
            for url in &config.urls {
                let client = Self::connect_one(url, &config.table).await?;
                clients.push(client);
            }
            tracing::info!(
                shard_count = config.shard_count,
                table = %config.table,
                "postgres registrar backend connected (sharded)"
            );
            clients
        } else {
            let client = Self::connect_one(&config.url, &config.table).await?;
            tracing::info!(table = %config.table, "postgres registrar backend connected");
            vec![client]
        };

        Ok(Self {
            config,
            clients,
            max_binding_lifetime_secs: DEFAULT_MAX_BINDING_LIFETIME_SECS,
            expired_row_grace_secs: EXPIRED_ROW_GRACE_SECS,
        })
    }

    /// Set the longest binding the registrar grants (`registrar.max_expires`),
    /// which bounds a state row with no live binding.
    pub fn with_max_binding_lifetime(mut self, secs: u64) -> Self {
        self.max_binding_lifetime_secs = secs;
        self
    }

    /// Connect to a single PostgreSQL instance and ensure the table exists.
    async fn connect_one(
        url: &str,
        table: &str,
    ) -> Result<Arc<tokio_postgres::Client>, BackendError> {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .map_err(|error| BackendError::Connection(error.to_string()))?;

        // Spawn the connection task so it runs in the background.
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                tracing::error!("postgres connection error: {error}");
            }
        });

        // Create the registrations table if it does not exist.
        // Data is stored as TEXT (JSON string) to avoid requiring the
        // `with-serde_json-1` feature on tokio-postgres.
        let create_table_query = format!(
            "CREATE TABLE IF NOT EXISTS {} (
                aor TEXT NOT NULL,
                contact_uri TEXT NOT NULL,
                data TEXT NOT NULL,
                expires_at TIMESTAMPTZ NOT NULL,
                PRIMARY KEY (aor, contact_uri)
            )",
            table
        );
        client
            .execute(&create_table_query, &[])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        // Companion table for the per-AoR auxiliary state (Service-Route,
        // P-Asserted-Identity, P-Associated-URI list).  Stored as JSON
        // text, one row per AoR.
        let create_state_table_query = format!(
            "CREATE TABLE IF NOT EXISTS {}_aor_state (
                aor TEXT PRIMARY KEY,
                state TEXT NOT NULL
            )",
            table
        );
        client
            .execute(&create_state_table_query, &[])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        // When the state was last written, so the purge can tell state set
        // ahead of a binding from state its binding has outlived. Added to
        // a table from an earlier version too; its rows read as written
        // now and are purged a full binding lifetime later if no binding
        // claims them.
        let add_updated_at = format!(
            "ALTER TABLE {}_aor_state
                ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()",
            table
        );
        client
            .execute(&add_updated_at, &[])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        Ok(Arc::new(client))
    }

    fn state_table(&self) -> String {
        format!("{}_aor_state", self.config.table)
    }

    /// Get the client for the given AoR (shard-aware).
    fn client_for(&self, aor: &str) -> &tokio_postgres::Client {
        if self.clients.len() == 1 {
            &self.clients[0]
        } else {
            let index = shard_index(aor, self.clients.len());
            &self.clients[index]
        }
    }
}

impl RegistrarBackend for PostgresBackend {
    async fn save(&self, aor: &str, contacts: &[StoredContact]) -> Result<(), BackendError> {
        let client = self.client_for(aor);
        let table = &self.config.table;

        if contacts.is_empty() {
            let query = format!("DELETE FROM {} WHERE aor = $1", table);
            client
                .execute(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            return Ok(());
        }

        // "Replacing any existing bindings": a contact no longer in the
        // set (one removed, or de-registered on its own) goes, or it would
        // be restored and counted until it expired.
        let uris: Vec<&str> = contacts
            .iter()
            .map(|contact| contact.uri.as_str())
            .collect();
        let prune = format!(
            "DELETE FROM {} WHERE aor = $1 AND NOT (contact_uri = ANY($2))",
            table
        );
        client
            .execute(&prune, &[&aor, &uris])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        // Upsert each contact individually.
        let query = format!(
            "INSERT INTO {} (aor, contact_uri, data, expires_at)
             VALUES ($1, $2, $3, NOW() + $4 * INTERVAL '1 second')
             ON CONFLICT (aor, contact_uri) DO UPDATE
             SET data = $3, expires_at = NOW() + $4 * INTERVAL '1 second'",
            table
        );

        for contact in contacts {
            let json = serde_json::to_string(contact)
                .map_err(|error| BackendError::Serialization(error.to_string()))?;
            let expires_secs = contact.remaining_secs() as f64;

            client
                .execute(&query, &[&aor, &contact.uri, &json, &expires_secs])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
        }

        Ok(())
    }

    async fn load(&self, aor: &str) -> Result<Vec<StoredContact>, BackendError> {
        let client = self.client_for(aor);
        let table = &self.config.table;

        // Select remaining seconds so we can set accurate TTL on the
        // deserialized StoredContact, regardless of when it was stored.
        let query = format!(
            "SELECT data, EXTRACT(EPOCH FROM (expires_at - NOW()))::bigint AS remaining \
             FROM {} WHERE aor = $1 AND expires_at > NOW()",
            table
        );
        let rows = client
            .query(&query, &[&aor])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mut contacts = Vec::with_capacity(rows.len());
        for row in rows {
            let data: &str = row.get(0);
            let remaining: i64 = row.get(1);
            let mut contact: StoredContact = serde_json::from_str(data)
                .map_err(|error| BackendError::Serialization(error.to_string()))?;
            // Overwrite with the actual remaining TTL from the database.
            let remaining = remaining.max(0) as u64;
            contact.expires_secs = remaining;
            contact.expires_at = Some(now_epoch + remaining);
            contacts.push(contact);
        }
        Ok(contacts)
    }

    async fn remove(&self, aor: &str) -> Result<(), BackendError> {
        let client = self.client_for(aor);
        let table = &self.config.table;

        let query = format!("DELETE FROM {} WHERE aor = $1", table);
        client
            .execute(&query, &[&aor])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(())
    }

    async fn exists(&self, aor: &str) -> Result<bool, BackendError> {
        let client = self.client_for(aor);
        let table = &self.config.table;

        let query = format!(
            "SELECT EXISTS(SELECT 1 FROM {} WHERE aor = $1 AND expires_at > NOW())",
            table
        );
        let row = client
            .query_one(&query, &[&aor])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        let result: bool = row.get(0);
        Ok(result)
    }

    async fn all_aors(&self) -> Result<Vec<String>, BackendError> {
        let mut all_aors = Vec::new();

        for client in &self.clients {
            let query = format!(
                "SELECT DISTINCT aor FROM {} WHERE expires_at > NOW()",
                self.config.table
            );
            let rows = client
                .query(&query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;

            for row in rows {
                let aor: String = row.get(0);
                all_aors.push(aor);
            }
        }

        Ok(all_aors)
    }

    async fn save_aor_state(&self, aor: &str, state: &StoredAorState) -> Result<(), BackendError> {
        let client = self.client_for(aor);
        let table = self.state_table();

        if state.is_empty() {
            let query = format!("DELETE FROM {table} WHERE aor = $1");
            client
                .execute(&query, &[&aor])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            return Ok(());
        }

        let json = serde_json::to_string(state)
            .map_err(|error| BackendError::Serialization(error.to_string()))?;
        let query = format!(
            "INSERT INTO {table} (aor, state, updated_at) VALUES ($1, $2, NOW())
             ON CONFLICT (aor) DO UPDATE SET state = $2, updated_at = NOW()"
        );
        client
            .execute(&query, &[&aor, &json])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(())
    }

    async fn load_aor_state(&self, aor: &str) -> Result<Option<StoredAorState>, BackendError> {
        let client = self.client_for(aor);
        let table = self.state_table();
        let query = format!("SELECT state FROM {table} WHERE aor = $1");
        let rows = client
            .query(&query, &[&aor])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;

        match rows.first() {
            Some(row) => {
                let json: &str = row.get(0);
                let state: StoredAorState = serde_json::from_str(json)
                    .map_err(|error| BackendError::Serialization(error.to_string()))?;
                Ok(Some(state))
            }
            None => Ok(None),
        }
    }

    async fn remove_aor_state(&self, aor: &str) -> Result<(), BackendError> {
        let client = self.client_for(aor);
        let table = self.state_table();
        let query = format!("DELETE FROM {table} WHERE aor = $1");
        client
            .execute(&query, &[&aor])
            .await
            .map_err(|error| BackendError::Query(error.to_string()))?;
        Ok(())
    }

    async fn count_aors(&self) -> Result<usize, BackendError> {
        let mut total = 0usize;
        for client in &self.clients {
            let query = format!(
                "SELECT COUNT(DISTINCT aor) FROM {} WHERE expires_at > NOW()",
                self.config.table
            );
            let row = client
                .query_one(&query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            let count: i64 = row.get(0);
            total += count.max(0) as usize;
        }
        Ok(total)
    }

    async fn purge_expired(&self) -> Result<usize, BackendError> {
        let slack = self.expired_row_grace_secs as f64;
        let without_binding = self
            .max_binding_lifetime_secs
            .saturating_add(self.expired_row_grace_secs) as f64;
        let table = &self.config.table;
        let state_table = self.state_table();
        let contacts =
            format!("DELETE FROM {table} WHERE expires_at <= NOW() - $1 * INTERVAL '1 second'");
        let orphaned_state = format!(
            "DELETE FROM {state_table} AS state
             WHERE state.updated_at <= NOW() - $1 * INTERVAL '1 second'
               AND NOT EXISTS (
                   SELECT 1 FROM {table} AS binding
                   WHERE binding.aor = state.aor AND binding.expires_at > NOW()
               )"
        );
        let mut purged = 0u64;
        for client in &self.clients {
            purged += client
                .execute(&contacts, &[&slack])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            purged += client
                .execute(&orphaned_state, &[&without_binding])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
        }
        Ok(purged as usize)
    }

    async fn all_aor_state_aors(&self) -> Result<Vec<String>, BackendError> {
        let table = self.state_table();
        let mut aors = Vec::new();

        for client in &self.clients {
            let query = format!("SELECT aor FROM {table}");
            let rows = client
                .query(&query, &[])
                .await
                .map_err(|error| BackendError::Query(error.to_string()))?;
            for row in rows {
                aors.push(row.get::<_, String>(0));
            }
        }

        Ok(aors)
    }
}

#[cfg(test)]
#[path = "postgres_store_tests.rs"]
mod tests;
