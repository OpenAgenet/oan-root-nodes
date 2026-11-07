// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use oan_service_security::{NonceStore, SecurityError};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous},
    Executor, SqlitePool,
};
use std::{path::Path, time::Duration};


const LEGACY_IMPORT_MARKER: &str = "legacy_json_imported_v1";

#[derive(Clone)]
pub struct RootRequestNonceStore {
    pool: SqlitePool,
}

#[derive(Clone)]
pub enum RootRequestNonceBackend {
    Sqlite(RootRequestNonceStore),
}

impl RootRequestNonceStore {
    pub async fn connect_and_migrate(
        legacy_path: &Path,
        ttl_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<Self> {
        if ttl_seconds < 0 {
            anyhow::bail!("nonce TTL must not be negative");
        }
        let database_path = legacy_path.with_extension("sqlite3");
        if let Some(parent) = database_path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create nonce database directory {}",
                    parent.display()
                )
            })?;
        }
        let options = SqliteConnectOptions::new()
            .filename(&database_path)
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .busy_timeout(Duration::from_secs(5));
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(5))
            .connect_with(options)
            .await
            .with_context(|| {
                format!("failed to open nonce database {}", database_path.display())
            })?;
        let store = Self { pool };
        store.initialize().await?;
        store
            .migrate_legacy_json(legacy_path, ttl_seconds, now)
            .await?;
        Ok(store)
    }

    async fn initialize(&self) -> Result<()> {
        self.pool
            .execute(
                r#"
                CREATE TABLE IF NOT EXISTS request_nonces (
                    scope TEXT NOT NULL,
                    nonce TEXT NOT NULL,
                    request_timestamp_us INTEGER NOT NULL,
                    expires_at_us INTEGER NOT NULL,
                    PRIMARY KEY (scope, nonce)
                );
                CREATE INDEX IF NOT EXISTS idx_request_nonces_expiry
                    ON request_nonces(scope, expires_at_us);
                CREATE TABLE IF NOT EXISTS request_nonce_metadata (
                    key TEXT NOT NULL PRIMARY KEY,
                    value TEXT NOT NULL
                );
                "#,
            )
            .await
            .context("failed to initialize nonce database")?;
        Ok(())
    }

    async fn migrate_legacy_json(
        &self,
        legacy_path: &Path,
        ttl_seconds: i64,
        now: DateTime<Utc>,
    ) -> Result<()> {
        let mut transaction = self
            .pool
            .begin()
            .await
            .context("failed to begin nonce migration")?;
        let already_imported = sqlx::query_scalar::<_, String>(
            "SELECT value FROM request_nonce_metadata WHERE key = ?",
        )
        .bind(LEGACY_IMPORT_MARKER)
        .fetch_optional(&mut *transaction)
        .await
        .context("failed to read nonce migration marker")?
        .is_some();
        if already_imported {
            transaction
                .commit()
                .await
                .context("failed to finish nonce migration check")?;
            return Ok(());
        }

        if legacy_path.exists() {
            let bytes = std::fs::read(legacy_path).with_context(|| {
                format!(
                    "failed to read legacy nonce store {}",
                    legacy_path.display()
                )
            })?;
            let legacy: NonceStore = serde_json::from_slice(&bytes).with_context(|| {
                format!(
                    "failed to parse legacy nonce store {}",
                    legacy_path.display()
                )
            })?;
            let cutoff_seconds = ttl_seconds.checked_neg().context("nonce TTL overflow")?;
            let cutoff_us = checked_expiry_us(now, cutoff_seconds)?;
            for (nonce, request_timestamp) in legacy.nonces {
                let request_timestamp_us = request_timestamp.timestamp_micros();
                if request_timestamp_us < cutoff_us {
                    continue;
                }
                let expires_at_us = checked_expiry_us(request_timestamp, ttl_seconds)?;
                sqlx::query(
                    r#"
                    INSERT INTO request_nonces(
                        scope, nonce, request_timestamp_us, expires_at_us
                    ) VALUES (?, ?, ?, ?)
                    ON CONFLICT(scope, nonce) DO UPDATE SET
                        request_timestamp_us = excluded.request_timestamp_us,
                        expires_at_us = excluded.expires_at_us
                    WHERE request_nonces.expires_at_us < excluded.expires_at_us
                    "#,
                )
                .bind(RootRequestNonceBackend::TRUSTED_UPSTREAM_SCOPE)
                .bind(nonce)
                .bind(request_timestamp_us)
                .bind(expires_at_us)
                .execute(&mut *transaction)
                .await
                .context("failed to import legacy nonce")?;
            }
        }
        sqlx::query(
            "INSERT INTO request_nonce_metadata(key, value) VALUES (?, ?) \
             ON CONFLICT(key) DO NOTHING",
        )
        .bind(LEGACY_IMPORT_MARKER)
        .bind(now.to_rfc3339())
        .execute(&mut *transaction)
        .await
        .context("failed to write nonce migration marker")?;
        transaction
            .commit()
            .await
            .context("failed to commit nonce migration")?;
        Ok(())
    }

    pub async fn claim(
        &self,
        scope: &str,
        nonce: &str,
        request_timestamp: DateTime<Utc>,
        now: DateTime<Utc>,
        ttl_seconds: i64,
    ) -> std::result::Result<(), SecurityError> {
        let request_timestamp_us = request_timestamp.timestamp_micros();
        let expires_at_us = checked_expiry_us(request_timestamp, ttl_seconds)
            .map_err(|_| SecurityError::code("invalid_nonce_store"))?;
        let result = sqlx::query(
            r#"
            INSERT INTO request_nonces(scope, nonce, request_timestamp_us, expires_at_us)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(scope, nonce) DO UPDATE SET
                request_timestamp_us = excluded.request_timestamp_us,
                expires_at_us = excluded.expires_at_us
            WHERE request_nonces.expires_at_us < ?
            "#,
        )
        .bind(scope)
        .bind(nonce)
        .bind(request_timestamp_us)
        .bind(expires_at_us)
        .bind(now.timestamp_micros())
        .execute(&self.pool)
        .await
        .map_err(|_| SecurityError::code("invalid_nonce_store"))?;
        if result.rows_affected() == 0 {
            return Err(SecurityError::code("trusted_upstream_nonce_replayed"));
        }
        Ok(())
    }

    pub async fn cleanup_expired(&self, now: DateTime<Utc>, limit: i64) -> Result<u64> {
        let result = sqlx::query(
            r#"
            DELETE FROM request_nonces
            WHERE rowid IN (
                SELECT rowid FROM request_nonces
                WHERE expires_at_us < ?
                ORDER BY expires_at_us
                LIMIT ?
            )
            "#,
        )
        .bind(now.timestamp_micros())
        .bind(limit.max(0))
        .execute(&self.pool)
        .await
        .context("failed to clean expired request nonces")?;
        Ok(result.rows_affected())
    }

}

impl RootRequestNonceBackend {
    pub const TRUSTED_UPSTREAM_SCOPE: &'static str = "root-trusted-upstream";

    pub async fn claim(
        &self,
        nonce: &str,
        request_timestamp: DateTime<Utc>,
        now: DateTime<Utc>,
        ttl_seconds: i64,
    ) -> std::result::Result<(), SecurityError> {
        match self {
            Self::Sqlite(store) => {
                store
                    .claim(
                        Self::TRUSTED_UPSTREAM_SCOPE,
                        nonce,
                        request_timestamp,
                        now,
                        ttl_seconds,
                    )
                    .await
            }
        }
    }

    pub async fn cleanup_expired(&self, now: DateTime<Utc>, limit: i64) -> Result<u64> {
        match self {
            Self::Sqlite(store) => store.cleanup_expired(now, limit).await,
        }
    }
}

fn checked_expiry_us(timestamp: DateTime<Utc>, seconds: i64) -> Result<i64> {
    let delta = seconds
        .checked_mul(1_000_000)
        .context("nonce TTL overflow")?;
    timestamp
        .timestamp_micros()
        .checked_add(delta)
        .context("nonce expiry overflow")
}

