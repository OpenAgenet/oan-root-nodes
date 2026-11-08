// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use super::runtime_config::RuntimeConfig;
use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Config {
    #[serde(default)]
    pub runtime: RuntimeConfig,
    #[serde(default)]
    pub database: oan_config::DatabaseConfig,
    pub server: ServerConfig,
    #[serde(default)]
    pub cors: CorsConfig,
    #[serde(default)]
    pub debug: DebugConfig,
    #[serde(default)]
    pub events: EventStreamConfig,
    #[serde(default)]
    pub security: SecurityConfig,
    pub paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ServerConfig {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub endpoint: Option<String>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CorsConfig {
    #[serde(default)]
    pub allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DebugConfig {
    #[serde(default)]
    pub export_snapshots: bool,
    #[serde(default = "default_debug_export_interval_ms")]
    pub export_interval_ms: u64,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            export_snapshots: false,
            export_interval_ms: default_debug_export_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct EventStreamConfig {
    #[serde(default = "default_event_enabled")]
    pub enabled: bool,
    #[serde(default = "default_event_backend")]
    pub backend: String,
    #[serde(default = "default_event_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_event_stream")]
    pub stream: String,
    #[serde(default = "default_cdn_publish_subject")]
    pub cdn_publish_subject: String,
    #[serde(default = "default_event_publish_timeout_ms")]
    pub publish_timeout_ms: u64,
    #[serde(default = "default_event_failure_mode")]
    pub failure_mode: String,
}

impl Default for EventStreamConfig {
    fn default() -> Self {
        Self {
            enabled: default_event_enabled(),
            backend: default_event_backend(),
            endpoint: default_event_endpoint(),
            stream: default_event_stream(),
            cdn_publish_subject: default_cdn_publish_subject(),
            publish_timeout_ms: default_event_publish_timeout_ms(),
            failure_mode: default_event_failure_mode(),
        }
    }
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct SecurityConfig {
    #[serde(default)]
    pub admin: AdminSecurityConfig,
    #[serde(default)]
    pub trusted_upstream: TrustedUpstreamSecurityConfig,
    #[serde(default)]
    pub workers: WorkerSecurityConfig,
    #[serde(default)]
    pub trust_indexer: TrustIndexerConfig,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AdminSecurityConfig {
    #[serde(default = "default_admin_mode")]
    pub mode: String,
    #[serde(default)]
    pub static_tokens: Vec<String>,
    #[serde(default)]
    pub trusted_admin_dids: Vec<String>,
    #[serde(default = "default_clock_skew_seconds")]
    pub max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    pub nonce_ttl_seconds: i64,
    #[serde(default = "default_admin_nonce_file")]
    pub nonce_store_file: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustedUpstreamSecurityConfig {
    #[serde(default = "default_clock_skew_seconds")]
    pub max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    pub nonce_ttl_seconds: i64,
}

impl Default for TrustedUpstreamSecurityConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_clock_skew_seconds(),
            nonce_ttl_seconds: default_nonce_ttl_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct TrustIndexerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default = "default_trust_indexer_fail_mode")]
    pub fail_mode: String,
    #[serde(default = "default_trust_indexer_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_trust_indexer_poll_interval_ms")]
    pub poll_interval_ms: u64,
}

impl Default for TrustIndexerConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            endpoint: Some("http://127.0.0.1:8088".to_owned()),
            fail_mode: default_trust_indexer_fail_mode(),
            timeout_ms: default_trust_indexer_timeout_ms(),
            poll_interval_ms: default_trust_indexer_poll_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct WorkerSecurityConfig {
    #[serde(default = "default_worker_enabled")]
    pub enabled: bool,
    #[serde(default = "default_cdn_worker_interval_ms")]
    pub cdn_interval_ms: u64,
    #[serde(default = "default_discovery_worker_interval_ms")]
    pub discovery_interval_ms: u64,
    #[serde(default = "default_cdn_worker_batch_size")]
    pub cdn_batch_size: usize,
    #[serde(default = "default_discovery_worker_batch_size")]
    pub discovery_batch_size: usize,
    #[serde(default = "default_cdn_worker_concurrency")]
    pub cdn_concurrency: usize,
    #[serde(default = "default_discovery_worker_concurrency")]
    pub discovery_concurrency: usize,
    #[serde(default = "default_root_admission_concurrency")]
    pub admission_concurrency: usize,
    #[serde(default = "default_worker_lease_seconds")]
    pub lease_seconds: i64,
    #[serde(default = "default_worker_retry_backoff_seconds")]
    pub retry_backoff_seconds: i64,
    #[serde(default = "default_worker_http_timeout_seconds")]
    pub http_timeout_seconds: u64,
}

impl Default for WorkerSecurityConfig {
    fn default() -> Self {
        Self {
            enabled: default_worker_enabled(),
            cdn_interval_ms: default_cdn_worker_interval_ms(),
            discovery_interval_ms: default_discovery_worker_interval_ms(),
            cdn_batch_size: default_cdn_worker_batch_size(),
            discovery_batch_size: default_discovery_worker_batch_size(),
            cdn_concurrency: default_cdn_worker_concurrency(),
            discovery_concurrency: default_discovery_worker_concurrency(),
            admission_concurrency: default_root_admission_concurrency(),
            lease_seconds: default_worker_lease_seconds(),
            retry_backoff_seconds: default_worker_retry_backoff_seconds(),
            http_timeout_seconds: default_worker_http_timeout_seconds(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PathConfig {
    pub data_dir: PathBuf,
    #[serde(default = "default_identity_file")]
    pub identity_file: PathBuf,
    pub bulletin_file: PathBuf,
    #[serde(default = "default_authorization_state_file")]
    pub authorization_state_file: PathBuf,
    #[serde(default = "default_request_nonce_file")]
    pub request_nonce_file: PathBuf,
    #[serde(default = "default_controller_authorization_nonce_file")]
    pub controller_authorization_nonce_file: PathBuf,
    #[serde(default = "default_capability_tree_file")]
    pub capability_tree_file: PathBuf,
    #[serde(default)]
    pub database_url: Option<String>,
}

pub(super) fn default_identity_file() -> PathBuf {
    PathBuf::from("../../data/root/identity.json")
}

pub(super) fn default_authorization_state_file() -> PathBuf {
    PathBuf::from("../../data/root/authorization-state.json")
}

pub(super) fn default_request_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/request-nonces.json")
}

pub(super) fn default_controller_authorization_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/controller-authorization-nonces.json")
}

pub(super) fn default_admin_nonce_file() -> PathBuf {
    PathBuf::from("../../data/root/admin-request-nonces.json")
}

pub(super) fn default_capability_tree_file() -> PathBuf {
    PathBuf::from("../../docs/capability-tree-v1.json")
}

pub(super) fn default_admin_mode() -> String {
    "static-token".to_owned()
}

pub(super) fn default_event_backend() -> String {
    "nats-jetstream".to_owned()
}

pub(super) fn default_event_endpoint() -> String {
    "nats://127.0.0.1:4222".to_owned()
}

pub(super) fn default_event_stream() -> String {
    "OAN_RESOURCE_PUBLICATION".to_owned()
}

pub(super) fn default_cdn_publish_subject() -> String {
    "oan.resource.cdn.publish.requested".to_owned()
}

pub(super) fn default_event_enabled() -> bool {
    true
}

pub(super) fn default_event_publish_timeout_ms() -> u64 {
    1_000
}

pub(super) fn default_event_failure_mode() -> String {
    "fallback".to_owned()
}

pub(super) fn default_worker_enabled() -> bool {
    true
}

pub(super) fn default_cdn_worker_interval_ms() -> u64 {
    1_000
}

pub(super) fn default_discovery_worker_interval_ms() -> u64 {
    1_500
}

pub(super) fn default_cdn_worker_batch_size() -> usize {
    200
}

pub(super) fn default_discovery_worker_batch_size() -> usize {
    100
}

pub(super) fn default_cdn_worker_concurrency() -> usize {
    16
}

pub(super) fn default_discovery_worker_concurrency() -> usize {
    8
}

pub(super) fn default_root_admission_concurrency() -> usize {
    64
}

pub(super) fn default_worker_lease_seconds() -> i64 {
    60
}

pub(super) fn default_worker_retry_backoff_seconds() -> i64 {
    15
}

pub(super) fn default_worker_http_timeout_seconds() -> u64 {
    10
}

pub(super) fn default_debug_export_interval_ms() -> u64 {
    super::ROOT_DEBUG_EXPORT_INTERVAL_MS
}

pub(super) fn default_trust_indexer_fail_mode() -> String {
    "closed".to_owned()
}

pub(super) fn default_trust_indexer_timeout_ms() -> u64 {
    500
}

pub(super) fn default_trust_indexer_poll_interval_ms() -> u64 {
    3_000
}

pub(super) fn default_clock_skew_seconds() -> i64 {
    300
}

pub(super) fn default_nonce_ttl_seconds() -> i64 {
    300
}

pub(super) fn load_config_details(
    path: String,
) -> Result<(Config, std::collections::BTreeMap<String, String>)> {
    let path = oan_config::absolute(Path::new(&path))?;
    let loaded =
        oan_config::load::<Config>(&path, PREFIX, FIELDS, &oan_config::environment(), true)?;
    let mut config = loaded.value;
    for warning in &loaded.warnings {
        eprintln!("{warning}");
    }
    config.runtime.validate()?;
    super::validate_event_failure_mode(&config.events.failure_mode)
        .map_err(|_| anyhow!("unsupported_event_failure_mode (value hidden)"))?;
    if config.events.backend != "nats-jetstream" {
        return Err(anyhow!("unsupported_event_backend (value hidden)"));
    }
    if config.server.host.trim().is_empty() {
        return Err(anyhow::anyhow!("server.host is required"));
    }
    if let Some(url) = config
        .paths
        .database_url
        .as_deref()
        .filter(|u| !u.is_empty())
    {
        oan_storage::DatabaseConfig::parse(url)
            .map_err(|_| anyhow::anyhow!("invalid paths.database_url (value hidden)"))?;
    }
    config
        .database
        .pool
        .resolve(config.paths.database_url.as_deref())?;
    validate_paths(&serde_json::to_value(&config)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    config.paths.identity_file = resolve_relative(base, &config.paths.identity_file);
    config.paths.bulletin_file = resolve_relative(base, &config.paths.bulletin_file);
    config.paths.authorization_state_file =
        resolve_relative(base, &config.paths.authorization_state_file);
    config.paths.request_nonce_file = resolve_relative(base, &config.paths.request_nonce_file);
    config.paths.controller_authorization_nonce_file =
        resolve_relative(base, &config.paths.controller_authorization_nonce_file);
    config.security.admin.nonce_store_file =
        resolve_relative(base, &config.security.admin.nonce_store_file);
    if !config.paths.capability_tree_file.as_os_str().is_empty() {
        config.paths.capability_tree_file =
            resolve_relative(base, &config.paths.capability_tree_file);
    }
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    if !config.events.enabled {
        return Err(anyhow!(
            "root_cdn_event_stream_required: Root-to-CDN publication no longer supports the legacy Root DB worker path; set [events].enabled=true"
        ));
    }
    Ok((config, loaded.sources))
}

pub(super) fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        oan_config::absolute(path).expect("absolute path normalization")
    } else {
        // base is made absolute during configuration loading.
        oan_config::absolute(&base.join(path)).expect("configuration directory resolved")
    }
}

pub(super) fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

const PREFIX: &str = "OAN_ROOT";
const FIELDS: &[oan_config::Field] = &[
    oan_config::Field {
        path: "server.host",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "server.port",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "server.endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "cors.allowed_origins",
        kind: oan_config::Kind::List,
    },
    oan_config::Field {
        path: "debug.export_snapshots",
        kind: oan_config::Kind::Bool,
    },
    oan_config::Field {
        path: "debug.export_interval_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "events.enabled",
        kind: oan_config::Kind::Bool,
    },
    oan_config::Field {
        path: "events.backend",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "events.endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "events.stream",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "events.cdn_publish_subject",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "events.publish_timeout_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "events.failure_mode",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "security.admin.mode",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "security.admin.static_tokens",
        kind: oan_config::Kind::List,
    },
    oan_config::Field {
        path: "security.admin.trusted_admin_dids",
        kind: oan_config::Kind::List,
    },
    oan_config::Field {
        path: "security.admin.max_clock_skew_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.admin.nonce_ttl_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.admin.nonce_store_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "security.trusted_upstream.max_clock_skew_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.trusted_upstream.nonce_ttl_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.workers.enabled",
        kind: oan_config::Kind::Bool,
    },
    oan_config::Field {
        path: "security.workers.cdn_interval_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.discovery_interval_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.cdn_batch_size",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.discovery_batch_size",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.cdn_concurrency",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.discovery_concurrency",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.admission_concurrency",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.workers.lease_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.workers.retry_backoff_seconds",
        kind: oan_config::Kind::I64,
    },
    oan_config::Field {
        path: "security.workers.http_timeout_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.trust_indexer.enabled",
        kind: oan_config::Kind::Bool,
    },
    oan_config::Field {
        path: "security.trust_indexer.endpoint",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "security.trust_indexer.fail_mode",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "security.trust_indexer.timeout_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "security.trust_indexer.poll_interval_ms",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "paths.data_dir",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.identity_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.bulletin_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.authorization_state_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.request_nonce_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.controller_authorization_nonce_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.capability_tree_file",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "paths.database_url",
        kind: oan_config::Kind::String,
    },
    oan_config::Field {
        path: "runtime.tokio.worker_threads",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.tokio.thread_stack_size_mib",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.tokio.max_blocking_threads",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.worker_count",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.queue_capacity",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "runtime.did_verification.worker_stack_size_mib",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.max_connections",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.acquire_timeout_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.idle_timeout_seconds",
        kind: oan_config::Kind::U64,
    },
    oan_config::Field {
        path: "database.pool.max_lifetime_seconds",
        kind: oan_config::Kind::U64,
    },
];

fn validate_paths(config: &serde_json::Value) -> Result<()> {
    if config
        .pointer("/paths/data_dir")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.data_dir must not be empty"));
    }
    if config
        .pointer("/paths/identity_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.identity_file must not be empty"));
    }
    if config
        .pointer("/paths/bulletin_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!("paths.bulletin_file must not be empty"));
    }
    if config
        .pointer("/paths/authorization_state_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "paths.authorization_state_file must not be empty"
        ));
    }
    if config
        .pointer("/paths/request_nonce_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "paths.request_nonce_file must not be empty"
        ));
    }
    if config
        .pointer("/paths/controller_authorization_nonce_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "paths.controller_authorization_nonce_file must not be empty"
        ));
    }
    if config
        .pointer("/security/admin/nonce_store_file")
        .and_then(serde_json::Value::as_str)
        .is_some_and(str::is_empty)
    {
        return Err(anyhow::anyhow!(
            "security.admin.nonce_store_file must not be empty"
        ));
    }
    Ok(())
}

