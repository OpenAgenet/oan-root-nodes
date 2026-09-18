// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::Result;
use axum::{
    extract::DefaultBodyLimit,
    extract::{Path as AxumPath, Query, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use oan_core::DidDocument;
use oan_package::ResourcePackage;
use oan_protocol::{
    ResourceCdnBatchPublishRequest, ResourceCdnIndexItem, ResourceCdnIndexResponse,
    ResourceCdnPublishBatchItem, ResourceCdnPublishRequest, OAN_RESOURCE_PROTOCOL_VERSION,
    PATH_CDN_RESOURCES, PATH_CDN_RESOURCES_BATCH, PURPOSE_CDN_PUBLISH,
};
use oan_service_security::{
    bearer_token_from_header, verify_admin_token, verify_signed_request_envelope, AdminAuthConfig,
    AdminAuthMode, AdminPrincipal, TrustedUpstreamPolicy,
};
use oan_storage::{
    did_to_file_name, DatabaseBackend, DatabaseConfig, JsonStore, PostgresJsonStore,
    SqliteJsonStore,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sqlx::{Postgres, QueryBuilder, Row, Sqlite};
use std::{
    collections::BTreeMap,
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
};
use tokio::time::{sleep, Duration as TokioDuration};
use tower_http::cors::{AllowHeaders, AllowOrigin, CorsLayer};

const CDN_PUBLISH_HISTORY_TABLE: &str = "cdn_publish_history";
const CDN_ROOT_META_TABLE: &str = "cdn_root_meta";
const CDN_RESOURCE_PACKAGE_TABLE: &str = "cdn_resource_packages";
const MAX_BATCH_PUBLISH_BODY_BYTES: usize = 32 * 1024 * 1024;

#[derive(Clone, Debug, Deserialize)]
struct ResourceIndexQuery {
    #[serde(rename = "afterCursor", default)]
    after_cursor: Option<i64>,
    #[serde(default)]
    limit: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct PublishHistoryQuery {
    #[serde(rename = "afterKey", default)]
    after_key: Option<String>,
    #[serde(default)]
    limit: Option<u32>,
}

const CDN_DEFAULT_PAGE_SIZE: i64 = 100;
const CDN_MAX_PAGE_SIZE: i64 = 500;

#[derive(Clone, Debug, Deserialize)]
struct ResourceBatchGetRequest {
    #[serde(rename = "resourceDids")]
    resource_dids: Vec<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    #[serde(default)]
    cors: CorsConfig,
    #[serde(default)]
    security: SecurityConfig,
    #[serde(default)]
    debug: DebugConfig,
    paths: PathConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct CorsConfig {
    #[serde(default)]
    allowed_origins: Vec<String>,
}

#[derive(Clone, Debug, Default, Deserialize)]
struct SecurityConfig {
    #[serde(default)]
    admin: AdminSecurityConfig,
    #[serde(default)]
    trusted_upstream: TrustedUpstreamSecurityConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct DebugConfig {
    #[serde(default)]
    export_snapshots: bool,
    #[serde(default = "default_debug_export_interval_ms")]
    export_interval_ms: u64,
}

impl Default for DebugConfig {
    fn default() -> Self {
        Self {
            export_snapshots: false,
            export_interval_ms: default_debug_export_interval_ms(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct AdminSecurityConfig {
    #[serde(default = "default_admin_mode")]
    mode: String,
    #[serde(default)]
    static_tokens: Vec<String>,
}

impl Default for AdminSecurityConfig {
    fn default() -> Self {
        Self {
            mode: default_admin_mode(),
            static_tokens: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct TrustedUpstreamSecurityConfig {
    #[serde(default = "default_clock_skew_seconds")]
    max_clock_skew_seconds: i64,
    #[serde(default = "default_nonce_ttl_seconds")]
    nonce_ttl_seconds: i64,
    #[serde(default = "default_root_did")]
    root_did: String,
    #[serde(default = "default_root_did_document_file")]
    root_did_document_file: PathBuf,
    #[serde(default = "default_nonce_store_file")]
    nonce_store_file: PathBuf,
}

impl Default for TrustedUpstreamSecurityConfig {
    fn default() -> Self {
        Self {
            max_clock_skew_seconds: default_clock_skew_seconds(),
            nonce_ttl_seconds: default_nonce_ttl_seconds(),
            root_did: default_root_did(),
            root_did_document_file: default_root_did_document_file(),
            nonce_store_file: default_nonce_store_file(),
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
struct PathConfig {
    data_dir: PathBuf,
    #[serde(default)]
    database_url: Option<String>,
}

fn default_admin_mode() -> String {
    "static-token".to_owned()
}

fn default_clock_skew_seconds() -> i64 {
    300
}

fn default_nonce_ttl_seconds() -> i64 {
    300
}

fn default_root_did() -> String {
    "did:oan:INRT:7YpQm9Kx2VnRb6Ts3WfHa4Cd5Ej8LgNz".to_owned()
}

fn default_root_did_document_file() -> PathBuf {
    PathBuf::from("../../data/root/did-document.json")
}

fn default_nonce_store_file() -> PathBuf {
    PathBuf::from("../../data/cdn/request-nonces.json")
}

fn default_debug_export_interval_ms() -> u64 {
    2_000
}

#[derive(Clone)]
struct AppState {
    data: JsonStore,
    config: Config,
    sqlite: Option<SqliteJsonStore>,
    postgres: Option<PostgresJsonStore>,
}

#[derive(Debug, Serialize)]
struct ErrorBody {
    error: String,
}

#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn bad_request(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: message.into(),
        }
    }

    fn not_found(message: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: message.into(),
        }
    }

    fn internal(error: anyhow::Error) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: error.to_string(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (
            self.status,
            Json(ErrorBody {
                error: self.message,
            }),
        )
            .into_response()
    }
}

type ApiResult<T> = std::result::Result<Json<T>, ApiError>;

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/cdn-node/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let (sqlite, postgres) = match config.paths.database_url.as_deref() {
        Some(url) if !url.is_empty() => {
            let database = DatabaseConfig::parse(url)?;
            match database.backend() {
                DatabaseBackend::Sqlite => {
                    let sqlite = SqliteJsonStore::connect(url).await?;
                    initialize_cdn_sqlite(&sqlite).await?;
                    (Some(sqlite), None)
                }
                DatabaseBackend::Postgres => {
                    let postgres = PostgresJsonStore::connect(url).await?;
                    initialize_cdn_postgres(&postgres).await?;
                    (None, Some(postgres))
                }
            }
        }
        _ => (None, None),
    };
    let state = AppState {
        data: JsonStore::new(&config.paths.data_dir),
        config: config.clone(),
        sqlite,
        postgres,
    };
    let public_routes = Router::new()
        .route("/health", get(health))
        .route("/cdn/resources/{did}", get(get_resource_package))
        .route(
            "/cdn/resources/batch-get",
            post(api_get_resource_packages_batch),
        )
        .route("/cdn/resources/index", get(api_resource_index))
        .route("/cdn/documents/{did}", get(get_document))
        .route("/cdn/metadata/{did}", get(get_metadata))
        .route("/cdn/status", get(api_status))
        .route("/cdn/catalog/resources", get(api_resources_catalog))
        .route(
            "/cdn/catalog/resources/{did}",
            get(api_resource_catalog_detail),
        )
        .route("/cdn/catalog/documents/{did}", get(api_document_detail))
        .route("/cdn/catalog/metadata/{did}", get(api_metadata_detail))
        .route(
            "/cdn/catalog/resources/stats",
            get(api_resource_catalog_stats),
        )
        .route("/cdn/catalog/publish/history", get(api_publish_history))
        .layer(build_cors_layer(&config.cors)?);

    let admin_routes = Router::new()
        .route("/cdn/resources", post(publish_resource))
        .route("/cdn/resources/batch", post(publish_resources_batch))
        .route("/cdn/purge", post(api_purge));

    let app = Router::new()
        .merge(public_routes)
        .merge(admin_routes)
        .layer(DefaultBodyLimit::max(MAX_BATCH_PUBLISH_BODY_BYTES))
        .with_state(state.clone());

    if (state.sqlite.is_some() || state.postgres.is_some()) && state.config.debug.export_snapshots {
        tokio::spawn(async move {
            cdn_debug_export_loop(state).await;
        });
    }

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    println!("cdn-service listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: String) -> Result<Config> {
    let path = PathBuf::from(path);
    let mut config: Config = toml::from_str(&std::fs::read_to_string(&path)?)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.paths.data_dir = resolve_relative(base, &config.paths.data_dir);
    if let Some(database_url) = config.paths.database_url.as_mut() {
        *database_url = resolve_database_url(base, database_url);
    }
    config.security.trusted_upstream.nonce_store_file =
        resolve_relative(base, &config.security.trusted_upstream.nonce_store_file);
    config.security.trusted_upstream.root_did_document_file = resolve_relative(
        base,
        &config.security.trusted_upstream.root_did_document_file,
    );
    Ok(config)
}

fn resolve_database_url(base: &Path, url: &str) -> String {
    let Some(raw_path) = url
        .strip_prefix("sqlite://")
        .or_else(|| url.strip_prefix("sqlite:"))
    else {
        return url.to_owned();
    };
    let resolved = resolve_relative(base, Path::new(raw_path));
    format!("sqlite:{}", resolved.display())
}

async fn initialize_cdn_sqlite(sqlite: &SqliteJsonStore) -> Result<()> {
    sqlite
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {CDN_PUBLISH_HISTORY_TABLE} (
                history_key TEXT PRIMARY KEY,
                item_json TEXT NOT NULL,
                published_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_ROOT_META_TABLE} (
                meta_key TEXT PRIMARY KEY,
                meta_value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_RESOURCE_PACKAGE_TABLE} (
                resource_did TEXT PRIMARY KEY,
                publication_cursor INTEGER NOT NULL DEFAULT 0,
                resource_type TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_json TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            "#
        ))
        .await?;
    let columns = sqlx::query(&format!("PRAGMA table_info({CDN_RESOURCE_PACKAGE_TABLE})"))
        .fetch_all(sqlite.pool())
        .await?;
    let has_publication_cursor = columns.iter().any(|row| {
        row.try_get::<String, _>("name")
            .map(|name| name == "publication_cursor")
            .unwrap_or(false)
    });
    if !has_publication_cursor {
        sqlx::query(&format!(
            "ALTER TABLE {CDN_RESOURCE_PACKAGE_TABLE} ADD COLUMN publication_cursor INTEGER NOT NULL DEFAULT 0"
        ))
        .execute(sqlite.pool())
        .await?;
    }
    sqlite
        .execute_batch(&format!(
            "CREATE INDEX IF NOT EXISTS idx_cdn_resource_packages_cursor ON {CDN_RESOURCE_PACKAGE_TABLE}(publication_cursor, resource_did);"
        ))
        .await?;
    Ok(())
}

async fn initialize_cdn_postgres(postgres: &PostgresJsonStore) -> Result<()> {
    postgres
        .execute_batch(&format!(
            r#"
            CREATE TABLE IF NOT EXISTS {CDN_PUBLISH_HISTORY_TABLE} (
                history_key TEXT PRIMARY KEY,
                item_json JSONB NOT NULL,
                published_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_ROOT_META_TABLE} (
                meta_key TEXT PRIMARY KEY,
                meta_value TEXT NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            CREATE TABLE IF NOT EXISTS {CDN_RESOURCE_PACKAGE_TABLE} (
                resource_did TEXT PRIMARY KEY,
                publication_cursor BIGINT NOT NULL DEFAULT 0,
                resource_type TEXT NOT NULL,
                package_version TEXT NOT NULL,
                package_json JSONB NOT NULL,
                updated_at TIMESTAMPTZ NOT NULL
            );
            ALTER TABLE {CDN_RESOURCE_PACKAGE_TABLE}
                ADD COLUMN IF NOT EXISTS publication_cursor BIGINT NOT NULL DEFAULT 0;
            CREATE INDEX IF NOT EXISTS idx_cdn_publish_history_published
            ON {CDN_PUBLISH_HISTORY_TABLE}(published_at, history_key);
            CREATE INDEX IF NOT EXISTS idx_cdn_resource_packages_type_updated
            ON {CDN_RESOURCE_PACKAGE_TABLE}(resource_type, updated_at);
            CREATE INDEX IF NOT EXISTS idx_cdn_resource_packages_cursor
            ON {CDN_RESOURCE_PACKAGE_TABLE}(publication_cursor, resource_did);
            "#
        ))
        .await?;
    Ok(())
}

fn admin_auth_config(state: &AppState) -> AdminAuthConfig {
    match state.config.security.admin.mode.as_str() {
        "static-token" => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
        _ => AdminAuthConfig {
            mode: AdminAuthMode::StaticToken {
                tokens: state.config.security.admin.static_tokens.clone(),
            },
        },
    }
}

fn require_admin(
    headers: &HeaderMap,
    state: &AppState,
) -> std::result::Result<AdminPrincipal, ApiError> {
    let config = admin_auth_config(state);
    let token = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| bearer_token_from_header(Some(value)));
    verify_admin_token(token, &config).map_err(|err| ApiError {
        status: StatusCode::UNAUTHORIZED,
        message: err.to_string(),
    })
}

fn load_trusted_root_document(state: &AppState) -> std::result::Result<DidDocument, ApiError> {
    let did_document: DidDocument = state
        .data
        .read(
            &state
                .config
                .security
                .trusted_upstream
                .root_did_document_file,
        )
        .or_else(|_| {
            JsonStore::new(".").read(
                &state
                    .config
                    .security
                    .trusted_upstream
                    .root_did_document_file,
            )
        })
        .map_err(|err| ApiError::internal(err.into()))?;
    if did_document.id != state.config.security.trusted_upstream.root_did {
        return Err(ApiError::bad_request("trusted_root_document_id_mismatch"));
    }
    Ok(did_document)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn build_cors_layer(config: &CorsConfig) -> Result<CorsLayer> {
    let origins: Vec<HeaderValue> = config
        .allowed_origins
        .iter()
        .map(|origin| HeaderValue::from_str(origin))
        .collect::<std::result::Result<_, _>>()?;
    Ok(CorsLayer::new()
        .allow_origin(AllowOrigin::list(origins))
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::OPTIONS])
        .allow_headers(AllowHeaders::any()))
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({"status": "ok", "nodeType": "cdn-service", "did": null}))
}

fn trusted_resource_upstream_policy(
    state: &AppState,
    expected_path: &str,
) -> TrustedUpstreamPolicy {
    TrustedUpstreamPolicy {
        expected_purpose: PURPOSE_CDN_PUBLISH.to_owned(),
        expected_method: "POST".to_owned(),
        expected_path: expected_path.to_owned(),
        expected_audience: state.config.security.trusted_upstream.root_did.clone(),
        max_clock_skew_seconds: state
            .config
            .security
            .trusted_upstream
            .max_clock_skew_seconds,
        nonce_ttl_seconds: state.config.security.trusted_upstream.nonce_ttl_seconds,
        nonce_store_path: state
            .config
            .security
            .trusted_upstream
            .nonce_store_file
            .clone(),
    }
}

async fn publish_resource(
    State(state): State<AppState>,
    Json(request): Json<ResourceCdnPublishRequest>,
) -> ApiResult<serde_json::Value> {
    let root_document = load_trusted_root_document(&state)?;
    verify_signed_request_envelope(
        &request.upstream_auth,
        &request.package,
        &state.config.security.trusted_upstream.root_did,
        &root_document,
        &trusted_resource_upstream_policy(&state, PATH_CDN_RESOURCES),
        Utc::now(),
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;
    let package = request.package;
    validate_publishable_resource(&state, &package)?;
    persist_published_resource(&state, &package)
        .await
        .map_err(ApiError::internal)?;
    let publication_cursor = next_publication_cursor(&state)
        .await
        .map_err(ApiError::internal)?;
    upsert_resource_index(&state, publication_cursor, &package)
        .await
        .map_err(ApiError::internal)?;
    let history_item = json!({
        "resourceDid": package.resource_did,
        "resourceType": package.resource_type,
        "version": package.package_version,
        "publicationCursor": publication_cursor,
        "requestId": request.upstream_auth.request_id,
        "publishedAt": Utc::now()
    });
    append_publish_history(&state, history_item)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "published",
        "resourceDid": package.resource_did,
        "resourceType": package.resource_type,
        "packageVersion": package.package_version,
        "publicationCursor": publication_cursor
    })))
}

async fn publish_resources_batch(
    State(state): State<AppState>,
    Json(request): Json<ResourceCdnBatchPublishRequest>,
) -> ApiResult<serde_json::Value> {
    if request.items.is_empty() {
        return Err(ApiError::bad_request("empty_batch"));
    }
    let root_document = load_trusted_root_document(&state)?;
    verify_signed_request_envelope(
        &request.upstream_auth,
        &request.items,
        &state.config.security.trusted_upstream.root_did,
        &root_document,
        &trusted_resource_upstream_policy(&state, PATH_CDN_RESOURCES_BATCH),
        Utc::now(),
    )
    .map_err(|err| ApiError::bad_request(err.to_string()))?;

    let mut accepted = Vec::with_capacity(request.items.len());
    let mut failed = Vec::new();
    for item in request.items {
        match validate_publishable_resource(&state, &item.package) {
            Ok(()) => accepted.push(item),
            Err(err) => failed.push(json!({
                "resourceDid": item.package.resource_did,
                "publicationCursor": item.publication_cursor,
                "error": err.message
            })),
        }
    }
    persist_published_resources_batch(&state, &accepted)
        .await
        .map_err(ApiError::internal)?;
    append_publish_history_batch(&state, &accepted, &request.upstream_auth.request_id)
        .await
        .map_err(ApiError::internal)?;

    Ok(Json(json!({
        "status": if failed.is_empty() { "published" } else { "partial" },
        "acceptedCount": accepted.len(),
        "failedCount": failed.len(),
        "items": accepted.iter().map(|item| json!({
            "resourceDid": item.package.resource_did,
            "resourceType": item.package.resource_type,
            "packageVersion": item.package.package_version,
            "publicationCursor": item.publication_cursor,
            "status": "published"
        })).collect::<Vec<_>>(),
        "failed": failed
    })))
}

fn validate_publishable_resource(
    state: &AppState,
    package: &ResourcePackage,
) -> std::result::Result<(), ApiError> {
    package
        .verify_did_document_hash()
        .and_then(|_| package.verify_metadata_hash())
        .and_then(|_| package.verify_package_hash())
        .and_then(|_| package.verify_resource_type_consistency())
        .and_then(|_| package.verify_metadata_consistency())
        .and_then(|_| package.verify_root_claim_binding())
        .map_err(|err| ApiError::bad_request(err.to_string()))?;
    if package.root_proof.root_did != state.config.security.trusted_upstream.root_did {
        return Err(ApiError::bad_request("trusted_upstream_root_did_mismatch"));
    }
    Ok(())
}

async fn persist_published_resource(state: &AppState, package: &ResourcePackage) -> Result<()> {
    let file = did_to_file_name(&package.resource_did);
    state
        .data
        .write(format!("documents/{file}"), &package.did_document)?;
    state
        .data
        .write(format!("metadata/{file}"), &package.metadata)?;
    state.data.write(format!("resources/{file}"), package)?;
    Ok(())
}

async fn persist_published_resources_batch(
    state: &AppState,
    items: &[ResourceCdnPublishBatchItem],
) -> Result<()> {
    let items = dedupe_publish_items_by_did(items);
    if state.sqlite.is_none() && state.postgres.is_none() {
        for item in &items {
            let package = &item.package;
            let file = did_to_file_name(&package.resource_did);
            state
                .data
                .write(format!("documents/{file}"), &package.did_document)?;
            state
                .data
                .write(format!("metadata/{file}"), &package.metadata)?;
            state.data.write(format!("resources/{file}"), package)?;
        }
    }
    upsert_resource_index_batch(state, &items).await
}

fn dedupe_publish_items_by_did(
    items: &[ResourceCdnPublishBatchItem],
) -> Vec<ResourceCdnPublishBatchItem> {
    let mut deduped = BTreeMap::<String, ResourceCdnPublishBatchItem>::new();
    for item in items {
        let did = item.package.resource_did.clone();
        match deduped.get(&did) {
            Some(existing) if existing.publication_cursor >= item.publication_cursor => {}
            _ => {
                deduped.insert(did, item.clone());
            }
        }
    }
    deduped.into_values().collect()
}

async fn get_resource_package(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<ResourcePackage> {
    read_by_did(&state, "resources", &did).await
}

async fn api_get_resource_packages_batch(
    State(state): State<AppState>,
    Json(request): Json<ResourceBatchGetRequest>,
) -> ApiResult<serde_json::Value> {
    if request.resource_dids.is_empty() {
        return Err(ApiError::bad_request("empty_resource_dids"));
    }
    let packages = read_resource_packages_by_dids(&state, &request.resource_dids)
        .await
        .map_err(ApiError::internal)?;
    let items = request
        .resource_dids
        .iter()
        .filter_map(|did| {
            packages.get(did).map(|package| {
                json!({
                    "resourceDid": did,
                    "package": package
                })
            })
        })
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "requestedCount": request.resource_dids.len(),
        "foundCount": items.len(),
        "items": items
    })))
}

async fn get_document(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<oan_core::DidDocument> {
    read_by_did(&state, "documents", &did).await
}

async fn get_metadata(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<Value> {
    read_by_did(&state, "metadata", &did).await
}

async fn resource_count(state: &AppState) -> Result<i64> {
    if let Some(sqlite) = &state.sqlite {
        return Ok(sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {CDN_RESOURCE_PACKAGE_TABLE}"
        ))
        .fetch_one(sqlite.pool())
        .await?);
    }
    if let Some(postgres) = &state.postgres {
        return Ok(sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {CDN_RESOURCE_PACKAGE_TABLE}"
        ))
        .fetch_one(postgres.pool())
        .await?);
    }
    Ok(read_resource_index(state).await?.len() as i64)
}

async fn api_status(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let resource_count = resource_count(&state).await.map_err(ApiError::internal)?;
    Ok(Json(json!({
        "status": "ok",
        "resourceCount": resource_count,
        "rootDid": read_root_meta(&state, "root_did").await.map_err(ApiError::internal)?,
        "generatedAt": read_root_meta(&state, "generated_at").await.map_err(ApiError::internal)?
    })))
}

async fn api_resources_catalog(
    State(state): State<AppState>,
    Query(query): Query<ResourceIndexQuery>,
) -> ApiResult<serde_json::Value> {
    let after_cursor = query.after_cursor.unwrap_or(0).max(0);
    let limit = query
        .limit
        .unwrap_or(CDN_DEFAULT_PAGE_SIZE)
        .clamp(1, CDN_MAX_PAGE_SIZE);
    let page = read_resource_index_page(&state, after_cursor, limit)
        .await
        .map_err(ApiError::internal)?;
    let items = page
        .items
        .into_iter()
        .map(|item| item.package)
        .collect::<Vec<_>>();
    Ok(Json(json!({
        "items": items,
        "count": items.len(),
        "afterCursor": after_cursor,
        "nextCursor": page.next_cursor,
        "hasMore": page.has_more
    })))
}

async fn api_resource_catalog_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let package: Option<ResourcePackage> = state
        .data
        .read(format!("resources/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "resourceDid": did, "package": package })))
}

async fn api_document_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let document: Option<oan_core::DidDocument> = state
        .data
        .read(format!("documents/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "did": did, "document": document })))
}

async fn api_metadata_detail(
    State(state): State<AppState>,
    AxumPath(did): AxumPath<String>,
) -> ApiResult<serde_json::Value> {
    let metadata: Option<oan_package::ResourceMetadata> = state
        .data
        .read(format!("metadata/{}", did_to_file_name(&did)))
        .ok();
    Ok(Json(json!({ "resourceDid": did, "metadata": metadata })))
}

async fn api_resource_catalog_stats(State(state): State<AppState>) -> ApiResult<serde_json::Value> {
    let mut resource_type_counts = serde_json::Map::new();
    let resource_count = if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT resource_type, COUNT(*) FROM {CDN_RESOURCE_PACKAGE_TABLE} GROUP BY resource_type"
        ))
        .fetch_all(sqlite.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let mut total = 0_i64;
        for row in rows {
            let count = row.get::<i64, _>(1);
            total += count;
            resource_type_counts.insert(row.get::<String, _>(0), json!(count));
        }
        total
    } else if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT resource_type, COUNT(*) FROM {CDN_RESOURCE_PACKAGE_TABLE} GROUP BY resource_type"
        ))
        .fetch_all(postgres.pool())
        .await
        .map_err(|err| ApiError::internal(err.into()))?;
        let mut total = 0_i64;
        for row in rows {
            let count = row.get::<i64, _>(1);
            total += count;
            resource_type_counts.insert(row.get::<String, _>(0), json!(count));
        }
        total
    } else {
        let resources = read_resource_index(&state)
            .await
            .map_err(ApiError::internal)?;
        for package in &resources {
            let key = package.resource_type.as_str();
            let count = resource_type_counts
                .get(key)
                .and_then(Value::as_u64)
                .unwrap_or(0)
                + 1;
            resource_type_counts.insert(key.to_owned(), json!(count));
        }
        resources.len() as i64
    };
    Ok(Json(json!({
        "resourceCount": resource_count,
        "resourceTypeCounts": resource_type_counts,
        "version": OAN_RESOURCE_PROTOCOL_VERSION
    })))
}

async fn api_publish_history(
    State(state): State<AppState>,
    Query(query): Query<PublishHistoryQuery>,
) -> ApiResult<serde_json::Value> {
    let limit = query
        .limit
        .unwrap_or(CDN_DEFAULT_PAGE_SIZE as u32)
        .clamp(1, CDN_MAX_PAGE_SIZE as u32) as i64;
    let (items, next_key, has_more) =
        read_publish_history_page(&state, query.after_key.as_deref(), limit)
            .await
            .map_err(ApiError::internal)?;
    Ok(Json(json!({
        "items": items,
        "count": items.len(),
        "afterKey": query.after_key,
        "nextKey": if has_more { next_key } else { None::<String> },
        "hasMore": has_more
    })))
}

async fn api_purge(
    headers: HeaderMap,
    State(state): State<AppState>,
    Json(payload): Json<Value>,
) -> ApiResult<serde_json::Value> {
    let _principal = require_admin(&headers, &state)?;
    if let Some(did) = payload
        .get("resourceDid")
        .or_else(|| payload.get("did"))
        .and_then(|value| value.as_str())
    {
        let _ = state
            .data
            .resolve(format!("resources/{}", did_to_file_name(did)));
    }
    Ok(Json(json!({
        "status": "accepted",
        "note": "resource purge is advisory only"
    })))
}

async fn cdn_debug_export_loop(state: AppState) {
    loop {
        if let Err(err) = export_cdn_debug_snapshot(&state).await {
            eprintln!("cdn debug export failed: {err}");
        }
        sleep(TokioDuration::from_millis(
            state.config.debug.export_interval_ms.max(100),
        ))
        .await;
    }
}

async fn api_resource_index(
    State(state): State<AppState>,
    Query(query): Query<ResourceIndexQuery>,
) -> ApiResult<serde_json::Value> {
    let after_cursor = query.after_cursor.unwrap_or(0).max(0);
    let limit = query
        .limit
        .unwrap_or(CDN_DEFAULT_PAGE_SIZE)
        .clamp(1, CDN_MAX_PAGE_SIZE);
    let page = read_resource_index_page(&state, after_cursor, limit)
        .await
        .map_err(ApiError::internal)?;
    Ok(Json(
        serde_json::to_value(page).map_err(|err| ApiError::internal(err.into()))?,
    ))
}

async fn read_resource_index_page(
    state: &AppState,
    after_cursor: i64,
    limit: i64,
) -> Result<ResourceCdnIndexResponse> {
    let page_limit = limit.max(1);
    let fetch_limit = page_limit + 1;
    let mut rows = Vec::<ResourceCdnIndexItem>::new();
    if let Some(sqlite) = &state.sqlite {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, package_json
            FROM {CDN_RESOURCE_PACKAGE_TABLE}
            WHERE publication_cursor > ?
            ORDER BY publication_cursor, resource_did
            LIMIT ?
            "#
        ))
        .bind(after_cursor)
        .bind(fetch_limit)
        .fetch_all(sqlite.pool())
        .await?;
        for row in db_rows {
            rows.push(ResourceCdnIndexItem {
                cursor: row.get::<i64, _>(0),
                package: serde_json::from_str(&row.get::<String, _>(1))?,
            });
        }
    } else if let Some(postgres) = &state.postgres {
        let db_rows = sqlx::query(&format!(
            r#"
            SELECT publication_cursor, package_json::text
            FROM {CDN_RESOURCE_PACKAGE_TABLE}
            WHERE publication_cursor > $1
            ORDER BY publication_cursor, resource_did
            LIMIT $2
            "#
        ))
        .bind(after_cursor)
        .bind(fetch_limit)
        .fetch_all(postgres.pool())
        .await?;
        for row in db_rows {
            rows.push(ResourceCdnIndexItem {
                cursor: row.get::<i64, _>(0),
                package: serde_json::from_str(&row.get::<String, _>(1))?,
            });
        }
    } else {
        let mut indexed = state
            .data
            .read::<BTreeMap<String, ResourcePackage>>("resources/index.json")
            .unwrap_or_default()
            .into_values()
            .enumerate()
            .map(|(index, package)| ResourceCdnIndexItem {
                cursor: index as i64 + 1,
                package,
            })
            .filter(|item| item.cursor > after_cursor)
            .collect::<Vec<_>>();
        indexed.sort_by(|a, b| {
            a.cursor
                .cmp(&b.cursor)
                .then(a.package.resource_did.cmp(&b.package.resource_did))
        });
        rows = indexed.into_iter().take(fetch_limit as usize).collect();
    }
    let has_more = rows.len() as i64 > page_limit;
    if has_more {
        rows.truncate(page_limit as usize);
    }
    let next_cursor = rows.last().map(|item| item.cursor).unwrap_or(after_cursor);
    Ok(ResourceCdnIndexResponse {
        count: rows.len(),
        items: rows,
        after_cursor,
        next_cursor,
        has_more,
    })
}

async fn read_resource_index(state: &AppState) -> Result<Vec<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT package_json FROM {CDN_RESOURCE_PACKAGE_TABLE} ORDER BY updated_at, resource_did"
        ))
        .fetch_all(sqlite.pool())
        .await?;
        return rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .collect();
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT package_json::text FROM {CDN_RESOURCE_PACKAGE_TABLE} ORDER BY updated_at, resource_did"
        ))
        .fetch_all(postgres.pool())
        .await?;
        return rows
            .into_iter()
            .map(|row| {
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0))
                    .map_err(anyhow::Error::from)
            })
            .collect();
    }
    Ok(state
        .data
        .read::<BTreeMap<String, ResourcePackage>>("resources/index.json")
        .unwrap_or_default()
        .into_values()
        .collect())
}

async fn next_publication_cursor(state: &AppState) -> Result<i64> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT COALESCE(MAX(publication_cursor), 0) + 1 FROM {CDN_RESOURCE_PACKAGE_TABLE}"
        ))
        .fetch_one(sqlite.pool())
        .await?;
        return Ok(row.get::<i64, _>(0));
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT COALESCE(MAX(publication_cursor), 0) + 1 FROM {CDN_RESOURCE_PACKAGE_TABLE}"
        ))
        .fetch_one(postgres.pool())
        .await?;
        return Ok(row.get::<i64, _>(0));
    }
    let count = state
        .data
        .read::<BTreeMap<String, ResourcePackage>>("resources/index.json")
        .unwrap_or_default()
        .len();
    Ok(count as i64 + 1)
}

async fn upsert_resource_index(
    state: &AppState,
    publication_cursor: i64,
    package: &ResourcePackage,
) -> Result<()> {
    upsert_resource_index_batch(
        state,
        &[ResourceCdnPublishBatchItem {
            publication_cursor,
            package: package.clone(),
        }],
    )
    .await
}

async fn upsert_resource_index_batch(
    state: &AppState,
    items: &[ResourceCdnPublishBatchItem],
) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    let updated_at = Utc::now();
    let updated_at_text = updated_at.to_rfc3339();
    if let Some(sqlite) = &state.sqlite {
        let rows = items
            .iter()
            .map(|item| {
                Ok::<_, anyhow::Error>((
                    item.package.resource_did.clone(),
                    item.publication_cursor,
                    item.package.resource_type.as_str().to_owned(),
                    item.package.package_version.clone(),
                    serde_json::to_string(&item.package)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tx = sqlite.pool().begin().await?;
        for chunk in rows.chunks(250) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                "INSERT INTO {CDN_RESOURCE_PACKAGE_TABLE}(resource_did, publication_cursor, resource_type, package_version, package_json, updated_at) "
            ));
            builder.push_values(
                chunk,
                |mut row,
                 (
                    resource_did,
                    publication_cursor,
                    resource_type,
                    package_version,
                    package_json,
                )| {
                    row.push_bind(resource_did)
                        .push_bind(publication_cursor)
                        .push_bind(resource_type)
                        .push_bind(package_version)
                        .push_bind(package_json)
                        .push_bind(&updated_at_text);
                },
            );
            builder.push(
                r#"
                ON CONFLICT(resource_did)
                DO UPDATE SET
                    publication_cursor = MAX(cdn_resource_packages.publication_cursor, excluded.publication_cursor),
                    resource_type = excluded.resource_type,
                    package_version = excluded.package_version,
                    package_json = excluded.package_json,
                    updated_at = excluded.updated_at
                "#,
            );
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        upsert_root_meta(state, "root_did", &items[0].package.root_proof.root_did).await?;
        upsert_root_meta(state, "generated_at", &updated_at_text).await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let rows = items
            .iter()
            .map(|item| {
                Ok::<_, anyhow::Error>((
                    item.package.resource_did.clone(),
                    item.publication_cursor,
                    item.package.resource_type.as_str().to_owned(),
                    item.package.package_version.clone(),
                    serde_json::to_value(&item.package)?,
                ))
            })
            .collect::<Result<Vec<_>>>()?;
        let mut tx = postgres.pool().begin().await?;
        for chunk in rows.chunks(250) {
            let mut builder = QueryBuilder::<Postgres>::new(format!(
                "INSERT INTO {CDN_RESOURCE_PACKAGE_TABLE}(resource_did, publication_cursor, resource_type, package_version, package_json, updated_at) "
            ));
            builder.push_values(
                chunk,
                |mut row,
                 (
                    resource_did,
                    publication_cursor,
                    resource_type,
                    package_version,
                    package_json,
                )| {
                    row.push_bind(resource_did)
                        .push_bind(publication_cursor)
                        .push_bind(resource_type)
                        .push_bind(package_version)
                        .push_bind(package_json)
                        .push_bind(updated_at);
                },
            );
            builder.push(format!(
                r#"
                ON CONFLICT(resource_did)
                DO UPDATE SET
                    publication_cursor = GREATEST({CDN_RESOURCE_PACKAGE_TABLE}.publication_cursor, excluded.publication_cursor),
                    resource_type = excluded.resource_type,
                    package_version = excluded.package_version,
                    package_json = excluded.package_json,
                    updated_at = excluded.updated_at
                "#
            ));
            builder.build().execute(&mut *tx).await?;
        }
        tx.commit().await?;
        upsert_root_meta(state, "root_did", &items[0].package.root_proof.root_did).await?;
        upsert_root_meta(state, "generated_at", &updated_at_text).await?;
        return Ok(());
    }
    let mut index = state
        .data
        .read::<BTreeMap<String, ResourcePackage>>("resources/index.json")
        .unwrap_or_default();
    for item in items {
        index.insert(item.package.resource_did.clone(), item.package.clone());
    }
    state.data.write("resources/index.json", &index)?;
    upsert_root_meta(state, "root_did", &items[0].package.root_proof.root_did).await?;
    upsert_root_meta(state, "generated_at", &Utc::now().to_rfc3339()).await?;
    Ok(())
}

async fn read_root_meta(state: &AppState, key: &str) -> Result<Option<String>> {
    if let Some(sqlite) = &state.sqlite {
        return Ok(sqlx::query(&format!(
            "SELECT meta_value FROM {CDN_ROOT_META_TABLE} WHERE meta_key = ?"
        ))
        .bind(key)
        .fetch_optional(sqlite.pool())
        .await?
        .map(|row| row.get::<String, _>(0)));
    }
    if let Some(postgres) = &state.postgres {
        return Ok(sqlx::query(&format!(
            "SELECT meta_value FROM {CDN_ROOT_META_TABLE} WHERE meta_key = $1"
        ))
        .bind(key)
        .fetch_optional(postgres.pool())
        .await?
        .map(|row| row.get::<String, _>(0)));
    }
    Ok(None)
}

async fn upsert_root_meta(state: &AppState, key: &str, value: &str) -> Result<()> {
    if let Some(sqlite) = &state.sqlite {
        sqlx::query(&format!(
            r#"
            INSERT INTO {CDN_ROOT_META_TABLE}(meta_key, meta_value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(meta_key)
            DO UPDATE SET meta_value = excluded.meta_value, updated_at = excluded.updated_at
            "#
        ))
        .bind(key)
        .bind(value)
        .bind(Utc::now().to_rfc3339())
        .execute(sqlite.pool())
        .await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        sqlx::query(&format!(
            r#"
            INSERT INTO {CDN_ROOT_META_TABLE}(meta_key, meta_value, updated_at)
            VALUES ($1, $2, $3::timestamptz)
            ON CONFLICT(meta_key)
            DO UPDATE SET meta_value = excluded.meta_value, updated_at = excluded.updated_at
            "#
        ))
        .bind(key)
        .bind(value)
        .bind(Utc::now())
        .execute(postgres.pool())
        .await?;
    }
    Ok(())
}

async fn append_publish_history(state: &AppState, item: Value) -> Result<()> {
    append_publish_history_values(state, &[item]).await
}

async fn append_publish_history_batch(
    state: &AppState,
    items: &[ResourceCdnPublishBatchItem],
    request_id: &str,
) -> Result<()> {
    let now = Utc::now();
    let history = items
        .iter()
        .map(|item| {
            json!({
                "resourceDid": item.package.resource_did,
                "resourceType": item.package.resource_type,
                "version": item.package.package_version,
                "publicationCursor": item.publication_cursor,
                "requestId": request_id,
                "publishedAt": now
            })
        })
        .collect::<Vec<_>>();
    append_publish_history_values(state, &history).await
}

async fn append_publish_history_values(state: &AppState, items: &[Value]) -> Result<()> {
    if items.is_empty() {
        return Ok(());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut tx = sqlite.pool().begin().await?;
        for (offset, item) in items.iter().enumerate() {
            sqlx::query(&format!(
                "INSERT INTO {CDN_PUBLISH_HISTORY_TABLE}(history_key, item_json, published_at) VALUES (?, ?, ?)"
            ))
            .bind(format!(
                "{}-{offset}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ))
            .bind(serde_json::to_string(item)?)
            .bind(Utc::now())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    if let Some(postgres) = &state.postgres {
        let mut tx = postgres.pool().begin().await?;
        for (offset, item) in items.iter().enumerate() {
            sqlx::query(&format!(
                "INSERT INTO {CDN_PUBLISH_HISTORY_TABLE}(history_key, item_json, published_at) VALUES ($1, $2::jsonb, $3::timestamptz)"
            ))
            .bind(format!(
                "{}-{offset}",
                Utc::now().timestamp_nanos_opt().unwrap_or_default()
            ))
            .bind(serde_json::to_string(item)?)
            .bind(Utc::now().to_rfc3339())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        return Ok(());
    }
    let mut history: Vec<Value> = state.data.read("publish-history.json").unwrap_or_default();
    history.extend(items.iter().cloned());
    state.data.write("publish-history.json", &history)?;
    Ok(())
}


async fn read_publish_history_page(
    state: &AppState,
    after_key: Option<&str>,
    limit: i64,
) -> Result<(Vec<Value>, Option<String>, bool)> {
    let fetch_limit = limit.saturating_add(1);
    if let Some(sqlite) = &state.sqlite {
        let rows = sqlx::query(&format!(
            "SELECT history_key, item_json
             FROM {CDN_PUBLISH_HISTORY_TABLE}
             WHERE (? IS NULL OR history_key > ?)
             ORDER BY history_key
             LIMIT ?"
        ))
        .bind(after_key)
        .bind(after_key)
        .bind(fetch_limit)
        .fetch_all(sqlite.pool())
        .await?;
        let fetched_len = rows.len();
        let mut items = Vec::new();
        let mut next_key = None;
        for row in rows.into_iter().take(limit as usize) {
            next_key = Some(row.get::<String, _>(0));
            items.push(serde_json::from_str::<Value>(&row.get::<String, _>(1))?);
        }
        let has_more = fetched_len > limit as usize;
        return Ok((items, next_key, has_more));
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT history_key, item_json::text
             FROM {CDN_PUBLISH_HISTORY_TABLE}
             WHERE ($1::text IS NULL OR history_key > $1)
             ORDER BY history_key
             LIMIT $2"
        ))
        .bind(after_key)
        .bind(fetch_limit)
        .fetch_all(postgres.pool())
        .await?;
        let fetched_len = rows.len();
        let mut items = Vec::new();
        let mut next_key = None;
        for row in rows.into_iter().take(limit as usize) {
            next_key = Some(row.get::<String, _>(0));
            items.push(serde_json::from_str::<Value>(&row.get::<String, _>(1))?);
        }
        let has_more = fetched_len > limit as usize;
        return Ok((items, next_key, has_more));
    }
    let history: Vec<Value> = state.data.read("publish-history.json").unwrap_or_default();
    let start = after_key
        .and_then(|key| key.parse::<usize>().ok())
        .unwrap_or(0);
    let mut items = history
        .into_iter()
        .skip(start)
        .take(limit as usize + 1)
        .collect::<Vec<_>>();
    let has_more = items.len() > limit as usize;
    if has_more {
        items.truncate(limit as usize);
    }
    let next_key = if has_more {
        Some((start + items.len()).to_string())
    } else {
        None
    };
    Ok((std::mem::take(&mut items), next_key, has_more))
}

async fn export_cdn_debug_snapshot(state: &AppState) -> Result<()> {
    if state.sqlite.is_none() && state.postgres.is_none() {
        return Ok(());
    }
    let mut after_cursor = 0;
    let mut index = BTreeMap::new();
    loop {
        let page = read_resource_index_page(state, after_cursor, CDN_DEFAULT_PAGE_SIZE).await?;
        let next = page.next_cursor;
        for item in page.items {
            index.insert(item.package.resource_did.clone(), item.package);
        }
        if !page.has_more {
            break;
        }
        after_cursor = next;
    }
    state.data.write("resources/index.json", &index)?;
    let mut after_key = None;
    let mut history = Vec::new();
    loop {
        let (items, next, has_more) =
            read_publish_history_page(state, after_key.as_deref(), CDN_DEFAULT_PAGE_SIZE).await?;
        history.extend(items);
        if !has_more {
            break;
        }
        after_key = next;
    }
    state.data.write("publish-history.json", &history)?;
    Ok(())
}

async fn read_resource_package_by_did(
    state: &AppState,
    did: &str,
) -> Result<Option<ResourcePackage>> {
    if let Some(sqlite) = &state.sqlite {
        let row = sqlx::query(&format!(
            "SELECT package_json FROM {CDN_RESOURCE_PACKAGE_TABLE} WHERE resource_did = ?"
        ))
        .bind(did)
        .fetch_optional(sqlite.pool())
        .await?;
        return row
            .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
            .transpose()
            .map_err(Into::into);
    }
    if let Some(postgres) = &state.postgres {
        let row = sqlx::query(&format!(
            "SELECT package_json::text FROM {CDN_RESOURCE_PACKAGE_TABLE} WHERE resource_did = $1"
        ))
        .bind(did)
        .fetch_optional(postgres.pool())
        .await?;
        return row
            .map(|row| serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(0)))
            .transpose()
            .map_err(Into::into);
    }
    Ok(None)
}

async fn read_resource_packages_by_dids(
    state: &AppState,
    dids: &[String],
) -> Result<BTreeMap<String, ResourcePackage>> {
    if dids.is_empty() {
        return Ok(BTreeMap::new());
    }
    if let Some(sqlite) = &state.sqlite {
        let mut packages = BTreeMap::new();
        for chunk in dids.chunks(500) {
            let mut builder = QueryBuilder::<Sqlite>::new(format!(
                "SELECT resource_did, package_json FROM {CDN_RESOURCE_PACKAGE_TABLE} WHERE resource_did IN ("
            ));
            let mut separated = builder.separated(", ");
            for did in chunk {
                separated.push_bind(did);
            }
            separated.push_unseparated(")");
            let rows = builder.build().fetch_all(sqlite.pool()).await?;
            for row in rows {
                packages.insert(
                    row.get::<String, _>(0),
                    serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?,
                );
            }
        }
        return Ok(packages);
    }
    if let Some(postgres) = &state.postgres {
        let rows = sqlx::query(&format!(
            "SELECT resource_did, package_json::text FROM {CDN_RESOURCE_PACKAGE_TABLE} WHERE resource_did = ANY($1)"
        ))
        .bind(dids)
        .fetch_all(postgres.pool())
        .await?;
        let mut packages = BTreeMap::new();
        for row in rows {
            packages.insert(
                row.get::<String, _>(0),
                serde_json::from_str::<ResourcePackage>(&row.get::<String, _>(1))?,
            );
        }
        return Ok(packages);
    }
    let index = state
        .data
        .read::<BTreeMap<String, ResourcePackage>>("resources/index.json")
        .unwrap_or_default();
    Ok(dids
        .iter()
        .filter_map(|did| index.get(did).map(|package| (did.clone(), package.clone())))
        .collect())
}

async fn read_by_did<T: serde::de::DeserializeOwned>(
    state: &AppState,
    kind: &str,
    did: &str,
) -> ApiResult<T> {
    if state.sqlite.is_some() || state.postgres.is_some() {
        let package = read_resource_package_by_did(state, did)
            .await
            .map_err(ApiError::internal)?;
        if let Some(package) = package {
            let value = match kind {
                "resources" => serde_json::to_value(package),
                "documents" => serde_json::to_value(package.did_document),
                "metadata" => serde_json::to_value(package.metadata),
                _ => Err(serde_json::Error::io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "unsupported CDN resource kind",
                ))),
            }
            .map_err(|err| ApiError::internal(err.into()))?;
            return serde_json::from_value(value)
                .map(Json)
                .map_err(|err| ApiError::internal(err.into()));
        }
    }
    state
        .data
        .read(format!("{kind}/{}", did_to_file_name(did)))
        .map(Json)
        .map_err(|_| ApiError::not_found(format!("{kind} not found for {did}")))
}

