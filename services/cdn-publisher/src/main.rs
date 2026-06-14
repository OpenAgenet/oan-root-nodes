// Copyright (c) 2026 OpenAgenet contributors
//
// Initial author: JINLIANG XU
// Email: jlxufly@gmail.com

use anyhow::{anyhow, Result};
use axum::{extract::State, routing::get, Json, Router};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::Utc;
use futures::StreamExt;
use oan_core::CryptoSuite;
use oan_crypto::{signing_key_from_bytes, SigningKey};
use oan_package::ResourcePackage;
use oan_protocol::{
    HealthResponse, ResourceCdnBatchPublishRequest, ResourceCdnPublishBatchItem,
    OAN_RESOURCE_PROTOCOL_VERSION, PATH_CDN_RESOURCES_BATCH, PURPOSE_CDN_PUBLISH,
};
use oan_publication_events::CdnPublishRequestedEvent;
use oan_service_security::{
    create_signed_request_envelope, request_id, request_nonce, SignedRequestEnvelopeInput,
};
use oan_storage::JsonStore;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    task::JoinSet,
    time::{sleep, Duration as TokioDuration},
};
use url::Url;

#[derive(Clone, Debug, Deserialize)]
struct Config {
    server: ServerConfig,
    events: EventConfig,
    root: RootConfig,
    cdn: CdnConfig,
}

#[derive(Clone, Debug, Deserialize)]
struct ServerConfig {
    host: String,
    port: u16,
}

#[derive(Clone, Debug, Deserialize)]
struct EventConfig {
    endpoint: String,
    stream: String,
    subject: String,
    durable_consumer: String,
    #[serde(default = "default_batch_size")]
    batch_size: usize,
    #[serde(default = "default_fetch_timeout_ms")]
    fetch_timeout_ms: u64,
    #[serde(default = "default_max_in_flight")]
    max_in_flight: usize,
}

#[derive(Clone, Debug, Deserialize)]
struct RootConfig {
    endpoint: String,
    keys_dir: PathBuf,
    #[serde(default)]
    admin_token: Option<String>,
    #[serde(default = "default_package_batch_path")]
    package_batch_path: String,
    #[serde(default = "default_mark_published_path")]
    mark_published_path: String,
}

#[derive(Clone, Debug, Deserialize)]
struct CdnConfig {
    endpoint: String,
    publish_batch_path: String,
    #[serde(default = "default_http_timeout_seconds")]
    http_timeout_seconds: u64,
}

#[derive(Clone)]
struct AppState {
    config: Config,
    root_did: String,
    signing_key: SigningKey,
    client: reqwest::Client,
    runtime: Arc<Mutex<PublisherRuntime>>,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PublisherStageRuntime {
    last_batch_size: usize,
    last_concurrency: usize,
    last_success_count: usize,
    last_failure_count: usize,
    last_elapsed_ms: u128,
}

#[derive(Clone, Debug, Default, Serialize)]
struct PublisherRuntime {
    stream: String,
    subject: String,
    durable_consumer: String,
    last_fetched_count: usize,
    last_acked_count: usize,
    last_failed_count: usize,
    total_acked_count: u64,
    total_failed_count: u64,
    last_elapsed_ms: u128,
    last_fetch_elapsed_ms: u128,
    last_prepare_elapsed_ms: u128,
    last_publish_elapsed_ms: u128,
    last_callback_elapsed_ms: u128,
    last_ack_elapsed_ms: u128,
    last_effective_batch_size: usize,
    last_ack_concurrency: usize,
    fetch_stage: PublisherStageRuntime,
    root_fetch_stage: PublisherStageRuntime,
    binding_stage: PublisherStageRuntime,
    cdn_publish_stage: PublisherStageRuntime,
    root_callback_stage: PublisherStageRuntime,
    ack_stage: PublisherStageRuntime,
    last_error: Option<String>,
    updated_at: Option<chrono::DateTime<Utc>>,
}

#[derive(Clone, Debug, Default)]
struct PublisherCycleMetrics {
    fetch_elapsed_ms: u128,
    root_fetch_elapsed_ms: u128,
    binding_elapsed_ms: u128,
    publish_elapsed_ms: u128,
    callback_elapsed_ms: u128,
    ack_elapsed_ms: u128,
    effective_batch_size: usize,
    ack_concurrency: usize,
    fetch_stage: PublisherStageRuntime,
    root_fetch_stage: PublisherStageRuntime,
    binding_stage: PublisherStageRuntime,
    cdn_publish_stage: PublisherStageRuntime,
    root_callback_stage: PublisherStageRuntime,
    ack_stage: PublisherStageRuntime,
}

#[derive(Clone, Debug, Default)]
struct CdnBatchPublishOutcome {
    published_cursors: BTreeSet<i64>,
    published_count: usize,
    retry_count: usize,
    publish_elapsed_ms: u128,
}

struct FetchedEventTask {
    message: async_nats::jetstream::Message,
    event: CdnPublishRequestedEvent,
}

struct PreparedPublishTask {
    message: async_nats::jetstream::Message,
    publication_cursor: i64,
    package: ResourcePackage,
}

struct TerminalFailureTask {
    message: async_nats::jetstream::Message,
}

#[derive(Clone, Debug, Default)]
struct PreparedBatchClassification {
    prepared: Vec<(String, i64, ResourcePackage)>,
    root_fetch_failures: usize,
    binding_failures: usize,
    terminal_job_keys: BTreeSet<String>,
}

#[derive(Clone, Debug, Deserialize)]
struct RootBatchPackageItem {
    #[serde(rename = "jobKey")]
    job_key: String,
    #[serde(rename = "publicationCursor")]
    publication_cursor: i64,
    #[serde(rename = "resourceDid")]
    resource_did: String,
    #[serde(rename = "packageVersion")]
    package_version: String,
    #[serde(rename = "packageHash")]
    package_hash: String,
    #[serde(rename = "didDocumentHash")]
    did_document_hash: String,
    #[serde(rename = "metadataHash")]
    metadata_hash: String,
    package: ResourcePackage,
}

#[derive(Clone, Debug, Deserialize)]
struct DevKeyFile {
    did: String,
    algorithm: String,
    #[serde(rename = "privateKeyJwk")]
    private_key_jwk: PrivateKeyJwk,
}

#[derive(Clone, Debug, Deserialize)]
struct PrivateKeyJwk {
    d: String,
}

fn default_batch_size() -> usize {
    200
}

fn default_fetch_timeout_ms() -> u64 {
    1_000
}

fn default_max_in_flight() -> usize {
    200
}

fn default_http_timeout_seconds() -> u64 {
    30
}

fn default_mark_published_path() -> String {
    "/root/internal/cdn-publication-jobs/mark-published".to_owned()
}

fn default_package_batch_path() -> String {
    "/root/internal/cdn-publication-jobs/packages".to_owned()
}

fn crypto_suite_from_algorithm(value: &str) -> Result<CryptoSuite> {
    match value {
        "Ed25519" => Ok(CryptoSuite::Ed25519Sha256),
        "SM2" => Ok(CryptoSuite::Sm2Sm3),
        other => Err(anyhow!("unsupported_algorithm: {other}")),
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = env::args()
        .nth(1)
        .unwrap_or_else(|| "services/cdn-publisher/config.example.toml".to_owned());
    let config = load_config(config_path)?;
    let key: DevKeyFile = JsonStore::new(".").read(config.root.keys_dir.join("keypair.json"))?;
    let crypto_suite = crypto_suite_from_algorithm(&key.algorithm)?;
    let signing_key = signing_key_from_bytes(
        crypto_suite,
        &URL_SAFE_NO_PAD.decode(key.private_key_jwk.d)?,
    )?;
    let client = reqwest::Client::builder()
        .timeout(TokioDuration::from_secs(config.cdn.http_timeout_seconds))
        .build()?;
    let state = AppState {
        runtime: Arc::new(Mutex::new(PublisherRuntime {
            stream: config.events.stream.clone(),
            subject: config.events.subject.clone(),
            durable_consumer: config.events.durable_consumer.clone(),
            ..Default::default()
        })),
        root_did: key.did,
        signing_key,
        client,
        config: config.clone(),
    };

    let worker_state = state.clone();
    tokio::spawn(async move {
        if let Err(err) = run_publisher_loop(worker_state).await {
            eprintln!("cdn-publisher loop stopped: {err}");
        }
    });

    let addr: SocketAddr = format!("{}:{}", config.server.host, config.server.port).parse()?;
    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .with_state(state);
    println!("cdn-publisher listening on http://{addr}");
    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_config(path: impl AsRef<Path>) -> Result<Config> {
    let path = path.as_ref();
    let value = std::fs::read_to_string(path)?;
    let mut config: Config = toml::from_str(&value)?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    config.root.keys_dir = resolve_relative(base, &config.root.keys_dir);
    Ok(config)
}

fn resolve_relative(base: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_owned(),
        node_type: "cdn-publisher".to_owned(),
        did: Some(state.root_did),
    })
}

async fn status(State(state): State<AppState>) -> Json<Value> {
    Json(json!({
        "nodeType": "cdn-publisher",
        "rootDid": state.root_did,
        "runtime": runtime_json(&state)
    }))
}

fn runtime_json(state: &AppState) -> Value {
    state
        .runtime
        .lock()
        .map(|runtime| serde_json::to_value(&*runtime).unwrap_or_else(|_| json!({})))
        .unwrap_or_else(|_| json!({"status": "unavailable"}))
}

async fn run_publisher_loop(state: AppState) -> Result<()> {
    let client = async_nats::connect(&state.config.events.endpoint).await?;
    let context = async_nats::jetstream::new(client);
    let stream = context
        .get_or_create_stream(async_nats::jetstream::stream::Config {
            name: state.config.events.stream.clone(),
            subjects: vec![state.config.events.subject.clone()],
            ..Default::default()
        })
        .await?;
    let consumer = stream
        .get_or_create_consumer(
            &state.config.events.durable_consumer,
            async_nats::jetstream::consumer::pull::Config {
                durable_name: Some(state.config.events.durable_consumer.clone()),
                ack_policy: async_nats::jetstream::consumer::AckPolicy::Explicit,
                ..Default::default()
            },
        )
        .await?;

    loop {
        let started = std::time::Instant::now();
        let mut cycle_metrics = PublisherCycleMetrics::default();
        let mut fetched = 0usize;
        let mut acked = 0usize;
        let mut failed = 0usize;
        let fetch_limit = state
            .config
            .events
            .batch_size
            .min(state.config.events.max_in_flight.max(1))
            .max(1);
        let mut messages = consumer
            .fetch()
            .max_messages(fetch_limit)
            .expires(TokioDuration::from_millis(
                state.config.events.fetch_timeout_ms.max(1),
            ))
            .messages()
            .await?;
        let fetch_started = std::time::Instant::now();

        let mut batch = Vec::new();
        while let Some(message) = messages.next().await {
            fetched += 1;
            let message = match message {
                Ok(message) => message,
                Err(err) => {
                    failed += 1;
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics.clone(),
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            let decoded = decode_event_payload(&message.payload);
            batch.push((message, decoded));
        }
        cycle_metrics.fetch_elapsed_ms = fetch_started.elapsed().as_millis();
        cycle_metrics.effective_batch_size = batch.len();
        cycle_metrics.fetch_stage = PublisherStageRuntime {
            last_batch_size: batch.len(),
            last_concurrency: 1,
            last_success_count: batch.iter().filter(|(_, event)| event.is_ok()).count(),
            last_failure_count: batch.iter().filter(|(_, event)| event.is_err()).count(),
            last_elapsed_ms: cycle_metrics.fetch_elapsed_ms,
        };

        let (decoded, decode_failures) = decode_fetched_batch(batch);
        let fetch_failures = decode_failures.len();
        failed += fetch_failures;
        let mut terminal_ack_messages = decode_failures
            .into_iter()
            .map(|item| item.message)
            .collect::<Vec<_>>();

        let (prepared, terminal_prepared_failures, root_fetch_metrics, binding_metrics) =
            if decoded.is_empty() {
                (
                    Vec::new(),
                    Vec::new(),
                    PublisherStageRuntime::default(),
                    PublisherStageRuntime::default(),
                )
            } else {
                match prepare_publish_batch(&state, decoded).await {
                    Ok(result) => result,
                    Err(err) => {
                        record_cycle(
                            &state,
                            fetched,
                            acked,
                            failed,
                            started.elapsed().as_millis(),
                            cycle_metrics,
                            Some(err.to_string()),
                        );
                        continue;
                    }
                }
            };
        terminal_ack_messages.extend(
            terminal_prepared_failures
                .into_iter()
                .map(|item| item.message),
        );
        cycle_metrics.root_fetch_elapsed_ms = root_fetch_metrics.last_elapsed_ms;
        cycle_metrics.binding_elapsed_ms = binding_metrics.last_elapsed_ms;
        cycle_metrics.root_fetch_stage = root_fetch_metrics;
        let binding_failure_count = binding_metrics.last_failure_count;
        cycle_metrics.binding_stage = binding_metrics;
        failed += cycle_metrics.root_fetch_stage.last_failure_count;
        failed += cycle_metrics.binding_stage.last_failure_count;

        if !prepared.is_empty() {
            let publish_started = std::time::Instant::now();
            let publish_outcome = match publish_packages_to_cdn(
                &state,
                prepared
                    .iter()
                    .map(|item| (item.publication_cursor, item.package.clone()))
                    .collect(),
            )
            .await
            {
                Ok(outcome) => outcome,
                Err(err) => {
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics,
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            cycle_metrics.publish_elapsed_ms = publish_outcome
                .publish_elapsed_ms
                .max(publish_started.elapsed().as_millis());
            cycle_metrics.cdn_publish_stage = PublisherStageRuntime {
                last_batch_size: prepared.len(),
                last_concurrency: 1,
                last_success_count: publish_outcome.published_count,
                last_failure_count: publish_outcome.retry_count,
                last_elapsed_ms: cycle_metrics.publish_elapsed_ms,
            };
            failed += publish_outcome.retry_count;

            let successful = prepared
                .iter()
                .filter(|item| {
                    publish_outcome
                        .published_cursors
                        .contains(&item.publication_cursor)
                })
                .map(|item| ResourceCdnPublishBatchItem {
                    publication_cursor: item.publication_cursor,
                    package: item.package.clone(),
                })
                .collect::<Vec<_>>();

            let callback_started = std::time::Instant::now();
            let callback_success_count = if successful.is_empty() {
                0
            } else {
                if let Err(err) = mark_root_jobs_published(&state, &successful).await {
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics,
                        Some(err.to_string()),
                    );
                    continue;
                }
                successful.len()
            };
            cycle_metrics.callback_elapsed_ms = callback_started.elapsed().as_millis();
            cycle_metrics.root_callback_stage = PublisherStageRuntime {
                last_batch_size: successful.len(),
                last_concurrency: 1,
                last_success_count: callback_success_count,
                last_failure_count: 0,
                last_elapsed_ms: cycle_metrics.callback_elapsed_ms,
            };

            let mut ack_messages_batch = prepared
                .into_iter()
                .filter_map(|item| {
                    publish_outcome
                        .published_cursors
                        .contains(&item.publication_cursor)
                        .then_some(item.message)
                })
                .collect::<Vec<_>>();
            ack_messages_batch.extend(terminal_ack_messages);
            let ack_concurrency = state.config.events.max_in_flight.max(1);
            cycle_metrics.ack_concurrency = ack_concurrency;
            let ack_started = std::time::Instant::now();
            let acked_batch = match ack_messages(ack_messages_batch, ack_concurrency).await {
                Ok(value) => value,
                Err(err) => {
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics,
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            acked += acked_batch;
            cycle_metrics.ack_elapsed_ms = ack_started.elapsed().as_millis();
            let ack_target_count = callback_success_count + fetch_failures + binding_failure_count;
            cycle_metrics.ack_stage = PublisherStageRuntime {
                last_batch_size: ack_target_count,
                last_concurrency: ack_concurrency,
                last_success_count: acked_batch,
                last_failure_count: ack_target_count.saturating_sub(acked_batch),
                last_elapsed_ms: cycle_metrics.ack_elapsed_ms,
            };
            if acked_batch < ack_target_count {
                failed += ack_target_count - acked_batch;
            }
        } else if !terminal_ack_messages.is_empty() {
            let ack_concurrency = state.config.events.max_in_flight.max(1);
            cycle_metrics.ack_concurrency = ack_concurrency;
            let ack_started = std::time::Instant::now();
            let acked_batch = match ack_messages(terminal_ack_messages, ack_concurrency).await {
                Ok(value) => value,
                Err(err) => {
                    record_cycle(
                        &state,
                        fetched,
                        acked,
                        failed,
                        started.elapsed().as_millis(),
                        cycle_metrics,
                        Some(err.to_string()),
                    );
                    continue;
                }
            };
            acked += acked_batch;
            cycle_metrics.ack_elapsed_ms = ack_started.elapsed().as_millis();
            let ack_target_count = fetch_failures + binding_failure_count;
            cycle_metrics.ack_stage = PublisherStageRuntime {
                last_batch_size: ack_target_count,
                last_concurrency: ack_concurrency,
                last_success_count: acked_batch,
                last_failure_count: ack_target_count.saturating_sub(acked_batch),
                last_elapsed_ms: cycle_metrics.ack_elapsed_ms,
            };
            if acked_batch < ack_target_count {
                failed += ack_target_count - acked_batch;
            }
        }
        record_cycle(
            &state,
            fetched,
            acked,
            failed,
            started.elapsed().as_millis(),
            cycle_metrics,
            None,
        );
        if fetched == 0 {
            sleep(TokioDuration::from_millis(
                state.config.events.fetch_timeout_ms.max(100),
            ))
            .await;
        }
    }
}

async fn ack_messages(
    messages: Vec<async_nats::jetstream::Message>,
    concurrency: usize,
) -> Result<usize> {
    if messages.is_empty() {
        return Ok(0);
    }
    let mut acked = 0usize;
    let mut in_flight = JoinSet::new();
    let mut iter = messages.into_iter();
    let concurrency = concurrency.max(1);
    loop {
        while in_flight.len() < concurrency {
            let Some(message) = iter.next() else {
                break;
            };
            in_flight
                .spawn(async move { message.ack().await.map_err(|err| anyhow!(err.to_string())) });
        }
        if in_flight.is_empty() {
            break;
        }
        let Some(result) = in_flight.join_next().await else {
            break;
        };
        result.map_err(|err| anyhow!("cdn_publisher_ack_task_failed:{err}"))??;
        acked += 1;
    }
    Ok(acked)
}

fn decode_fetched_batch(
    batch: Vec<(
        async_nats::jetstream::Message,
        Result<CdnPublishRequestedEvent>,
    )>,
) -> (Vec<FetchedEventTask>, Vec<TerminalFailureTask>) {
    let mut decoded = Vec::new();
    let mut failures = Vec::new();
    for (message, event) in batch {
        match event {
            Ok(event) => decoded.push(FetchedEventTask { message, event }),
            Err(err) => {
                eprintln!("cdn-publisher failed to decode task: {err}");
                failures.push(TerminalFailureTask { message });
            }
        }
    }
    (decoded, failures)
}

fn decode_event_payload(payload: &[u8]) -> Result<CdnPublishRequestedEvent> {
    let event: CdnPublishRequestedEvent = serde_json::from_slice(payload)?;
    event.validate().map_err(|err| anyhow!(err))?;
    Ok(event)
}

async fn prepare_publish_batch(
    state: &AppState,
    decoded: Vec<FetchedEventTask>,
) -> Result<(
    Vec<PreparedPublishTask>,
    Vec<TerminalFailureTask>,
    PublisherStageRuntime,
    PublisherStageRuntime,
)> {
    if decoded.is_empty() {
        return Ok((
            Vec::new(),
            Vec::new(),
            PublisherStageRuntime::default(),
            PublisherStageRuntime::default(),
        ));
    }
    let input_batch_size = decoded.len();
    let root_fetch_started = std::time::Instant::now();
    let event_refs = decoded.iter().map(|item| &item.event).collect::<Vec<_>>();
    let packages = fetch_resource_packages_batch(state, event_refs.as_slice()).await?;
    let root_fetch_elapsed_ms = root_fetch_started.elapsed().as_millis();

    let binding_started = std::time::Instant::now();
    let events = decoded
        .iter()
        .map(|item| item.event.clone())
        .collect::<Vec<_>>();
    let classification = classify_prepared_packages(&events, &packages);
    let mut classified_by_job = classification
        .prepared
        .into_iter()
        .map(|(job_key, publication_cursor, package)| (job_key, (publication_cursor, package)))
        .collect::<BTreeMap<_, _>>();
    let mut prepared = Vec::new();
    let mut terminal_failures = Vec::new();
    for item in decoded {
        if let Some((publication_cursor, package)) = classified_by_job.remove(&item.event.job_key) {
            prepared.push(PreparedPublishTask {
                message: item.message,
                publication_cursor,
                package,
            });
        } else if classification
            .terminal_job_keys
            .contains(&item.event.job_key)
        {
            eprintln!(
                "cdn-publisher dropped terminal invalid task for job: {}",
                item.event.job_key
            );
            terminal_failures.push(TerminalFailureTask {
                message: item.message,
            });
        } else if !packages.contains_key(&item.event.job_key) {
            eprintln!(
                "cdn-publisher will retry missing root package for job: {}",
                item.event.job_key
            );
        } else {
            eprintln!(
                "cdn-publisher will retry unresolved task for {}",
                item.event.job_key
            );
        }
    }
    let binding_elapsed_ms = binding_started.elapsed().as_millis();
    Ok((
        prepared,
        terminal_failures,
        PublisherStageRuntime {
            last_batch_size: input_batch_size,
            last_concurrency: 1,
            last_success_count: input_batch_size.saturating_sub(classification.root_fetch_failures),
            last_failure_count: classification.root_fetch_failures,
            last_elapsed_ms: root_fetch_elapsed_ms,
        },
        PublisherStageRuntime {
            last_batch_size: input_batch_size.saturating_sub(classification.root_fetch_failures),
            last_concurrency: 1,
            last_success_count: input_batch_size.saturating_sub(
                classification.root_fetch_failures + classification.binding_failures,
            ),
            last_failure_count: classification.binding_failures,
            last_elapsed_ms: binding_elapsed_ms,
        },
    ))
}

fn validate_package_matches_event(
    package: &ResourcePackage,
    event: &CdnPublishRequestedEvent,
) -> Result<()> {
    if package.resource_did != event.resource_did {
        return Err(anyhow!("resource_did_mismatch"));
    }
    if package.package_version != event.package_version {
        return Err(anyhow!("package_version_mismatch"));
    }
    if package.package_hash != event.package_hash {
        return Err(anyhow!("package_hash_mismatch"));
    }
    if package.did_document_hash != event.did_document_hash {
        return Err(anyhow!("did_document_hash_mismatch"));
    }
    if package.metadata_hash != event.metadata_hash {
        return Err(anyhow!("metadata_hash_mismatch"));
    }
    Ok(())
}

fn classify_prepared_packages(
    events: &[CdnPublishRequestedEvent],
    packages: &BTreeMap<String, (i64, ResourcePackage)>,
) -> PreparedBatchClassification {
    let mut classification = PreparedBatchClassification::default();
    for event in events {
        let job_key = event.job_key.clone();
        let Some((publication_cursor, package)) = packages.get(&job_key).cloned() else {
            classification.root_fetch_failures += 1;
            continue;
        };
        if validate_package_matches_event(&package, event).is_err() {
            classification.binding_failures += 1;
            classification.terminal_job_keys.insert(job_key);
            continue;
        }
        classification
            .prepared
            .push((job_key, publication_cursor, package));
    }
    classification
}

async fn fetch_resource_packages_batch(
    state: &AppState,
    events: &[&CdnPublishRequestedEvent],
) -> Result<std::collections::BTreeMap<String, (i64, ResourcePackage)>> {
    if events.is_empty() {
        return Ok(std::collections::BTreeMap::new());
    }
    let Some(admin_token) = state.config.root.admin_token.as_ref() else {
        return Err(anyhow!("root_admin_token_required_for_package_batch"));
    };
    let url = root_package_batch_url(
        &state.config.root.endpoint,
        &state.config.root.package_batch_path,
    )?;
    let jobs = events
        .iter()
        .map(|event| {
            json!({
                "jobKey": event.job_key
            })
        })
        .collect::<Vec<_>>();
    let response = state
        .client
        .post(url)
        .bearer_auth(admin_token)
        .json(&json!({ "jobs": jobs }))
        .send()
        .await?;
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("root_package_batch_failed:{status}:{value}"));
    }
    let items = serde_json::from_value::<Vec<RootBatchPackageItem>>(
        value
            .get("items")
            .cloned()
            .ok_or_else(|| anyhow!("root_package_batch_items_missing"))?,
    )?;
    let mut packages = BTreeMap::new();
    for item in items {
        if item.job_key.trim().is_empty() {
            return Err(anyhow!("root_package_batch_job_key_missing"));
        }
        if item.publication_cursor <= 0 {
            return Err(anyhow!("root_package_batch_cursor_missing"));
        }
        if item.resource_did != item.package.resource_did {
            return Err(anyhow!("root_package_batch_resource_did_mismatch"));
        }
        if item.package_version != item.package.package_version {
            return Err(anyhow!("root_package_batch_package_version_mismatch"));
        }
        if item.package_hash != item.package.package_hash {
            return Err(anyhow!("root_package_batch_package_hash_mismatch"));
        }
        if item.did_document_hash != item.package.did_document_hash {
            return Err(anyhow!("root_package_batch_did_document_hash_mismatch"));
        }
        if item.metadata_hash != item.package.metadata_hash {
            return Err(anyhow!("root_package_batch_metadata_hash_mismatch"));
        }
        packages.insert(item.job_key, (item.publication_cursor, item.package));
    }
    Ok(packages)
}


fn root_package_batch_url(root_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(root_endpoint)?;
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("root_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.trim_start_matches('/').split('/') {
            if !segment.is_empty() {
                segments.push(segment);
            }
        }
    }
    Ok(url)
}

async fn publish_packages_to_cdn(
    state: &AppState,
    packages: Vec<(i64, ResourcePackage)>,
) -> Result<CdnBatchPublishOutcome> {
    if packages.is_empty() {
        return Ok(CdnBatchPublishOutcome::default());
    }
    let request = build_cdn_batch_publish_request(state, packages)?;
    let url = cdn_publish_batch_url(
        &state.config.cdn.endpoint,
        &state.config.cdn.publish_batch_path,
    )?;
    let publish_started = std::time::Instant::now();
    let response = state.client.post(url).json(&request).send().await?;
    let publish_elapsed_ms = publish_started.elapsed().as_millis();
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("cdn_publish_failed:{status}:{value}"));
    }
    let published_cursors = extract_published_cursors(&value)?;
    let retry_count = value
        .get("failedCount")
        .and_then(Value::as_u64)
        .unwrap_or(0) as usize;
    if published_cursors.len() + retry_count != request.items.len() {
        return Err(anyhow!(
            "cdn_publish_response_count_mismatch:accepted={} failed={} requested={}",
            published_cursors.len(),
            retry_count,
            request.items.len()
        ));
    }
    Ok(CdnBatchPublishOutcome {
        published_count: published_cursors.len(),
        retry_count,
        published_cursors,
        publish_elapsed_ms,
    })
}

fn extract_published_cursors(value: &Value) -> Result<BTreeSet<i64>> {
    let mut cursors = BTreeSet::new();
    let items = value
        .get("items")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("cdn_publish_items_missing"))?;
    for item in items {
        let cursor = item
            .get("publicationCursor")
            .and_then(Value::as_i64)
            .ok_or_else(|| anyhow!("cdn_publish_item_cursor_missing"))?;
        cursors.insert(cursor);
    }
    Ok(cursors)
}

async fn mark_root_jobs_published(
    state: &AppState,
    items: &[ResourceCdnPublishBatchItem],
) -> Result<()> {
    let Some(admin_token) = state.config.root.admin_token.as_ref() else {
        return Err(anyhow!("root_admin_token_required_for_mark_published"));
    };
    let url = root_mark_published_url(
        &state.config.root.endpoint,
        &state.config.root.mark_published_path,
    )?;
    let jobs = build_mark_published_jobs(items);
    let response = state
        .client
        .post(url)
        .bearer_auth(admin_token)
        .json(&json!({ "jobs": jobs }))
        .send()
        .await?;
    let status = response.status();
    let value = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    if !status.is_success() {
        return Err(anyhow!("root_mark_published_failed:{status}:{value}"));
    }
    Ok(())
}

fn build_mark_published_jobs(items: &[ResourceCdnPublishBatchItem]) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            json!({
                "jobKey": format!("{}:{}", item.package.resource_did, item.package.package_version),
                "publicationCursor": item.publication_cursor,
                "resourceDid": item.package.resource_did,
                "packageVersion": item.package.package_version,
                "packageHash": item.package.package_hash
            })
        })
        .collect()
}

fn root_mark_published_url(root_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(root_endpoint)?;
    let path = path.trim_start_matches('/');
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("root_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn cdn_publish_batch_url(cdn_endpoint: &str, path: &str) -> Result<Url> {
    let mut url = Url::parse(cdn_endpoint)?;
    let path = path.trim_start_matches('/');
    {
        let mut segments = url
            .path_segments_mut()
            .map_err(|_| anyhow!("cdn_endpoint_cannot_be_base"))?;
        segments.pop_if_empty();
        for segment in path.split('/') {
            segments.push(segment);
        }
    }
    Ok(url)
}

fn build_cdn_batch_publish_request(
    state: &AppState,
    packages: Vec<(i64, ResourcePackage)>,
) -> Result<ResourceCdnBatchPublishRequest> {
    let items = packages
        .into_iter()
        .map(
            |(publication_cursor, package)| ResourceCdnPublishBatchItem {
                publication_cursor,
                package,
            },
        )
        .collect::<Vec<_>>();
    let verification_method = format!("{}#key-1", state.root_did);
    let envelope = create_signed_request_envelope(SignedRequestEnvelopeInput {
        request_id: request_id("resource-cdn-batch-publish"),
        protocol_version: OAN_RESOURCE_PROTOCOL_VERSION.to_owned(),
        purpose: PURPOSE_CDN_PUBLISH.to_owned(),
        method: "POST".to_owned(),
        path: PATH_CDN_RESOURCES_BATCH.to_owned(),
        aud: state.root_did.clone(),
        payload: &items,
        creator: state.root_did.clone(),
        verification_method,
        signing_key: &state.signing_key,
        nonce: request_nonce("resource-cdn-batch-publish"),
    })?;
    Ok(ResourceCdnBatchPublishRequest {
        items,
        upstream_auth: envelope,
    })
}

fn record_cycle(
    state: &AppState,
    fetched: usize,
    acked: usize,
    failed: usize,
    elapsed_ms: u128,
    metrics: PublisherCycleMetrics,
    error: Option<String>,
) {
    if let Ok(mut runtime) = state.runtime.lock() {
        runtime.last_fetched_count = fetched;
        runtime.last_acked_count = acked;
        runtime.last_failed_count = failed;
        runtime.total_acked_count = runtime.total_acked_count.saturating_add(acked as u64);
        runtime.total_failed_count = runtime.total_failed_count.saturating_add(failed as u64);
        runtime.last_elapsed_ms = elapsed_ms;
        runtime.last_fetch_elapsed_ms = metrics.fetch_elapsed_ms;
        runtime.last_prepare_elapsed_ms = metrics
            .root_fetch_elapsed_ms
            .saturating_add(metrics.binding_elapsed_ms);
        runtime.last_publish_elapsed_ms = metrics.publish_elapsed_ms;
        runtime.last_callback_elapsed_ms = metrics.callback_elapsed_ms;
        runtime.last_ack_elapsed_ms = metrics.ack_elapsed_ms;
        runtime.last_effective_batch_size = metrics.effective_batch_size;
        runtime.last_ack_concurrency = metrics.ack_concurrency;
        runtime.fetch_stage = metrics.fetch_stage;
        runtime.root_fetch_stage = metrics.root_fetch_stage;
        runtime.binding_stage = metrics.binding_stage;
        runtime.cdn_publish_stage = metrics.cdn_publish_stage;
        runtime.root_callback_stage = metrics.root_callback_stage;
        runtime.ack_stage = metrics.ack_stage;
        if error.is_some() {
            runtime.last_error = error;
        }
        runtime.updated_at = Some(Utc::now());
    }
}

