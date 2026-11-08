# OAN Root Services

Root-side service workspace for OpenAgenet (OAN), an open infrastructure
project for the Internet of Agents (IoA). This repository implements the Root,
CDN, and publication worker services that turn Registrar-accepted resources into
Root-approved, distributed, and Discovery-indexable OAN resource packages.

This repository owns:

- `root-node`
- `cdn-node`
- `cdn-publisher`

Shared protocol, crypto, storage, service-security, and publication event
crates live in the sibling `oan-protocol-common` repository.

## Service Roles

- `root-node`: the OAN authorization, data distribution, and semantic
  governance hub. It verifies Registrar-submitted resource packages, records
  versions, maintains publication queues, exposes Registrar and Discovery node
  authorization views, and serves the capability tree used by registration and
  discovery assistance.
- `cdn-node`: stores and serves Root-approved resource packages, DID documents,
  metadata, resource indexes, and publish history for Discovery nodes and public
  clients.
- `cdn-publisher`: worker process that fetches prepared publication jobs from
  Root and publishes package batches into CDN.

Key public or service-facing routes include:

- Root:
  - `GET /health`
  - `GET /root/did`
  - `GET /bulletin`
  - `GET /root/status`
  - `GET /root/registrars`
  - `GET /root/discovery-nodes`
  - `GET /root/resources/{did}`
  - `GET /root/resources/{did}/versions`
  - `GET /root/capability-tree`
  - `GET /root/bulletin/events`
- CDN:
  - `GET /health`
  - `GET /cdn/status`
  - `GET /cdn/resources/{did}`
  - `POST /cdn/resources/batch-get`
  - `GET /cdn/resources/index`
  - `GET /cdn/documents/{did}`
  - `GET /cdn/metadata/{did}`
  - `GET /cdn/catalog/resources`
  - `GET /cdn/catalog/resources/stats`
- Publisher:
  - `GET /health`
  - `GET /status`

For public browser workflows, selected Root/CDN status and resource routes are
exposed through the official website gateway at `https://www.openagenet.xyz`.

## Local Checks

```powershell
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace -j 1
```

Full-network integration tests, deployment gates, and benchmarks are maintained
separately by official operators. Service-node identity material should be
provided by the operator for each deployment; this repository does not own
private node identity material.

## License

This core service repository is licensed under `Apache-2.0`. Brand and
official-node identity rights are reserved separately.


## Typed configuration and offline checks

The service loads one UTF-8 TOML file. Precedence is code defaults, TOML,
legacy database-pool environment variables (where applicable), then `OAN_ROOT__...`
scalar environment overrides. `--config` selects the file; it does not silently
create one when missing. Unknown fields, duplicate aliases, invalid types and
invalid runtime capacities are rejected. Configuration changes require restart.

```text
root-node --config services/root-node/config.example.toml check-config
root-node --config services/root-node/config.example.toml print-effective-config
```

These commands run without starting Tokio, opening a database, reading identity
material, connecting upstream, creating directories or writing runtime state.
The effective-config command prints redacted JSON plus per-field sources;
it is for inspection, not a round-trippable deployment file. URLs/endpoints and
tokens are hidden. Preserve the original protected configuration for deployment.

The old positional config path remains accepted. Relative paths remain based on
the configuration directory. `OAN_ROOT__RUNTIME__DID_VERIFICATION__WORKER_COUNT=4`
is an example override, not the default. Omitted verification settings retain
6 workers, a bounded queue of 12, and 16 MiB worker stacks. Tokio retains an
8 MiB stack; omitted Tokio worker/blocking counts retain runtime defaults.

`[database.pool]` supports `max_connections` and `acquire_timeout_seconds`.
PostgreSQL additionally supports `idle_timeout_seconds` and
`max_lifetime_seconds`. Defaults remain PostgreSQL 8 / SQLite 32 connections,
30 seconds acquisition timeout, and PostgreSQL idle/lifetime 30/300 seconds.
Existing `OAN_POSTGRES_*` / `OAN_SQLITE_*` pool variables remain compatible;
module-prefixed overrides take precedence. The backend still comes exclusively
from `paths.database_url`; an absent/empty URL retains file storage.

Remove previously unused `[node]` sections before enabling strict checks.
Arrays remain TOML-only; environment list splitting is not supported.
No identities, credentials, business records, nonce state or indexes are migrated.

Root nonce SQLite remains independent of `[database.pool]`. CDN/Publisher keep their existing configuration and storage entry points.
