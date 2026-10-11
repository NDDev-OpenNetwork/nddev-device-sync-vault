# NDS vault working contract

Public AGPL-3.0-only NDDev OpenNetwork module. Read standarts.lock and the pinned
engineering, identity, sync and telemetry contracts. Domain/application rules
stay in core; this module owns native authenticated encryption, bounded local
durability and automatic server-managed key provisioning adapters. Native unwrapped keys
never enter metadata databases, FFI or telemetry; server envelopes are protected
by a wrapping key outside PostgreSQL under ADR 0006. Never overwrite existing
keys to hide an uncertain outcome. No backup/recovery or implicit key rotation.
Existing tools own their data and safety rules. Never access protected RDS stores.
Use real cryptographic/native/store/backend acceptance and the approved signed
branch -> dev -> main workflow. Report the platforms actually exercised.
