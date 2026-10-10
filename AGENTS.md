# NDS vault working contract

Public AGPL-3.0-only NDDev OpenNetwork module. Read standarts.lock and the pinned
engineering, identity, sync and telemetry contracts. Domain/application rules
stay in core; this module owns native authenticated encryption, bounded local
durability and trusted-device key transfer adapters. Native keys never enter
metadata databases, FFI, telemetry or server state. Never overwrite existing
keys to hide an uncertain outcome. No backup/recovery or implicit key rotation.
Existing tools own their data and safety rules. Never access protected RDS stores.
Use real cryptographic/native/store/backend acceptance and the approved signed
branch -> dev -> main workflow. Report the platforms actually exercised.
