# nddev-device-sync-vault

Native E2EE and local synchronization adapters for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only. Rust owns keys, authenticated encryption, trusted-device pairing and durable ciphertext queues; presentation receives public state and record labels only.

AES-256-GCM binds ciphertext to owner, origin, entity, operation and revision context. Five-minute, one-use X25519/HKDF pairing invitations and wrapped responses can be transferred by QR/code after explicit trusted-device confirmation. The server receives no decryption material. Existing native key entries are retained; no backup, recovery or implicit rotation exists.

SQLite stores ciphertext, revisions, pending operations and explicit conflicts. A mutation is durable before local acknowledgement; network retries preserve exact bytes with fresh HTTP signatures. Inbox cursors advance in the same transaction as their retained entries. Queues, pages, storage and worker admission are bounded.

Run `just check`. The ignored native acceptance requires an explicitly started isolated PostgreSQL/Mailpit fixture and unlocked native credential service; set `NDS_FIXTURE_RECEIPT` and run `just native-acceptance`. Host checks do not prove another platform's secure-store or UI behavior.
