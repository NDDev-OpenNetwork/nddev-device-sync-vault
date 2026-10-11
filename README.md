# nddev-device-sync-vault

Native encrypted replica adapters for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only. Rust owns automatic server-managed key provisioning, authenticated record encryption and durable ciphertext queues; presentation receives state and record labels only.

AES-256-GCM binds ciphertext to owner, origin, entity, operation and revision. After authentication and device enrollment, the native client receives its established owner key through signed HTTPS and retains it in the native credential store. An existing local key registers once without replacement. The server has decryption authority under ADR 0006; this is not client-only E2EE. No backup, recovery or implicit rotation exists.

SQLite stores ciphertext, revisions, pending operations and explicit conflicts. A mutation is durable before local acknowledgement; network retries preserve exact bytes with fresh HTTP signatures. Inbox cursors advance in the same transaction as their retained entries. Queues, pages, storage and worker admission are bounded. Partial batches expose `catching_up`; only a fully caught-up observation advances `last_sync_at`.

Run `just check`. The ignored native acceptance requires an explicitly started isolated PostgreSQL/Mailpit fixture and unlocked native credential service; set `NDS_FIXTURE_RECEIPT` and run `just native-acceptance`. Host checks do not prove another platform's secure-store or UI behavior.

Vault record lists use 50-entity keyset pages with explicit continuation, including
pages containing only tombstones. Records expose their observed revision/cursor
and the latest conflicting edit's metadata. Native secret use rejects conflicts;
explicit resolution chooses the committed or conflicting value and commits a
version 2 encrypted record with a resolution watermark. Only an applied decision
clears observed conflicts transactionally; later competing changes remain visible.
Edits and deletion require the displayed revision, and resolution also requires
the displayed replica cursor. Deleted records with conflicts remain resolvable.

Version 1 ciphertext stays readable and ordinary writes keep that payload shape.
Upgrade native consumers before using version 2 resolution; older locked clients
cannot interpret its watermark. Keys and server history are never replaced.
Every incoming page is authenticated/decrypted and its typed payload validated
before records or cursor advance. A damaged page leaves both cursor and caught-up
time unchanged. The native acceptance covers 154 records across page boundaries,
deleted-record conflicts, both resolution choices and an actual corrupt server
entry; it runs only against its disposable fixture.
