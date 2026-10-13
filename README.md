# nddev-device-sync-vault

Encrypted native and browser replica adapters for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only. Rust owns automatic server-managed key provisioning, authenticated record encryption and durable ciphertext queues; presentation receives state and record labels only.

AES-256-GCM binds ciphertext to owner, origin, entity, operation and revision. After authentication and device enrollment, the client receives its established owner key through signed HTTPS and retains it in the platform credential adapter. Native clients use the OS credential store; the browser wraps local key material with its non-extractable WebCrypto key in IndexedDB. An existing local key registers once without replacement. The server has decryption authority under ADR 0006; this is not client-only E2EE. No backup, recovery or implicit rotation exists.

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

Browser builds run the same Rust journal SQL in a dedicated worker backed by
OPFS SAH-pool storage. A Web Lock covers each transaction and VFS handle lifetime;
the connection closes and VFS pauses before release. There is no memory-only
fallback. The composition root configures same-origin worker/module assets and
exports the four functions documented in `src/browser.rs`; no plaintext or keys
cross the journal command boundary. `just wasm-check` is a compile gate.

Schema 3 preserves legacy outbox bytes as potentially dispatched. New unsent
edits are visible locally and may be replaced only using the displayed
`pending_id` together with the committed revision. Once claimed for transport,
an operation is immutable; later edits form one coalescible successor. A server
conflict blocks that successor and preserves its latest intent for explicit
resolution. Both append receipts and inbox replay release successors atomically.
The queue stays bounded at 1024 operations. Refresh reads last complete sync time
from durable metadata; offline access retains the original authorization expiry.
Schema 4 adds a durable local mutation counter for presentation refresh across
tabs/processes, independent of the server cursor. Schema 5 scopes internal
conflict keys by device and operation, retaining ciphertext and receipts in
place. Append acknowledgement checks the exact claimed request; inbox settlement
checks every operation field, including the device. Stop older clients/tabs
before upgrading their shared journal; do not downgrade it. The migration does
not restore records previously discarded by an older client.

Browser qualification must exercise the actual composition root, credentials,
worker restart, cross-tab writes and storage eviction/quota behavior. Browser
profile storage may be evicted unless the browser grants persistence. The client
requests that preference at startup and reports the observed result; it never
claims protection from explicit site-data removal. Admission allows at most
four concurrent storage calls, with a 500 ms wait for the connection; local
acknowledgement is a completed storage transaction, not a cloud acknowledgement.
