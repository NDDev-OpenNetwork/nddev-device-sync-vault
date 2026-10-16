# nddev-device-sync-vault

Encrypted native and browser replica adapters for [NDDev OpenNetwork](https://nddev.ai), AGPL-3.0-only. Rust owns automatic server-managed key provisioning, authenticated record encryption and durable ciphertext queues; presentation receives state and record labels only.

AES-256-GCM binds ciphertext to owner, origin, entity, operation and revision. After authentication and device enrollment, the client receives its established owner key through signed HTTPS and retains it in the platform credential adapter. Native clients use the OS credential store; the browser wraps local key material with its non-extractable WebCrypto key in IndexedDB. An existing local key registers once without replacement. The server has decryption authority under ADR 0006; this is not client-only E2EE. No key backup, key recovery or implicit rotation exists.

SQLite stores ciphertext, revisions, pending operations and explicit conflicts. A mutation is durable before local acknowledgement; network retries preserve exact bytes with fresh HTTP signatures. Inbox cursors advance in the same transaction as their retained entries. Queues, pages, storage and worker admission are bounded. Partial batches expose `catching_up`; only a fully caught-up observation advances `last_sync_at`.

The core application owns one bounded replica reconciliation and checkpoint
recovery use case. This adapter supplies authenticated transport, payload
verification and whole journal transactions; it retains cryptography, key
provisioning and SQLite/OPFS execution. Transport DTOs come from Accounts,
generated from its immutable Protocol source pin.

Persisted writer facts describe the negotiated format, key and observed history;
they do not grant authorization. Recovery resumes an existing operational stage
before claiming uploads. A complete snapshot and sufficient contiguous tail may
replace the committed projection atomically while preserving exact pending and
Unknown operation families. Installation alone does not establish freshness.

`synchronize_inbox` uses that same authorized/key-prepared, admitted 60-second
batch and verified journal path without claiming or posting local operations.
Its Rust result distinguishes `inbox_at_head` from full freshness: pending work
still prevents `caught_up` and `last_sync_at` advancement. The caller retains
the core upload-capacity block and presents it independently of the current
read result. Successful reads clear read errors, not upload eligibility; real
read failures remain typed and observable. No second scheduler lives in Vault.

`probe_capacity_attempt` executes Core's bounded one-original check through the same
signed append and durable acknowledgement/Unknown path. Its distinct storage
claim cannot mark the other roots dispatched. Authenticated history metadata is
only a trigger for that check, never proof that capacity exists. A completed
probe outcome is returned before unrelated view/inbox reads can obscure it;
normal upload eligibility remains owned by Core and the shared caller's fence.
Rust attempt APIs return the result together with the history observed before
their sync permit is released, so a later batch cannot relabel an earlier refusal.

`native_secret_at` and `ensure_record_current` use the same protected key,
admission and journal/decode path as `native_secret`. The canonical Core
`CredentialSelection` binds the record ref, committed revision and exact current
pending operation ID; a replacement unsent edit can be stale at the same
revision. Missing/deleted/conflicted/stale selections return `SelectionChanged`;
admission remains `Busy`, and corrupt input retains its existing `Invalid` or
`Authentication` class. Legacy `native_secret(id)` retains its existing errors.
Unauthorized selections deny use. Rust
callers recheck around external awaits together with the Accounts local-use
fence and their cancellation lifetime; no secret or durable guard enters FFI.

The Rust catalog caller captures repository baselines before provider I/O with
its original Accounts fence, selected record and cancellation token. Publication
reuses Core's semantic comparison and the ordinary encrypted writer. Source
selection, ciphertext, writer facts and target revision are checked together in
the enqueue transaction. Core's 32-operation catalog window is enforced there;
unchanged facts produce no write, and stale/conflicted targets require a fresh
provider read. This API does not itself run a catalog scan, resolve conflicts or
synchronize Git repositories. A dispatched transaction retains its completion
owner after its caller stops waiting.

Saved catalog reads use local authorization and the retained Vault key without
calling GitHub or resolving a GitHub credential. Each bounded repository page
joins only its referenced owner observations under the existing local revision;
a concurrent mutation returns Busy for a fresh read. Missing owner records stay
absent. The opaque continuation is replica-scoped; every page reports its own
observed cursor/revision and original timestamps, not current provider freshness.

Run `just check`. The ignored native acceptance requires an explicitly started isolated PostgreSQL/Mailpit fixture and unlocked native credential service; set `NDS_FIXTURE_RECEIPT` and run `just native-acceptance`. Host checks do not prove another platform's secure-store or UI behavior.

Vault record lists use 50-entity keyset pages with explicit continuation, including
pages containing only tombstones. Records expose their observed revision/cursor
and the latest conflicting edit's metadata. Native secret use rejects conflicts;
explicit resolution chooses the committed or conflicting value using the Core
rule for actual observed conflicts. Only an applied decision clears those
conflicts transactionally; later competing changes remain visible.
Edits and deletion require the displayed revision, and resolution also requires
the displayed replica cursor. Deleted records with conflicts remain resolvable.

Existing ciphertext remains readable with its original authenticated metadata.
New writes use the negotiated format. Ordinary edits preserve a verified
committed legacy decision; transition to the current format is bounded by its
actual prior commit and occurs before encrypting a new operation. Retained or
dispatched originals are never rewritten. This does not reconstruct decisions
that an earlier write had already omitted from the committed payload.
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

New unsent
edits are visible locally and may be replaced only using the displayed
`pending_id` together with the committed revision. Once claimed for transport,
an operation is immutable; later edits form one coalescible successor. A server
conflict blocks that successor and preserves its latest intent for explicit
resolution. Both append receipts and inbox replay release successors atomically.
The queue stays bounded at 1024 operations. Refresh reads last complete sync time
from durable metadata; offline access retains the original authorization expiry.
The durable local mutation counter supports presentation refresh across
tabs/processes independently of the server cursor. Conflict keys include both
device and operation. Append acknowledgement checks the exact claimed request; inbox settlement
checks every operation field, including the device. Stop older clients/tabs
before upgrading their shared journal; do not downgrade it. The migration does
not restore records previously discarded by an older client.

The current journal schema is 7. Its forward migration preserves original rows,
IDs, ciphertext, receipts, pending chains and cursors. Read-only legacy views
prevent old bootstrap and writers from creating a parallel journal. Current
reads and writes recheck the supported version inside their transaction;
unknown stores fail closed. Writer facts, terminal Unknown reasons and checkpoint
staging remain in that same database. Browser commands execute the same Rust
journal under their Web Lock. Upgrade consumers together and preserve active
drafts while replacing old processes and tabs.

Browser qualification must exercise the actual composition root, credentials,
worker restart, cross-tab writes and storage eviction/quota behavior. Browser
profile storage may be evicted unless the browser grants persistence. The client
requests that preference at startup and reports the observed result; it never
claims protection from explicit site-data removal. Admission allows at most
four concurrent storage calls, with a 500 ms wait for the connection; local
acknowledgement is a completed storage transaction, not a cloud acknowledgement.

Direct and transitive NDS dependencies use canonical immutable Git sources.
Consuming applications verify one Core/Accounts/Vault package graph; dependency
updates must preserve that agreement without consumer-only source overrides.

Repository conflict capture retains the actual committed observation, latest
conflict original/receipt and any undispatched local intent after reopen. All
scoped receipts contribute to the existing resolution lifecycle; cursor values
are not substituted for witnesses. Dispatched families are refused until their
real outcome is known. Captured evidence does not itself resolve or delete a
conflict. `resolve_repository_observation` confirms fresh provider input through
Core, then queues a new operation against the observed committed revision. Its
separate storage command rechecks source, writer and a fingerprint of the exact
committed bytes, target metadata, pending operation/dispatch/lineage and every
scoped conflict request/receipt in one transaction. Unrelated writes and forward
history do not invalidate that proof; rollback or any family change does. Older
workers reject the new command instead of ignoring its required fingerprint.
Ordinary Vault record choices retain their existing global revision guard.
The old conflict survives queueing/reopen
and another Conflict receipt; only the actual Applied receipt retires it.
Blocked undispatched intents without a server receipt use the same explicit
fresh-read transition, preserving the committed lifecycle without inventing a
receipt or deriving it from the cursor. The automatic catalog caller has not
yet adopted resolution.
