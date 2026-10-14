use super::*;

impl Journal {
    pub(super) fn initialize(&self) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        if object_kind(&tx, "v3_meta")?.as_deref() == Some("table") {
            check_version(&tx)?;
            for name in [
                "meta",
                "replica_meta",
                "replica_outbox",
                "replica_entities",
                "replica_conflicts",
                "local_entities",
            ] {
                if object_kind(&tx, name)?.as_deref() != Some("view") {
                    return Err(Error::Invalid);
                }
            }
            for name in [
                "v3_outbox",
                "v3_entities",
                "v3_conflicts",
                "checkpoint_meta",
                "checkpoint_rows",
            ] {
                if object_kind(&tx, name)?.as_deref() != Some("table") {
                    return Err(Error::Invalid);
                }
            }
            let has_resolution: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pragma_table_info('checkpoint_rows') WHERE name='legacy_resolved')",
                    [],
                    |r| r.get(0),
                )
                .map_err(sql_failed)?;
            if !has_resolution {
                return Err(Error::Invalid);
            }
            return tx.commit().map_err(sql_failed);
        }
        match object_kind(&tx, "replica_meta")?.as_deref() {
            Some("table") => {
                let version: u32 = tx
                    .query_row(
                        "SELECT schema_version FROM replica_meta WHERE singleton=1",
                        [],
                        |r| r.get(0),
                    )
                    .map_err(sql_failed)?;
                if version != 6 {
                    return Err(Error::Invalid);
                }
                if object_kind(&tx, "meta")?.as_deref() != Some("view") {
                    return Err(Error::Invalid);
                }
                for name in ["outbox", "entities", "conflicts"] {
                    if object_kind(&tx, name)?.is_some() {
                        return Err(Error::Invalid);
                    }
                }
                for name in [
                    "replica_outbox",
                    "replica_entities",
                    "replica_conflicts",
                    "local_entities",
                ] {
                    let expected = if name == "local_entities" {
                        "view"
                    } else {
                        "table"
                    };
                    if object_kind(&tx, name)?.as_deref() != Some(expected) {
                        return Err(Error::Invalid);
                    }
                }
                migrate_v3(&tx, true)?;
                return tx.commit().map_err(sql_failed);
            }
            Some(_) => return Err(Error::Invalid),
            None => {}
        }
        let inherited_legacy = object_kind(&tx, "meta")?.as_deref() == Some("table");
        match object_kind(&tx, "meta")?.as_deref() {
            Some("table") => {
                let version: u32 = tx
                    .query_row(
                        "SELECT schema_version FROM meta WHERE singleton=1",
                        [],
                        |row| row.get(0),
                    )
                    .map_err(sql_failed)?;
                if !(1..=5).contains(&version) {
                    return Err(Error::Invalid);
                }
                for name in ["outbox", "entities", "conflicts"] {
                    if object_kind(&tx, name)?.as_deref() != Some("table") {
                        return Err(Error::Invalid);
                    }
                }
            }
            Some(_) => return Err(Error::Invalid),
            None => {
                let tables: u32 = tx.query_row("SELECT count(*) FROM sqlite_schema WHERE type='table' AND name NOT LIKE 'sqlite_%'", [], |row| row.get(0)).map_err(sql_failed)?;
                if tables != 0 {
                    return Err(Error::Invalid);
                }
            }
        }
        tx.execute_batch("CREATE TABLE IF NOT EXISTS meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),schema_version INTEGER NOT NULL,cursor INTEGER NOT NULL DEFAULT 0 CHECK(cursor BETWEEN 0 AND 9007199254740991));
            INSERT OR IGNORE INTO meta(singleton,schema_version) VALUES(1,1);
            CREATE TABLE IF NOT EXISTS outbox(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),state TEXT NOT NULL CHECK(state IN ('pending','conflict')));
            CREATE TABLE IF NOT EXISTS entities(kind TEXT NOT NULL,id TEXT NOT NULL,revision INTEGER NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),PRIMARY KEY(kind,id));
            CREATE TABLE IF NOT EXISTS conflicts(id TEXT PRIMARY KEY,kind TEXT NOT NULL,entity_id TEXT NOT NULL,body BLOB NOT NULL CHECK(length(body)<=24576),result BLOB NOT NULL);").map_err(sql_failed)?;
        let mut version: u32 = tx
            .query_row(
                "SELECT schema_version FROM meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .map_err(sql_failed)?;
        if version == 1 {
            tx.execute_batch("ALTER TABLE entities ADD COLUMN server_seq INTEGER NOT NULL DEFAULT 0 CHECK(server_seq BETWEEN 0 AND 9007199254740991); UPDATE meta SET schema_version=2,cursor=0 WHERE singleton=1;").map_err(sql_failed)?;
            version = 2;
        }
        if version == 2 {
            // An old pending operation may already have reached the server. It
            // must remain immutable until its original receipt is reconciled.
            tx.execute_batch("ALTER TABLE outbox ADD COLUMN dispatched INTEGER NOT NULL DEFAULT 1 CHECK(dispatched IN (0,1));
                ALTER TABLE outbox ADD COLUMN predecessor TEXT;
                ALTER TABLE meta ADD COLUMN last_sync_at INTEGER NOT NULL DEFAULT 0 CHECK(last_sync_at>=0);
                DROP INDEX IF EXISTS outbox_entity_pending;
                CREATE UNIQUE INDEX outbox_unsent ON outbox(kind,entity_id) WHERE dispatched=0;
                CREATE UNIQUE INDEX outbox_dispatched ON outbox(kind,entity_id) WHERE dispatched=1;
                CREATE INDEX conflict_entity ON conflicts(kind,entity_id);
                UPDATE meta SET schema_version=3 WHERE singleton=1;").map_err(sql_failed)?;
            version = 3;
        }
        if version == 3 {
            tx.execute_batch("ALTER TABLE meta ADD COLUMN local_revision INTEGER NOT NULL DEFAULT 0 CHECK(local_revision BETWEEN 0 AND 9007199254740991); UPDATE meta SET schema_version=4 WHERE singleton=1;").map_err(sql_failed)?;
            version = 4;
        }
        if version == 4 {
            // Conflict IDs are internal storage keys. Preserve every retained
            // body/receipt and cursor while namespacing existing IDs by device.
            // No table rebuild or outbox rewrite is needed. Version the changed
            // key semantics so older clients cannot reopen this journal.
            tx.execute_batch("UPDATE conflicts SET id=json_array(json_extract(CAST(body AS TEXT),'$.device_id'),json_extract(CAST(body AS TEXT),'$.operation_id')); UPDATE meta SET schema_version=5 WHERE singleton=1;").map_err(sql_failed)?;
            version = 5;
        }
        if version != 5 {
            return Err(Error::Invalid);
        }
        // Rename the private mutation boundary atomically. Cached legacy writers
        // cannot reach these tables. The read-only meta sentinel also prevents
        // legacy bootstrap from creating a second empty journal alongside them.
        tx.execute_batch("ALTER TABLE meta RENAME TO replica_meta;
            ALTER TABLE outbox RENAME TO replica_outbox;
            ALTER TABLE entities RENAME TO replica_entities;
            ALTER TABLE conflicts RENAME TO replica_conflicts;
            CREATE VIEW meta AS SELECT singleton,schema_version,cursor,last_sync_at,local_revision FROM replica_meta;").map_err(sql_failed)?;
        tx.execute(
            "UPDATE replica_meta SET schema_version=?1 WHERE singleton=1",
            [6],
        )
        .map_err(sql_failed)?;
        // One bounded projection owns local read-your-writes. Server revision
        // and pending operation identity stay separate; neither invents a commit.
        tx.execute_batch("CREATE VIEW IF NOT EXISTS local_entities AS
            SELECT k.kind,k.id,COALESCE(e.revision,0) AS revision,
                CASE WHEN EXISTS(SELECT 1 FROM replica_conflicts c WHERE c.kind=k.kind AND c.entity_id=k.id) OR p.state='conflict'
                     THEN COALESCE(e.body,p.body) ELSE COALESCE(p.body,e.body) END AS body,
                COALESCE(e.server_seq,0) AS server_seq,
                EXISTS(SELECT 1 FROM replica_conflicts c WHERE c.kind=k.kind AND c.entity_id=k.id) OR COALESCE(p.state='conflict',0) AS conflicted,
                p.id AS pending_id,
                CASE WHEN p.state='pending' THEN json_extract(CAST(p.body AS TEXT),'$.base_revision')+p.dispatched
                     ELSE COALESCE(e.revision,0) END AS next_base
            FROM (SELECT kind,id FROM replica_entities UNION SELECT kind,entity_id AS id FROM replica_outbox) k
            LEFT JOIN replica_entities e ON e.kind=k.kind AND e.id=k.id
            LEFT JOIN replica_outbox p ON p.rowid=(SELECT MAX(o.rowid) FROM replica_outbox o WHERE o.kind=k.kind AND o.entity_id=k.id);").map_err(sql_failed)?;
        migrate_v3(&tx, inherited_legacy)?;
        tx.commit().map_err(sql_failed)
    }
}

fn migrate_v3(tx: &rusqlite::Transaction<'_>, inherited_legacy: bool) -> Result<(), Error> {
    // Renames and sentinels share the existing owner's IMMEDIATE transaction.
    // No legacy writer can address a writable old table after this commit.
    tx.execute_batch("DROP VIEW meta;
        ALTER TABLE replica_meta RENAME TO v3_meta;
        ALTER TABLE replica_outbox RENAME TO v3_outbox;
        ALTER TABLE replica_entities RENAME TO v3_entities;
        ALTER TABLE replica_conflicts RENAME TO v3_conflicts;
        ALTER TABLE v3_meta ADD COLUMN legacy_v2_context INTEGER NOT NULL DEFAULT 0 CHECK(legacy_v2_context IN (0,1));
        ALTER TABLE v3_meta ADD COLUMN writer_mode INTEGER CHECK(writer_mode IS NULL OR writer_mode IN (2,3));
        ALTER TABLE v3_meta ADD COLUMN writer_key_id TEXT;
        ALTER TABLE v3_meta ADD COLUMN confirmed_basis_seq INTEGER CHECK(confirmed_basis_seq IS NULL OR confirmed_basis_seq BETWEEN 0 AND 9007199254740991);
        ALTER TABLE v3_outbox ADD COLUMN terminal_unknown_reason TEXT CHECK(terminal_unknown_reason IS NULL OR terminal_unknown_reason IN ('basis_expired','legacy_missing'));
        ALTER TABLE v3_meta ADD COLUMN known_committed_seq INTEGER NOT NULL DEFAULT 0 CHECK(known_committed_seq BETWEEN 0 AND 9007199254740991);
        ALTER TABLE v3_entities ADD COLUMN receipt_body BLOB CHECK(receipt_body IS NULL OR length(receipt_body) BETWEEN 1 AND 2048);
        ALTER TABLE v3_entities ADD COLUMN receipt_status INTEGER CHECK(receipt_status IS NULL OR receipt_status=201);
        UPDATE v3_meta SET schema_version=7,known_committed_seq=MAX(cursor,COALESCE((SELECT MAX(server_seq) FROM v3_entities),0),COALESCE((SELECT MAX(json_extract(CAST(result AS TEXT),'$.server_seq')) FROM v3_conflicts),0)) WHERE singleton=1;
        CREATE VIEW replica_meta AS SELECT singleton,schema_version,cursor,last_sync_at,local_revision FROM v3_meta;
        CREATE VIEW meta AS SELECT * FROM replica_meta;
        CREATE VIEW replica_outbox AS SELECT rowid AS rowid,* FROM v3_outbox;
        CREATE VIEW replica_entities AS SELECT kind,id,revision,body,server_seq FROM v3_entities;
        CREATE VIEW replica_conflicts AS SELECT rowid AS rowid,* FROM v3_conflicts;
        CREATE TABLE checkpoint_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
            stage_id TEXT NOT NULL,scope_tag TEXT NOT NULL,key_id TEXT NOT NULL,
            expected_cursor INTEGER NOT NULL,expected_local INTEGER NOT NULL,expected_known INTEGER NOT NULL,
            base_seq INTEGER NOT NULL,total_members INTEGER NOT NULL,received INTEGER NOT NULL DEFAULT 0,
            after_member INTEGER NOT NULL DEFAULT 0,through_seq INTEGER NOT NULL,tail_complete INTEGER NOT NULL DEFAULT 0 CHECK(tail_complete IN (0,1)));
        CREATE TABLE checkpoint_rows(server_seq INTEGER PRIMARY KEY CHECK(server_seq BETWEEN 1 AND 9007199254740991),
            body BLOB NOT NULL CHECK(length(body) BETWEEN 1 AND 24576),
            result BLOB NOT NULL CHECK(length(result) BETWEEN 1 AND 2048),status INTEGER NOT NULL CHECK(status IN (201,409)),
            legacy_resolved INTEGER NOT NULL CHECK(legacy_resolved BETWEEN 0 AND 9007199254740991));"
    ).map_err(sql_failed)?;
    tx.execute(
        "UPDATE v3_meta SET legacy_v2_context=?1 WHERE singleton=1",
        [inherited_legacy],
    )
    .map_err(sql_failed)?;
    Ok(())
}

fn object_kind(connection: &Connection, name: &str) -> Result<Option<String>, Error> {
    connection
        .query_row(
            "SELECT type FROM sqlite_schema WHERE name=?1",
            [name],
            |row| row.get(0),
        )
        .optional()
        .map_err(sql_failed)
}
