use super::*;

impl Journal {
    pub(super) fn initialize(&self) -> Result<(), Error> {
        let mut connection = self.connection()?;
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(sql_failed)?;
        match object_kind(&tx, "replica_meta")?.as_deref() {
            Some("table") => {
                check_version(&tx)?;
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
                return tx.commit().map_err(sql_failed);
            }
            Some(_) => return Err(Error::Invalid),
            None => {}
        }
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
            [SCHEMA_VERSION],
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
        tx.commit().map_err(sql_failed)
    }
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
