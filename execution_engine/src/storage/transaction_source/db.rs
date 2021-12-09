use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use filesize::PathExt;
use lmdb::{
    self, Database, Environment, EnvironmentFlags, RoTransaction, RwTransaction, WriteFlags,
};
use rocksdb::{BoundColumnFamily, DBWithThreadMode, MultiThreaded};
use tracing::info;

use crate::{
    rocksdb_defaults,
    storage::{
        error,
        transaction_source::{Readable, Transaction, TransactionSource, Writable},
        MAX_DBS,
    },
};
use casper_types::bytesrepr::Bytes;

/// Filename for the LMDB database created by the EE.
const EE_LMDB_FILENAME: &str = "data.lmdb";
const MIGRATION_COLUMN_FAMILY: &str = "migration_lmdb_state_roots";

/// newtype over alt db.
#[derive(Clone)]
pub struct RocksDb {
    pub(crate) db: Arc<DBWithThreadMode<MultiThreaded>>,
}

impl RocksDb {
    /// Store migrated state root in a separate column family from trie data (which resides in the
    /// default cf)
    pub fn store_migrated_state_root(&self, state_root: &[u8]) -> Result<(), error::Error> {
        self.db
            .put_cf(&self.migration_column_family()?, state_root, &[])
            .map_err(Into::into)
    }

    /// Opens a handle to the migration column family, creating it first if needed.
    fn migration_column_family(&self) -> Result<Arc<BoundColumnFamily>, error::Error> {
        let cf = match self.db.cf_handle(MIGRATION_COLUMN_FAMILY) {
            Some(cf) => cf,
            None => {
                info!(
                    "creating column family {} for migration",
                    MIGRATION_COLUMN_FAMILY
                );
                self.db
                    .create_cf(MIGRATION_COLUMN_FAMILY, &rocksdb_defaults())?;
                match self.db.cf_handle(MIGRATION_COLUMN_FAMILY) {
                    Some(cf) => cf,
                    None => {
                        return Err(error::Error::UnableToCreateColumnFamily(format!(
                            "unable to open column family {}",
                            MIGRATION_COLUMN_FAMILY
                        )))
                    }
                }
            }
        };
        Ok(cf)
    }

    /// Check if a state root has been marked as migrated from lmdb to rocksdb.
    pub fn is_state_root_migrated(&self, state_root: &[u8]) -> Result<bool, error::Error> {
        Ok(self
            .db
            .get_cf(&self.migration_column_family()?, state_root)?
            .is_some())
    }
}

impl Transaction for RocksDb {
    type Error = rocksdb::Error;

    type Handle = RocksDb;

    fn commit(self) -> Result<(), Self::Error> {
        // NO OP as rockdb doesn't use transactions.
        Ok(())
    }
}

impl Readable for RocksDb {
    fn read(&self, _handle: Self::Handle, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        Ok(self.db.get(key)?.map(|some| {
            let value = some.as_ref();
            Bytes::from(value)
        }))
    }
}

impl Writable for RocksDb {
    fn write(
        &mut self,
        _handle: Self::Handle,
        key: &[u8],
        value: &[u8],
    ) -> Result<(), Self::Error> {
        let _result = self.db.put(key, value)?;
        Ok(())
    }
}

/// Environment for rocksdb.
#[derive(Clone)]
pub struct RocksDbStore {
    pub(crate) rocksdb: RocksDb,
    pub(crate) path: PathBuf,
}

impl RocksDbStore {
    /// Create a new environment for alternative db.
    pub fn new(
        path: impl AsRef<Path>,
        rocksdb_opts: rocksdb::Options,
    ) -> Result<RocksDbStore, rocksdb::Error> {
        let db = Arc::new(rocksdb::DBWithThreadMode::<MultiThreaded>::open_cf(
            &rocksdb_opts,
            path.as_ref(),
            vec!["default", MIGRATION_COLUMN_FAMILY],
        )?);

        let rocksdb = RocksDb { db };

        Ok(RocksDbStore {
            rocksdb,
            path: path.as_ref().to_path_buf(),
        })
    }

    /// Returns the file size on disk of rocksdb.
    pub fn disk_size_in_bytes(&self) -> usize {
        let mut total = 0;
        for entry in walkdir::WalkDir::new(&self.path)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.metadata().unwrap().is_file() {
                total += entry.path().size_on_disk().unwrap() as usize;
            }
        }
        total
    }
}

// TODO: remove this abstraction entirely when we've moved from lmdb to rocksdb for global state.

impl<'a> TransactionSource<'a> for RocksDbStore {
    type Error = rocksdb::Error;

    type Handle = RocksDb;

    type ReadTransaction = RocksDb;

    type ReadWriteTransaction = RocksDb;

    fn create_read_txn(&'a self) -> Result<Self::ReadTransaction, Self::Error> {
        Ok(self.rocksdb.clone())
    }

    fn create_read_write_txn(&'a self) -> Result<Self::ReadWriteTransaction, Self::Error> {
        Ok(self.rocksdb.clone())
    }
}

impl<'a> Transaction for RoTransaction<'a> {
    type Error = lmdb::Error;

    type Handle = Database;

    fn commit(self) -> Result<(), Self::Error> {
        lmdb::Transaction::commit(self)
    }
}

impl<'a> Readable for RoTransaction<'a> {
    fn read(&self, handle: Self::Handle, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        match lmdb::Transaction::get(self, handle, &key) {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<'a> Transaction for RwTransaction<'a> {
    type Error = lmdb::Error;

    type Handle = Database;

    fn commit(self) -> Result<(), Self::Error> {
        <RwTransaction<'a> as lmdb::Transaction>::commit(self)
    }
}

impl<'a> Readable for RwTransaction<'a> {
    fn read(&self, handle: Self::Handle, key: &[u8]) -> Result<Option<Bytes>, Self::Error> {
        match lmdb::Transaction::get(self, handle, &key) {
            Ok(bytes) => Ok(Some(Bytes::from(bytes))),
            Err(lmdb::Error::NotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

impl<'a> Writable for RwTransaction<'a> {
    fn write(&mut self, handle: Self::Handle, key: &[u8], value: &[u8]) -> Result<(), Self::Error> {
        self.put(handle, &key, &value, WriteFlags::empty())
            .map_err(Into::into)
    }
}

/// The environment for an LMDB-backed trie store.
///
/// Wraps [`lmdb::Environment`].
#[derive(Debug)]
pub struct LmdbEnvironment {
    env: Environment,
    manual_sync_enabled: bool,
}

impl LmdbEnvironment {
    /// Constructor for `LmdbEnvironment`.
    pub fn new<P: AsRef<Path>>(
        path: P,
        map_size: usize,
        max_readers: u32,
        manual_sync_enabled: bool,
    ) -> Result<Self, error::Error> {
        let lmdb_flags = if manual_sync_enabled {
            // These options require that we manually call sync on the environment for the EE.
            EnvironmentFlags::NO_SUB_DIR
                | EnvironmentFlags::NO_READAHEAD
                | EnvironmentFlags::MAP_ASYNC
                | EnvironmentFlags::WRITE_MAP
                | EnvironmentFlags::NO_META_SYNC
        } else {
            EnvironmentFlags::NO_SUB_DIR | EnvironmentFlags::NO_READAHEAD
        };

        let env = Environment::new()
            // Set the flag to manage our own directory like in the storage component.
            .set_flags(lmdb_flags)
            .set_max_dbs(MAX_DBS)
            .set_map_size(map_size)
            .set_max_readers(max_readers)
            .open(&path.as_ref().join(EE_LMDB_FILENAME))?;
        Ok(LmdbEnvironment {
            env,
            manual_sync_enabled,
        })
    }

    /// Returns a reference to the wrapped `Environment`.
    pub fn env(&self) -> &Environment {
        &self.env
    }

    /// Returns if this environment was constructed with manual synchronization enabled.
    pub fn is_manual_sync_enabled(&self) -> bool {
        self.manual_sync_enabled
    }

    /// Manually synchronize LMDB to disk.
    pub fn sync(&self) -> Result<(), lmdb::Error> {
        self.env.sync(true)
    }
}

impl<'a> TransactionSource<'a> for LmdbEnvironment {
    type Error = lmdb::Error;

    type Handle = Database;

    type ReadTransaction = RoTransaction<'a>;

    type ReadWriteTransaction = RwTransaction<'a>;

    fn create_read_txn(&'a self) -> Result<RoTransaction<'a>, Self::Error> {
        self.env.begin_ro_txn()
    }

    fn create_read_write_txn(&'a self) -> Result<RwTransaction<'a>, Self::Error> {
        self.env.begin_rw_txn()
    }
}
