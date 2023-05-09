//! Support for pruning leaf nodes from the merkle trie.
use casper_hashing::Digest;
use casper_types::Key;

/// The result of performing a prune.
#[derive(Debug, Clone)]
pub enum PruneResult {
    /// Root not found.
    RootNotFound,
    /// Key does not exists.
    DoesNotExist,
    /// New state root hash generated after elements were pruned.
    Success {
        /// State root hash.
        post_state_hash: Digest,
    },
}

/// Represents the configuration of a prune operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneConfig {
    pre_state_hash: Digest,
    keys_to_prune: Vec<Key>,
}

impl PruneConfig {
    /// Create new prune config.
    pub fn new(pre_state_hash: Digest, keys_to_prune: Vec<Key>) -> Self {
        PruneConfig {
            pre_state_hash,
            keys_to_prune,
        }
    }

    /// Returns the current state root state hash
    pub fn pre_state_hash(&self) -> Digest {
        self.pre_state_hash
    }

    /// Returns the list of keys to delete.
    pub fn keys_to_prune(&self) -> &[Key] {
        &self.keys_to_prune
    }
}
