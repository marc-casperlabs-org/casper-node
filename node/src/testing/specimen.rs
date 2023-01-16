//! Specimen support.
//!
//! Structs implementing the specimen trait allow for specific sample instances being created, such
//! as the biggest possible.

use std::{
    collections::{BTreeMap, BTreeSet},
    iter::{self, Rev},
    net::{Ipv6Addr, SocketAddr, SocketAddrV6},
    ops::Range,
    sync::Arc,
};

use casper_execution_engine::core::engine_state::{
    executable_deploy_item::ExecutableDeployItemDiscriminants, ExecutableDeployItem,
};
use casper_hashing::Digest;
use casper_types::{
    crypto::{PublicKey, PublicKeyDiscriminants, Signature},
    AsymmetricType, DeployHash, EraId, ProtocolVersion, SemVer, SignatureDiscriminants, TimeDiff,
    Timestamp, DEPLOY_HASH_LENGTH, U512,
};
use either::Either;
use serde::Serialize;
use strum::IntoEnumIterator;

use crate::{
    components::consensus::EraReport,
    types::{
        Approval, ApprovalsHash, Block, BlockBody, BlockHash, BlockPayload, Deploy,
        DeployHashWithApprovals, DeployId, FinalitySignature, FinalitySignatureId, FinalizedBlock,
    },
};

/// The largest valid unicode codepoint that can be encoded to UTF-8.
pub(crate) const HIGHEST_UNICODE_CODEPOINT: char = '\u{10FFFF}';

/// Given a specific type instance, estimates its serialized size.
pub(crate) trait SizeEstimator {
    /// Estimate the serialized size of a value.
    fn estimate<T: Serialize>(&self, val: &T) -> usize;

    /// Retrieves a parameter.
    ///
    /// Parameters indicate potential specimens which values to expect, e.g. a maximum number of
    /// items configured for a specific collection. If `None` is returned a default should be used
    /// by the caller, or a panic produced.
    fn get_parameter(&self, name: &'static str) -> Option<i64>;

    /// Requires a parameter.
    ///
    /// Like `get_parameter`, but does not accept `None` as an answer.
    ///
    /// ##
    fn require_parameter(&self, name: &'static str) -> i64 {
        self.get_parameter(name)
            .unwrap_or_else(|| panic!("missing parameter \"{}\" for specimen estimation", name))
    }
}

/// Supports returning a maximum size specimen.
///
/// "Maximum size" refers to the instance that uses the highest amount of memory and is also most
/// likely to have the largest representation when serialized.
pub(crate) trait LargestSpecimen {
    /// Returns the largest possible specimen for this type.
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self;
}

/// Supports generating a unique sequence of specimen that are as large as possible.
pub(crate) trait LargeUniqueSequence<E>
where
    Self: Sized + Ord,
    E: SizeEstimator,
{
    /// Create a new sequence of the largest possible unique specimens.
    ///
    /// Note that multiple calls to this function will return overlapping sequences.
    // Note: This functions returns a materialized sequence instead of a generator to avoid
    //       complications with borrowing `E`.
    fn large_unique_sequence(estimator: &E, count: usize) -> BTreeSet<Self>;
}

/// Produces the largest variant of a specific `enum` using an estimator and a generation function.
pub(crate) fn largest_variant<T, D, E, F>(estimator: &E, generator: F) -> T
where
    T: Serialize,
    D: IntoEnumIterator,
    E: SizeEstimator,
    F: Fn(D) -> T,
{
    let mut candidates = vec![];
    for variant in D::iter() {
        candidates.push(generator(variant))
    }
    candidates.sort_by_key(|candidate| estimator.estimate(candidate));

    candidates
        .into_iter()
        .next()
        .expect("should have at least one candidate")
}

/// Generates a vec of a given size filled with the largest specimen.
pub(crate) fn vec_of_largest_specimen<T: LargestSpecimen, E: SizeEstimator>(
    estimator: &E,
    count: usize,
) -> Vec<T> {
    let mut vec = Vec::new();
    for _ in 0..count {
        vec.push(LargestSpecimen::largest_specimen(estimator));
    }
    vec
}

/// Generates a vec of the largest specimen, with a size from a property.
pub(crate) fn vec_prop_specimen<T: LargestSpecimen, E: SizeEstimator>(
    estimator: &E,
    parameter_name: &'static str,
) -> Vec<T> {
    let mut count = estimator.require_parameter(parameter_name);
    if count < 0 {
        count = 0;
    }

    vec_of_largest_specimen(estimator, count as usize)
}

/// Generates a `BTreeMap` with the size taken from a property.
///
/// Keys are generated uniquely using `LargeUniqueSequence`, while values will be largest specimen.
pub(crate) fn btree_map_distinct_from_prop<K, V, E>(
    estimator: &E,
    parameter_name: &'static str,
) -> BTreeMap<K, V>
where
    V: LargestSpecimen,
    K: Ord + LargeUniqueSequence<E> + Sized,
    E: SizeEstimator,
{
    let mut count = estimator.require_parameter(parameter_name);
    if count < 0 {
        count = 0;
    }

    K::large_unique_sequence(estimator, count as usize)
        .into_iter()
        .map(|key| (key, LargestSpecimen::largest_specimen(estimator)))
        .collect()
}

/// Generates a `BTreeSet` with the size taken from a property.
///
/// Value are generated uniquely using `LargeUniqueSequence`.
pub(crate) fn btree_set_distinct_from_prop<T, E>(
    estimator: &E,
    parameter_name: &'static str,
) -> BTreeSet<T>
where
    T: Ord + LargeUniqueSequence<E> + Sized,
    E: SizeEstimator,
{
    let mut count = estimator.require_parameter(parameter_name);
    if count < 0 {
        count = 0;
    }

    T::large_unique_sequence(estimator, count as usize)
}

impl LargestSpecimen for SocketAddr {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        SocketAddr::V6(SocketAddrV6::largest_specimen(estimator))
    }
}

impl LargestSpecimen for SocketAddrV6 {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        SocketAddrV6::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for Ipv6Addr {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        // Leading zeros get shorted, ensure there are none in the address.
        Ipv6Addr::new(
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
        )
    }
}

impl LargestSpecimen for bool {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        true
    }
}

impl LargestSpecimen for u16 {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        u16::MAX
    }
}

impl LargestSpecimen for u32 {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        u32::MAX
    }
}

impl LargestSpecimen for u64 {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        u64::MAX
    }
}

impl LargestSpecimen for u128 {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        u128::MAX
    }
}

impl<T> LargestSpecimen for Option<T>
where
    T: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Some(LargestSpecimen::largest_specimen(estimator))
    }
}

impl<T> LargestSpecimen for Box<T>
where
    T: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Box::new(LargestSpecimen::largest_specimen(estimator))
    }
}

impl<T> LargestSpecimen for Arc<T>
where
    T: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Arc::new(LargestSpecimen::largest_specimen(estimator))
    }
}

impl<T1, T2> LargestSpecimen for (T1, T2)
where
    T1: LargestSpecimen,
    T2: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        (
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl<T1, T2, T3> LargestSpecimen for (T1, T2, T3)
where
    T1: LargestSpecimen,
    T2: LargestSpecimen,
    T3: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        (
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

// various third party crates

impl<L, R> LargestSpecimen for Either<L, R>
where
    L: LargestSpecimen + Serialize,
    R: LargestSpecimen + Serialize,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        let l = L::largest_specimen(estimator);
        let r = R::largest_specimen(estimator);

        if estimator.estimate(&l) >= estimator.estimate(&r) {
            Either::Left(l)
        } else {
            Either::Right(r)
        }
    }
}

// impls for `casper_types`, which is technically a foreign crate -- so we put them here.
impl LargestSpecimen for ProtocolVersion {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        ProtocolVersion::new(LargestSpecimen::largest_specimen(estimator))
    }
}

impl LargestSpecimen for SemVer {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        SemVer {
            major: LargestSpecimen::largest_specimen(estimator),
            minor: LargestSpecimen::largest_specimen(estimator),
            patch: LargestSpecimen::largest_specimen(estimator),
        }
    }
}

impl LargestSpecimen for PublicKey {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        public_key_from_key_bytes(estimator, [0xFFu8; 32])
    }
}

fn key_bytes_from_random_value(seed: u128) -> [u8; 32] {
    let bytes = seed.to_ne_bytes();
    [
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8],
        bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15], bytes[0],
        bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
        bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15],
    ]
}

fn public_key_from_key_bytes<E: SizeEstimator>(estimator: &E, pub_key: [u8; 32]) -> PublicKey {
    largest_variant::<PublicKey, PublicKeyDiscriminants, _, _>(estimator, |variant| match variant {
        PublicKeyDiscriminants::System => PublicKey::system(),
        PublicKeyDiscriminants::Ed25519 => PublicKey::ed25519_from_bytes(&pub_key)
            .expect("fixed specimen should be valid Ed25519 public key"),
        PublicKeyDiscriminants::Secp256k1 => PublicKey::secp256k1_from_bytes(&pub_key)
            .expect("fixed specimen should be valid Secp256k1 public key"),
    })
}

impl<E> LargeUniqueSequence<E> for PublicKey
where
    E: SizeEstimator,
{
    fn large_unique_sequence(estimator: &E, count: usize) -> BTreeSet<Self> {
        (0..u128::MAX)
            .rev()
            .map(key_bytes_from_random_value)
            .map(|bytes| public_key_from_key_bytes(estimator, bytes))
            .take(count)
            .collect()
    }
}

impl LargestSpecimen for Signature {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        largest_variant::<Self, SignatureDiscriminants, _, _>(estimator, |variant| match variant {
            SignatureDiscriminants::System => Signature::system(),
            SignatureDiscriminants::Ed25519 => Signature::ed25519([0xFFu8; 64])
                .expect("fixed specimen should be valid Ed25519 signature"),
            SignatureDiscriminants::Secp256k1 => Signature::secp256k1([0xFFu8; 64])
                .expect("fixed specimen should be valid Secp256k1 signature"),
        })
    }
}

impl LargestSpecimen for EraId {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        EraId::new(LargestSpecimen::largest_specimen(estimator))
    }
}

impl LargestSpecimen for Timestamp {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        Timestamp::MAX
    }
}

impl LargestSpecimen for TimeDiff {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        TimeDiff::from_millis(LargestSpecimen::largest_specimen(estimator))
    }
}

impl LargestSpecimen for Block {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Block::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            Some(btree_map_distinct_from_prop(estimator, "validator_count")),
            LargestSpecimen::largest_specimen(estimator),
        )
        .expect("did not expect largest speciment creation of block to fail")
    }
}

impl LargestSpecimen for FinalizedBlock {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        FinalizedBlock::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for FinalitySignature {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        FinalitySignature::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for FinalitySignatureId {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        FinalitySignatureId {
            block_hash: LargestSpecimen::largest_specimen(estimator),
            era_id: LargestSpecimen::largest_specimen(estimator),
            public_key: LargestSpecimen::largest_specimen(estimator),
        }
    }
}

impl<T> LargestSpecimen for EraReport<T>
where
    T: LargestSpecimen,
{
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        EraReport {
            equivocators: todo!("max number of equivs?"),
            rewards: todo!("max reward struct?"),
            inactive_validators: todo!("max number of inactive?"),
        }
    }
}

impl LargestSpecimen for BlockHash {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        BlockHash::new(LargestSpecimen::largest_specimen(estimator))
    }
}

impl LargestSpecimen for BlockBody {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        todo!()
    }
}

// impls for `casper_hashing`, which is technically a foreign crate -- so we put them here.
impl LargestSpecimen for Digest {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        // Hashes are fixed size by definition, so any value will do.
        Digest::hash("")
    }
}

impl LargestSpecimen for BlockPayload {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        BlockPayload::new(
            vec_prop_specimen(estimator, "max_deploys_per_block"),
            vec_prop_specimen(estimator, "max_transfers_per_block"),
            vec_prop_specimen(estimator, "max_accusations_per_block"),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for DeployHashWithApprovals {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        DeployHashWithApprovals::new(
            LargestSpecimen::largest_specimen(estimator),
            todo!("how many approvals are there in this?"),
        )
    }
}

impl LargestSpecimen for DeployHash {
    fn largest_specimen<E: SizeEstimator>(_estimator: &E) -> Self {
        DeployHash::new([0xFFu8; DEPLOY_HASH_LENGTH])
    }
}

impl LargestSpecimen for Deploy {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Deploy::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            todo!("generate maximum number of unique dependencies"),
            todo!("implement largest chain name"),
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
            todo!("generate suitable secret key"),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for DeployId {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        DeployId::new(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for Approval {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        Approval::from_parts(
            LargestSpecimen::largest_specimen(estimator),
            LargestSpecimen::largest_specimen(estimator),
        )
    }
}

impl LargestSpecimen for ApprovalsHash {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        ApprovalsHash::compute(&Default::default()).expect("empty approvals hash should compute")
    }
}

// EE impls
impl LargestSpecimen for ExecutableDeployItem {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        largest_variant::<Self, ExecutableDeployItemDiscriminants, _, _>(estimator, |variant| {
            match variant {
                ExecutableDeployItemDiscriminants::ModuleBytes => {
                    ExecutableDeployItem::ModuleBytes {
                        module_bytes: todo!("how to create maximum size contract bytes?"),
                        args: todo!("how are runtime arguments limited?"),
                    }
                }
                ExecutableDeployItemDiscriminants::StoredContractByHash => {
                    ExecutableDeployItem::StoredContractByHash {
                        hash: todo!(),
                        entry_point: todo!("whats the maximum length for an entry point?"),
                        args: todo!(),
                    }
                }
                ExecutableDeployItemDiscriminants::StoredContractByName => {
                    ExecutableDeployItem::StoredContractByName {
                        name: todo!("what's the max length for a contract stored by name?"),
                        entry_point: todo!(),
                        args: todo!(),
                    }
                }
                ExecutableDeployItemDiscriminants::StoredVersionedContractByHash => {
                    ExecutableDeployItem::StoredVersionedContractByHash {
                        hash: todo!(),
                        version: todo!(),
                        entry_point: todo!(),
                        args: todo!(),
                    }
                }
                ExecutableDeployItemDiscriminants::StoredVersionedContractByName => {
                    ExecutableDeployItem::StoredVersionedContractByName {
                        name: todo!(),
                        version: todo!(),
                        entry_point: todo!(),
                        args: todo!(),
                    }
                }
                ExecutableDeployItemDiscriminants::Transfer => {
                    ExecutableDeployItem::Transfer { args: todo!() }
                }
            }
        })
    }
}

impl LargestSpecimen for U512 {
    fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
        U512::max_value()
    }
}
