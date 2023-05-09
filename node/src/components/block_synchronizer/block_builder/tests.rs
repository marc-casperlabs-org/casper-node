use std::{collections::BTreeMap, thread, time::Duration};

use casper_types::testing::TestRng;
use num_rational::Ratio;

use crate::components::consensus::tests::utils::{ALICE_PUBLIC_KEY, ALICE_SECRET_KEY};

use super::*;

#[test]
fn handle_acceptance() {
    let mut rng = TestRng::new();
    let block = Block::random(&mut rng);
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );

    let honest_peer = NodeId::random(&mut rng);
    let dishonest_peer = NodeId::random(&mut rng);

    // Builder acceptance for needed signature from ourselves.
    assert!(builder
        .handle_acceptance(None, Ok(Some(Acceptance::NeededIt)))
        .is_ok());
    assert!(builder.peer_list().qualified_peers(&mut rng).is_empty());
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for existent signature from ourselves.
    assert!(builder
        .handle_acceptance(None, Ok(Some(Acceptance::HadIt)))
        .is_ok());
    assert!(builder.peer_list().qualified_peers(&mut rng).is_empty());
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for no signature from ourselves.
    assert!(builder.handle_acceptance(None, Ok(None)).is_ok());
    assert!(builder.peer_list().qualified_peers(&mut rng).is_empty());
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for no signature from a peer.
    // Peer shouldn't be registered.
    assert!(builder
        .handle_acceptance(Some(honest_peer), Ok(None))
        .is_ok());
    assert!(builder.peer_list().qualified_peers(&mut rng).is_empty());
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for existent signature from a peer.
    // Peer shouldn't be registered.
    assert!(builder
        .handle_acceptance(Some(honest_peer), Ok(Some(Acceptance::HadIt)))
        .is_ok());
    assert!(builder.peer_list().qualified_peers(&mut rng).is_empty());
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for needed signature from a peer.
    // Peer should be registered as honest.
    assert!(builder
        .handle_acceptance(Some(honest_peer), Ok(Some(Acceptance::NeededIt)))
        .is_ok());
    assert!(builder
        .peer_list()
        .qualified_peers(&mut rng)
        .contains(&honest_peer));
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for error on signature handling from ourselves.
    assert!(builder
        .handle_acceptance(None, Err(BlockAcquisitionError::InvalidStateTransition))
        .is_err());
    assert!(builder
        .peer_list()
        .qualified_peers(&mut rng)
        .contains(&honest_peer));
    assert!(builder.peer_list().dishonest_peers().is_empty());
    // Builder acceptance for error on signature handling from a peer.
    // Peer should be registered as dishonest.
    assert!(builder
        .handle_acceptance(
            Some(dishonest_peer),
            Err(BlockAcquisitionError::InvalidStateTransition)
        )
        .is_err());
    assert!(builder
        .peer_list()
        .qualified_peers(&mut rng)
        .contains(&honest_peer));
    assert!(builder
        .peer_list()
        .dishonest_peers()
        .contains(&dishonest_peer));
}

#[test]
fn register_era_validator_weights() {
    let mut rng = TestRng::new();
    let block = Block::random(&mut rng);
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );
    let latest_timestamp = builder.last_progress;

    let mut validator_matrix = ValidatorMatrix::new_with_validator(ALICE_SECRET_KEY.clone());

    thread::sleep(Duration::from_millis(5));
    // Register default era (0). We have no information in the builder to
    // determine if these weights are relevant, so they shouldn't be stored.
    builder.register_era_validator_weights(&validator_matrix);
    assert!(builder.validator_weights.is_none());
    assert_eq!(latest_timestamp, builder.last_progress);
    // Set the era of the builder to 1000.
    builder.era_id = Some(EraId::from(1000));
    thread::sleep(Duration::from_millis(5));
    // Register the default era again. The builder is interested in weights
    // for era 1000, but the matrix has weights only for era 0, so they
    // shouldn't be registered.
    builder.register_era_validator_weights(&validator_matrix);
    assert!(builder.validator_weights.is_none());
    assert_eq!(latest_timestamp, builder.last_progress);
    // Set the era of the builder to the random block's era.
    builder.era_id = Some(block.header().era_id());
    // Add weights for that era to the validator matrix.
    let weights = EraValidatorWeights::new(
        block.header().era_id(),
        BTreeMap::from([(ALICE_PUBLIC_KEY.clone(), 100.into())]),
        Ratio::new(1, 3),
    );
    validator_matrix.register_era_validator_weights(weights.clone());
    thread::sleep(Duration::from_millis(5));
    // Register the random block's era weights. This should store the weights.
    builder.register_era_validator_weights(&validator_matrix);
    assert_eq!(builder.validator_weights.unwrap(), weights);
    assert_ne!(latest_timestamp, builder.last_progress);
}

#[test]
fn register_finalized_block() {
    let mut rng = TestRng::new();
    // Create a random block.
    let block = Block::random(&mut rng);
    // Create a builder for the block.
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );
    let mut latest_timestamp = builder.last_progress;
    // Create mock era weights for the block's era.
    let weights = EraValidatorWeights::new(
        block.header().era_id(),
        BTreeMap::from([(ALICE_PUBLIC_KEY.clone(), 100.into())]),
        Ratio::new(1, 3),
    );
    // Create a signature acquisition to fill.
    let mut signature_acquisition = SignatureAcquisition::new(
        vec![ALICE_PUBLIC_KEY.clone()],
        LegacyRequiredFinality::Strict,
    );
    let sig = FinalitySignature::create(
        *block.hash(),
        block.header().era_id(),
        &ALICE_SECRET_KEY,
        ALICE_PUBLIC_KEY.clone(),
    );
    assert_eq!(
        signature_acquisition.apply_signature(sig, &weights),
        Acceptance::NeededIt
    );
    // Set the builder's state to `HaveStrictFinalitySignatures`.
    let finalized_block = FinalizedBlock::from(block.clone());
    builder.acquisition_state = BlockAcquisitionState::HaveStrictFinalitySignatures(
        Box::new(block.clone()),
        signature_acquisition.clone(),
    );
    let expected_deploys = vec![Deploy::random(&mut rng)];

    // Register the finalized block.
    thread::sleep(Duration::from_millis(5));
    builder.register_made_finalized_block(finalized_block.clone(), expected_deploys.clone());
    match &builder.acquisition_state {
        BlockAcquisitionState::HaveFinalizedBlock(actual_block, _, actual_deploys, enqueued) => {
            assert_eq!(*actual_block.hash(), *block.hash());
            assert_eq!(expected_deploys, *actual_deploys);
            assert!(!enqueued);
        }
        _ => panic!("Unexpected outcome in registering finalized block"),
    }
    assert!(!builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
    latest_timestamp = builder.last_progress;

    // Make the builder historical.
    builder.should_fetch_execution_state = true;
    // Reset the state to `HaveStrictFinalitySignatures`.
    builder.acquisition_state = BlockAcquisitionState::HaveStrictFinalitySignatures(
        Box::new(block),
        signature_acquisition.clone(),
    );
    // Register the finalized block. This should fail on historical builders.
    thread::sleep(Duration::from_millis(5));
    builder.register_made_finalized_block(finalized_block, expected_deploys);
    assert!(builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
}

#[test]
fn register_block_execution() {
    let mut rng = TestRng::new();
    // Create a random block.
    let block = Block::random(&mut rng);
    // Create a builder for the block.
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );
    let mut latest_timestamp = builder.last_progress;
    // Create mock era weights for the block's era.
    let weights = EraValidatorWeights::new(
        block.header().era_id(),
        BTreeMap::from([(ALICE_PUBLIC_KEY.clone(), 100.into())]),
        Ratio::new(1, 3),
    );
    // Create a signature acquisition to fill.
    let mut signature_acquisition = SignatureAcquisition::new(
        vec![ALICE_PUBLIC_KEY.clone()],
        LegacyRequiredFinality::Strict,
    );
    let sig = FinalitySignature::create(
        *block.hash(),
        block.header().era_id(),
        &ALICE_SECRET_KEY,
        ALICE_PUBLIC_KEY.clone(),
    );
    assert_eq!(
        signature_acquisition.apply_signature(sig, &weights),
        Acceptance::NeededIt
    );

    let finalized_block = Box::new(FinalizedBlock::from(block.clone()));
    builder.acquisition_state = BlockAcquisitionState::HaveFinalizedBlock(
        Box::new(block),
        finalized_block,
        vec![Deploy::random(&mut rng)],
        false,
    );

    assert_eq!(builder.execution_progress, ExecutionProgress::Idle);
    // Register the block execution enquement as successful. This should
    // advance the execution progress.
    thread::sleep(Duration::from_millis(5));
    builder.register_block_execution_enqueued();
    assert_eq!(builder.execution_progress, ExecutionProgress::Started);
    assert!(matches!(
        builder.acquisition_state,
        BlockAcquisitionState::HaveFinalizedBlock(_, _, _, true)
    ));
    assert!(!builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
    latest_timestamp = builder.last_progress;

    // Attempt to register the block for execution again. The state shouldn't
    // change and the builder shouldn't fail.
    thread::sleep(Duration::from_millis(5));
    builder.register_block_execution_enqueued();
    assert_eq!(builder.execution_progress, ExecutionProgress::Started);
    assert!(matches!(
        builder.acquisition_state,
        BlockAcquisitionState::HaveFinalizedBlock(_, _, _, true)
    ));
    assert!(!builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
    latest_timestamp = builder.last_progress;

    // Make the builder historical.
    builder.should_fetch_execution_state = true;
    // Register the block execution enquement as successful. This should put
    // the builder in a failed state as we shouldn't execute historical blocks.
    thread::sleep(Duration::from_millis(5));
    builder.register_block_execution_enqueued();
    assert!(builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
}

#[test]
fn register_block_executed() {
    let mut rng = TestRng::new();
    // Create a random block.
    let block = Block::random(&mut rng);
    // Create a builder for the block.
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );
    let mut latest_timestamp = builder.last_progress;
    // Create mock era weights for the block's era.
    let weights = EraValidatorWeights::new(
        block.header().era_id(),
        BTreeMap::from([(ALICE_PUBLIC_KEY.clone(), 100.into())]),
        Ratio::new(1, 3),
    );
    // Create a signature acquisition to fill.
    let mut signature_acquisition = SignatureAcquisition::new(
        vec![ALICE_PUBLIC_KEY.clone()],
        LegacyRequiredFinality::Strict,
    );
    let sig = FinalitySignature::create(
        *block.hash(),
        block.header().era_id(),
        &ALICE_SECRET_KEY,
        ALICE_PUBLIC_KEY.clone(),
    );
    assert_eq!(
        signature_acquisition.apply_signature(sig, &weights),
        Acceptance::NeededIt
    );
    // Set the builder state to `HaveStrictFinalitySignatures`.
    builder.acquisition_state =
        BlockAcquisitionState::HaveStrictFinalitySignatures(Box::new(block), signature_acquisition);
    // Mark execution as started.
    builder.execution_progress = ExecutionProgress::Started;

    thread::sleep(Duration::from_millis(5));
    // Register the block as executed. This should advance the execution
    // progress to `Done`.
    builder.register_block_executed();
    assert_eq!(builder.execution_progress, ExecutionProgress::Done);
    assert!(!builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
    latest_timestamp = builder.last_progress;

    thread::sleep(Duration::from_millis(5));
    // Register the block as executed again. This should not change the
    // builder's state.
    builder.register_block_executed();
    assert_eq!(builder.execution_progress, ExecutionProgress::Done);
    assert!(!builder.is_failed());
    assert_eq!(latest_timestamp, builder.last_progress);

    // Set the builder to be historical and register the block as executed
    // again. This should put the builder in the failed state.
    builder.should_fetch_execution_state = true;
    thread::sleep(Duration::from_millis(5));
    builder.register_block_executed();
    assert!(builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
}

#[test]
fn register_block_marked_complete() {
    let mut rng = TestRng::new();
    // Create a random block.
    let block = Block::random(&mut rng);
    // Create a builder for the block.
    let mut builder = BlockBuilder::new(
        block.header().block_hash(),
        false,
        1,
        TimeDiff::from_seconds(1),
        TimeDiff::from_seconds(1),
        LegacyRequiredFinality::Strict,
        ProtocolVersion::V1_0_0,
    );
    // Make the builder historical.
    builder.should_fetch_execution_state = true;
    let mut latest_timestamp = builder.last_progress;
    // Create mock era weights for the block's era.
    let weights = EraValidatorWeights::new(
        block.header().era_id(),
        BTreeMap::from([(ALICE_PUBLIC_KEY.clone(), 100.into())]),
        Ratio::new(1, 3),
    );
    // Create a signature acquisition to fill.
    let mut signature_acquisition = SignatureAcquisition::new(
        vec![ALICE_PUBLIC_KEY.clone()],
        LegacyRequiredFinality::Strict,
    );
    let sig = FinalitySignature::create(
        *block.hash(),
        block.header().era_id(),
        &ALICE_SECRET_KEY,
        ALICE_PUBLIC_KEY.clone(),
    );
    assert_eq!(
        signature_acquisition.apply_signature(sig, &weights),
        Acceptance::NeededIt
    );

    // Set the builder state to `HaveStrictFinalitySignatures`.
    builder.acquisition_state = BlockAcquisitionState::HaveStrictFinalitySignatures(
        Box::new(block.clone()),
        signature_acquisition.clone(),
    );
    // Register the block as marked complete. Since there are no missing
    // deploys, this should transition the builder state to
    // `HaveStrictFinalitySignatures`.
    thread::sleep(Duration::from_millis(5));
    builder.register_marked_complete();
    assert!(matches!(
        builder.acquisition_state,
        BlockAcquisitionState::Complete(..)
    ));
    assert!(!builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
    latest_timestamp = builder.last_progress;

    // Make this a forward builder.
    builder.should_fetch_execution_state = false;
    // Set the builder state to `HaveStrictFinalitySignatures`.
    builder.acquisition_state = BlockAcquisitionState::HaveStrictFinalitySignatures(
        Box::new(block),
        signature_acquisition.clone(),
    );
    // Register the block as marked complete. In the forward flow we should
    // abort the builder as an attempt to mark the block complete is invalid.
    thread::sleep(Duration::from_millis(5));
    builder.register_marked_complete();
    assert!(builder.is_failed());
    assert_ne!(latest_timestamp, builder.last_progress);
}
