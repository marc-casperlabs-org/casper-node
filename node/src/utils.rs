//! Various functions that are not limited to a particular module, but are too small to warrant
//! being factored out into standalone crates.

mod block_signatures;
mod display_error;
pub(crate) mod ds;
mod external;
pub(crate) mod fmt_limit;
mod fuse;
pub(crate) mod opt_display;
pub(crate) mod registered_metric;
pub(crate) mod rlimit;
pub(crate) mod round_robin;
pub(crate) mod specimen;
pub(crate) mod umask;
pub mod work_queue;

use std::{
    any,
    cell::RefCell,
    fmt::{self, Debug, Display, Formatter},
    fs::File,
    io::{self, Write},
    net::{SocketAddr, ToSocketAddrs},
    ops::{Add, BitXorAssign, Div},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::{Duration, Instant, SystemTime},
};

use datasize::DataSize;
use fs2::FileExt;
use futures::future::Either;
use hyper::server::{conn::AddrIncoming, Builder, Server};

use prometheus::{self, IntGauge};
use serde::Serialize;
use thiserror::Error;
use tracing::{error, warn};

use crate::types::NodeId;
pub(crate) use block_signatures::{check_sufficient_block_signatures, BlockSignatureError};
pub(crate) use display_error::display_error;
#[cfg(test)]
pub(crate) use external::RESOURCES_PATH;
pub use external::{External, LoadError, Loadable};
pub(crate) use fuse::{DropSwitch, Fuse, ObservableFuse, SharedFuse};
pub(crate) use round_robin::WeightedRoundRobin;
#[cfg(test)]
pub(crate) use tests::extract_metric_names;

/// DNS resolution error.
#[derive(Debug, Error)]
#[error("could not resolve `{address}`: {kind}")]
pub struct ResolveAddressError {
    /// Address that failed to resolve.
    address: String,
    /// Reason for resolution failure.
    kind: ResolveAddressErrorKind,
}

/// DNS resolution error kind.
#[derive(Debug)]
enum ResolveAddressErrorKind {
    /// Resolve returned an error.
    ErrorResolving(io::Error),
    /// Resolution did not yield any address.
    NoAddressFound,
}

impl Display for ResolveAddressErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResolveAddressErrorKind::ErrorResolving(err) => {
                write!(f, "could not run dns resolution: {}", err)
            }
            ResolveAddressErrorKind::NoAddressFound => {
                write!(f, "no addresses found")
            }
        }
    }
}

/// Backport of `Result::flatten`, see <https://github.com/rust-lang/rust/issues/70142>.
pub trait FlattenResult {
    /// The output of the flattening operation.
    type Output;

    /// Flattens one level.
    ///
    /// This function is named `flatten_result` instead of `flatten` to avoid name collisions once
    /// `Result::flatten` stabilizes.
    fn flatten_result(self) -> Self::Output;
}

impl<T, E> FlattenResult for Result<Result<T, E>, E> {
    type Output = Result<T, E>;

    #[inline]
    fn flatten_result(self) -> Self::Output {
        match self {
            Ok(Ok(v)) => Ok(v),
            Ok(Err(e)) => Err(e),
            Err(e) => Err(e),
        }
    }
}

/// Parses a network address from a string, with DNS resolution.
pub(crate) fn resolve_address(address: &str) -> Result<SocketAddr, ResolveAddressError> {
    address
        .to_socket_addrs()
        .map_err(|err| ResolveAddressError {
            address: address.to_string(),
            kind: ResolveAddressErrorKind::ErrorResolving(err),
        })?
        .next()
        .ok_or_else(|| ResolveAddressError {
            address: address.to_string(),
            kind: ResolveAddressErrorKind::NoAddressFound,
        })
}

/// An error starting one of the HTTP servers.
#[derive(Debug, Error)]
pub(crate) enum ListeningError {
    /// Failed to resolve address.
    #[error("failed to resolve network address: {0}")]
    ResolveAddress(ResolveAddressError),

    /// Failed to listen.
    #[error("failed to listen on {address}: {error}")]
    Listen {
        /// The address attempted to listen on.
        address: SocketAddr,
        /// The failure reason.
        error: Box<dyn std::error::Error + Send + Sync>,
    },
}

pub(crate) fn start_listening(address: &str) -> Result<Builder<AddrIncoming>, ListeningError> {
    let address = resolve_address(address).map_err(|error| {
        warn!(%error, %address, "failed to start HTTP server, cannot parse address");
        ListeningError::ResolveAddress(error)
    })?;

    Server::try_bind(&address).map_err(|error| {
        warn!(%error, %address, "failed to start HTTP server");
        ListeningError::Listen {
            address,
            error: Box::new(error),
        }
    })
}

/// Moves a value to the heap and then forgets about, leaving only a static reference behind.
#[inline]
pub(crate) fn leak<T>(value: T) -> &'static T {
    Box::leak(Box::new(value))
}

/// An "unlimited semaphore".
///
/// Upon construction, `TokenizedCount` increases a given `IntGauge` by one for metrics purposed.
///
/// Once it is dropped, the underlying gauge will be decreased by one.
#[derive(Debug)]
pub(crate) struct TokenizedCount {
    /// The gauge modified on construction/drop.
    gauge: Option<IntGauge>,
}

impl TokenizedCount {
    /// Create a new tokenized count, increasing the given gauge.
    pub(crate) fn new(gauge: IntGauge) -> Self {
        gauge.inc();
        TokenizedCount { gauge: Some(gauge) }
    }
}

impl Drop for TokenizedCount {
    fn drop(&mut self) {
        if let Some(gauge) = self.gauge.take() {
            gauge.dec();
        }
    }
}

/// A display-helper that shows iterators display joined by ",".
#[derive(Debug)]
pub(crate) struct DisplayIter<T>(RefCell<Option<T>>);

impl<T> DisplayIter<T> {
    pub(crate) fn new(item: T) -> Self {
        DisplayIter(RefCell::new(Some(item)))
    }
}

impl<I, T> Display for DisplayIter<I>
where
    I: IntoIterator<Item = T>,
    T: Display,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        if let Some(src) = self.0.borrow_mut().take() {
            let mut first = true;
            for item in src.into_iter().take(f.width().unwrap_or(usize::MAX)) {
                if first {
                    first = false;
                    write!(f, "{}", item)?;
                } else {
                    write!(f, ", {}", item)?;
                }
            }

            Ok(())
        } else {
            write!(f, "DisplayIter:GONE")
        }
    }
}

/// With-directory context.
///
/// Associates a type with a "working directory".
#[derive(Clone, DataSize, Debug)]
pub struct WithDir<T> {
    dir: PathBuf,
    value: T,
}

impl<T> WithDir<T> {
    /// Creates a new with-directory context.
    pub fn new<P: Into<PathBuf>>(path: P, value: T) -> Self {
        WithDir {
            dir: path.into(),
            value,
        }
    }

    /// Returns a reference to the inner path.
    pub fn dir(&self) -> &Path {
        self.dir.as_ref()
    }

    /// Deconstructs a with-directory context.
    pub(crate) fn into_parts(self) -> (PathBuf, T) {
        (self.dir, self.value)
    }

    /// Maps an internal value onto a reference.
    pub fn map_ref<U, F: FnOnce(&T) -> U>(&self, f: F) -> WithDir<U> {
        WithDir {
            dir: self.dir.clone(),
            value: f(&self.value),
        }
    }

    /// Get a reference to the inner value.
    pub fn value(&self) -> &T {
        &self.value
    }

    /// Adds `self.dir` as a parent if `path` is relative, otherwise returns `path` unchanged.
    pub fn with_dir(&self, path: PathBuf) -> PathBuf {
        if path.is_relative() {
            self.dir.join(path)
        } else {
            path
        }
    }
}

/// The source of a piece of data.
#[derive(Clone, Debug, Serialize)]
pub(crate) enum Source {
    /// A peer with the wrapped ID.
    PeerGossiped(NodeId),
    /// A peer with the wrapped ID.
    Peer(NodeId),
    /// A client.
    Client,
    /// This node.
    Ourself,
}

impl Source {
    #[allow(clippy::wrong_self_convention)]
    pub(crate) fn is_client(&self) -> bool {
        matches!(self, Source::Client)
    }

    /// If `self` represents a peer, returns its ID, otherwise returns `None`.
    pub(crate) fn node_id(&self) -> Option<NodeId> {
        match self {
            Source::Peer(node_id) | Source::PeerGossiped(node_id) => Some(*node_id),
            Source::Client | Source::Ourself => None,
        }
    }
}

impl Display for Source {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Source::PeerGossiped(node_id) => Display::fmt(node_id, formatter),
            Source::Peer(node_id) => Display::fmt(node_id, formatter),
            Source::Client => write!(formatter, "client"),
            Source::Ourself => write!(formatter, "ourself"),
        }
    }
}

/// Divides `numerator` by `denominator` and rounds to the closest integer (round half down).
///
/// `numerator + denominator / 2` must not overflow, and `denominator` must not be zero.
pub(crate) fn div_round<T>(numerator: T, denominator: T) -> T
where
    T: Add<Output = T> + Div<Output = T> + From<u8> + Copy,
{
    (numerator + denominator / T::from(2)) / denominator
}

/// XORs two byte sequences.
///
/// # Panics
///
/// Panics if `lhs` and `rhs` are not of equal length.
#[inline]
pub(crate) fn xor(lhs: &mut [u8], rhs: &[u8]) {
    // Implementing SIMD support is left as an exercise for the reader.
    assert_eq!(lhs.len(), rhs.len(), "xor inputs should have equal length");
    lhs.iter_mut()
        .zip(rhs.iter())
        .for_each(|(sb, &cb)| sb.bitxor_assign(cb));
}

/// Wait until all strong references for a particular arc have been dropped.
///
/// Downgrades and immediately drops the `Arc`, keeping only a weak reference. The reference will
/// then be polled `attempts` times, unless it has a strong reference count of 0.
///
/// Returns whether or not `arc` has zero strong references left.
///
/// # Note
///
/// Using this function is usually a potential architectural issue and it should be used very
/// sparingly. Consider introducing a different access pattern for the value under `Arc`.
pub(crate) async fn wait_for_arc_drop<T>(
    arc: Arc<T>,
    attempts: usize,
    retry_delay: Duration,
) -> bool {
    // Ensure that if we do hold the last reference, we are now going to 0.
    let weak = Arc::downgrade(&arc);
    drop(arc);

    for _ in 0..attempts {
        let strong_count = weak.strong_count();

        if strong_count == 0 {
            // Everything has been dropped, we are done.
            return true;
        }

        tokio::time::sleep(retry_delay).await;
    }

    error!(
        attempts, ?retry_delay, ty=%any::type_name::<T>(),
        "failed to clean up shared reference"
    );

    false
}

/// A thread-safe wrapper around a file that writes chunks.
///
/// A chunk can (but needn't) be a line. The writer guarantees it will be written to the wrapped
/// file, even if other threads are attempting to write chunks at the same time.
#[derive(Clone)]
pub(crate) struct LockedLineWriter(Arc<Mutex<File>>);

impl LockedLineWriter {
    /// Creates a new `LockedLineWriter`.
    ///
    /// This function does not panic - if any error occurs, it will be logged and ignored.
    pub(crate) fn new(file: File) -> Self {
        LockedLineWriter(Arc::new(Mutex::new(file)))
    }

    /// Writes a chunk to the wrapped file.
    pub(crate) fn write_line(&self, line: &str) {
        match self.0.lock() {
            Ok(mut guard) => {
                // Acquire a lock on the file. This ensures we do not garble output when multiple
                // nodes are writing to the same file.
                if let Err(err) = guard.lock_exclusive() {
                    warn!(%line, %err, "could not acquire file lock, not writing line");
                    return;
                }

                if let Err(err) = guard.write_all(line.as_bytes()) {
                    warn!(%line, %err, "could not finish writing line");
                }

                if let Err(err) = guard.unlock() {
                    warn!(%err, "failed to release file lock in locked line writer, ignored");
                }
            }
            Err(_) => {
                error!(%line, "line writer lock poisoned, lost line");
            }
        }
    }
}

/// An anchor for converting an `Instant` into a wall-clock (`SystemTime`) time.
#[derive(Copy, Clone, Debug)]
pub(crate) struct TimeAnchor {
    /// The reference instant used for conversion.
    now: Instant,
    /// The reference wall-clock timestamp used for conversion.
    wall_clock_now: SystemTime,
}

impl TimeAnchor {
    /// Creates a new time anchor.
    ///
    /// Will take a sample of the monotonic clock and the current time and store it in the anchor.
    pub(crate) fn now() -> Self {
        TimeAnchor {
            now: Instant::now(),
            wall_clock_now: SystemTime::now(),
        }
    }

    /// Converts a point in time from the monotonic clock to wall clock time, using this anchor.
    #[inline]
    pub(crate) fn convert(&self, then: Instant) -> SystemTime {
        if then > self.now {
            self.wall_clock_now + then.duration_since(self.now)
        } else {
            self.wall_clock_now - self.now.duration_since(then)
        }
    }
}

/// Discard secondary data from a value.
pub(crate) trait Peel {
    /// What is left after discarding the wrapping.
    type Inner;

    /// Discard "uninteresting" data.
    fn peel(self) -> Self::Inner;
}

impl<A, B, F, G> Peel for Either<(A, G), (B, F)> {
    type Inner = Either<A, B>;

    fn peel(self) -> Self::Inner {
        match self {
            Either::Left((v, _)) => Either::Left(v),
            Either::Right((v, _)) => Either::Right(v),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::HashSet, sync::Arc, time::Duration};

    use prometheus::IntGauge;

    use super::{wait_for_arc_drop, xor, TokenizedCount};

    /// Extracts the names of all metrics contained in a prometheus-formatted metrics snapshot.

    pub(crate) fn extract_metric_names(raw: &str) -> HashSet<&str> {
        raw.lines()
            .filter_map(|line| {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    None
                } else {
                    let (full_id, _) = trimmed.split_once(' ')?;
                    let id = full_id.split_once('{').map(|v| v.0).unwrap_or(full_id);
                    Some(id)
                }
            })
            .collect()
    }

    #[test]
    fn xor_works() {
        let mut lhs = [0x43, 0x53, 0xf2, 0x2f, 0xa9, 0x70, 0xfb, 0xf4];
        let rhs = [0x04, 0x0b, 0x5c, 0xa1, 0xef, 0x11, 0x12, 0x23];
        let xor_result = [0x47, 0x58, 0xae, 0x8e, 0x46, 0x61, 0xe9, 0xd7];

        xor(&mut lhs, &rhs);

        assert_eq!(lhs, xor_result);
    }

    #[test]
    #[should_panic(expected = "equal length")]
    fn xor_panics_on_uneven_inputs() {
        let mut lhs = [0x43, 0x53, 0xf2, 0x2f, 0xa9, 0x70, 0xfb, 0xf4];
        let rhs = [0x04, 0x0b, 0x5c, 0xa1, 0xef, 0x11];

        xor(&mut lhs, &rhs);
    }

    #[tokio::test]
    async fn arc_drop_waits_for_drop() {
        let retry_delay = Duration::from_millis(25);
        let attempts = 15;

        let arc = Arc::new(());

        let arc_in_background = arc.clone();
        let _weak_in_background = Arc::downgrade(&arc);

        // At this point, the Arc has the following refernces:
        //
        // * main test task (`arc`, strong)
        // * background strong reference (`arc_in_background`)
        // * background weak reference (`weak_in_background`)

        // Phase 1: waiting for the arc should fail, because there still is the background
        // reference.
        assert!(!wait_for_arc_drop(arc, attempts, retry_delay).await);

        // We "restore" the arc from the background arc.
        let arc = arc_in_background.clone();

        // Add another "foreground" weak reference.
        let weak = Arc::downgrade(&arc);

        // Phase 2: Our background tasks drops its reference, now we should succeed.
        drop(arc_in_background);
        assert!(wait_for_arc_drop(arc, attempts, retry_delay).await);

        // Immedetialy after, we should not be able to obtain a strong reference anymore.
        // This test fails only if we have a race condition, so false positive tests are possible.
        assert!(weak.upgrade().is_none());
    }

    #[test]
    fn tokenized_count_sanity_check() {
        let gauge = IntGauge::new("sanity_gauge", "tokenized count test gauge")
            .expect("failed to construct IntGauge in test");

        gauge.inc();
        gauge.inc();
        assert_eq!(gauge.get(), 2);

        let ticket1 = TokenizedCount::new(gauge.clone());
        let ticket2 = TokenizedCount::new(gauge.clone());

        assert_eq!(gauge.get(), 4);
        drop(ticket2);
        assert_eq!(gauge.get(), 3);
        drop(ticket1);
        assert_eq!(gauge.get(), 2);
    }

    #[test]
    fn can_parse_metrics() {
        let sample = r#"
        chain_height 0
        # HELP consensus_current_era the current era in consensus
        # TYPE consensus_current_era gauge
        consensus_current_era 0
        # HELP consumed_ram_bytes total consumed ram in bytes
        # TYPE consumed_ram_bytes gauge
        consumed_ram_bytes 0
        # HELP contract_runtime_apply_commit time in seconds to commit the execution effects of a contract
        # TYPE contract_runtime_apply_commit histogram
        contract_runtime_apply_commit_bucket{le="0.01"} 0
        contract_runtime_apply_commit_bucket{le="0.02"} 0
        contract_runtime_apply_commit_bucket{le="0.04"} 0
        contract_runtime_apply_commit_bucket{le="0.08"} 0
        contract_runtime_apply_commit_bucket{le="0.16"} 0
        "#;

        let extracted = extract_metric_names(sample);

        let mut expected = HashSet::new();
        expected.insert("chain_height");
        expected.insert("consensus_current_era");
        expected.insert("consumed_ram_bytes");
        expected.insert("contract_runtime_apply_commit_bucket");

        assert_eq!(extracted, expected);
    }
}
