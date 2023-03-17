use std::convert::TryInto;

use prometheus::{Counter, IntCounter, IntGauge, Registry};
use strum::{EnumCount, IntoEnumIterator};

use super::{outgoing::OutgoingMetrics, Channel};
use crate::unregister_metric;

/// Network-type agnostic networking metrics.
#[derive(Debug)]
pub(super) struct Metrics {
    /// How often a request was made by a component to broadcast.
    pub(super) broadcast_requests: IntCounter,
    /// How often a request to send a message directly to a peer was made.
    pub(super) direct_message_requests: IntCounter,
    /// Number of connected peers.
    pub(super) peers: IntGauge,

    /// Number of outgoing connections in connecting state.
    pub(super) out_state_connecting: IntGauge,
    /// Number of outgoing connections in waiting state.
    pub(super) out_state_waiting: IntGauge,
    /// Number of outgoing connections in connected state.
    pub(super) out_state_connected: IntGauge,
    /// Number of outgoing connections in blocked state.
    pub(super) out_state_blocked: IntGauge,
    /// Number of outgoing connections in loopback state.
    pub(super) out_state_loopback: IntGauge,

    /// Total time spent delaying outgoing traffic to non-validators due to limiter, in seconds.
    pub(super) accumulated_outgoing_limiter_delay: Counter,
    /// Total time spent delaying incoming traffic from non-validators due to limiter, in seconds.
    pub(super) accumulated_incoming_limiter_delay: Counter,

    /// Per-channel metrics.
    pub(super) channel_metrics: [ChannelMetrics; Channel::COUNT],

    /// Registry instance.
    registry: Registry,
}

/// A set of metrics for a specific channel.
#[derive(Debug, Clone)]
pub(super) struct ChannelMetrics {
    /// Number of messages waiting in the internal queue.
    pub(super) buffer_count: IntGauge,
    /// Number of bytes waiting in the internal queue.
    pub(super) buffer_bytes: IntGauge,
    /// Number of messages pushed to outgoing sinks.
    pub(super) sent_count: IntCounter,
    /// Number of bytes pushed to outgoing sinks.
    pub(super) sent_bytes: IntCounter,
    /// Number of messages received on incoming streams.
    pub(super) received_count: IntCounter,
    /// Number of bytes deserialized from incoming streams.
    pub(super) received_bytes: IntCounter,

    /// Registry instance.
    registry: Registry,
}

impl Metrics {
    /// Creates a new instance of networking metrics.
    pub(super) fn new(registry: &Registry) -> Result<Self, prometheus::Error> {
        let broadcast_requests =
            IntCounter::new("net_broadcast_requests", "number of broadcasting requests")?;
        let direct_message_requests = IntCounter::new(
            "net_direct_message_requests",
            "number of requests to send a message directly to a peer",
        )?;
        let peers = IntGauge::new("peers", "number of connected peers")?;

        let out_state_connecting = IntGauge::new(
            "out_state_connecting",
            "number of connections in the connecting state",
        )?;
        let out_state_waiting = IntGauge::new(
            "out_state_waiting",
            "number of connections in the waiting state",
        )?;
        let out_state_connected = IntGauge::new(
            "out_state_connected",
            "number of connections in the connected state",
        )?;
        let out_state_blocked = IntGauge::new(
            "out_state_blocked",
            "number of connections in the blocked state",
        )?;
        let out_state_loopback = IntGauge::new(
            "out_state_loopback",
            "number of connections in the loopback state",
        )?;

        let requests_for_trie_accepted = IntCounter::new(
            "requests_for_trie_accepted",
            "number of trie requests accepted for processing",
        )?;
        let requests_for_trie_finished = IntCounter::new(
            "requests_for_trie_finished",
            "number of trie requests finished, successful or not",
        )?;

        let accumulated_outgoing_limiter_delay = Counter::new(
            "accumulated_outgoing_limiter_delay",
            "seconds spent delaying outgoing traffic to non-validators due to limiter, in seconds",
        )?;
        let accumulated_incoming_limiter_delay = Counter::new(
            "accumulated_incoming_limiter_delay",
            "seconds spent delaying incoming traffic from non-validators due to limiter, in seconds."
        )?;

        registry.register(Box::new(broadcast_requests.clone()))?;
        registry.register(Box::new(direct_message_requests.clone()))?;
        registry.register(Box::new(peers.clone()))?;

        registry.register(Box::new(out_state_connecting.clone()))?;
        registry.register(Box::new(out_state_waiting.clone()))?;
        registry.register(Box::new(out_state_connected.clone()))?;
        registry.register(Box::new(out_state_blocked.clone()))?;
        registry.register(Box::new(out_state_loopback.clone()))?;

        registry.register(Box::new(requests_for_trie_accepted.clone()))?;
        registry.register(Box::new(requests_for_trie_finished.clone()))?;

        registry.register(Box::new(accumulated_outgoing_limiter_delay.clone()))?;
        registry.register(Box::new(accumulated_incoming_limiter_delay.clone()))?;

        // Constructing channel metrics efficiently without unsafe code and external crates is a
        // bit of a challenge. We eat a single heap allocation and copy here, since this code is
        // only run once anyway.
        let channel_metrics_result: Result<Vec<ChannelMetrics>, prometheus::Error> =
            Channel::iter()
                .map(|channel| ChannelMetrics::new(channel, registry))
                .collect();

        Ok(Metrics {
            broadcast_requests,
            direct_message_requests,
            peers,

            out_state_connecting,
            out_state_waiting,
            out_state_connected,
            out_state_blocked,
            out_state_loopback,

            accumulated_outgoing_limiter_delay,
            accumulated_incoming_limiter_delay,

            channel_metrics: channel_metrics_result?
                .try_into()
                // This expect will only fail if the given `Vec` has the wrong size, which should
                // be impossible.
                .expect("failed to construct channel metrics"),

            registry: registry.clone(),
        })
    }

    /// Creates a set of outgoing metrics that is connected to this set of metrics.
    pub(super) fn create_outgoing_metrics(&self) -> OutgoingMetrics {
        OutgoingMetrics {
            out_state_connecting: self.out_state_connecting.clone(),
            out_state_waiting: self.out_state_waiting.clone(),
            out_state_connected: self.out_state_connected.clone(),
            out_state_blocked: self.out_state_blocked.clone(),
            out_state_loopback: self.out_state_loopback.clone(),
        }
    }
}

impl Drop for Metrics {
    fn drop(&mut self) {
        unregister_metric!(self.registry, self.broadcast_requests);
        unregister_metric!(self.registry, self.direct_message_requests);
        unregister_metric!(self.registry, self.peers);

        unregister_metric!(self.registry, self.out_state_connecting);
        unregister_metric!(self.registry, self.out_state_waiting);
        unregister_metric!(self.registry, self.out_state_connected);
        unregister_metric!(self.registry, self.out_state_blocked);
        unregister_metric!(self.registry, self.out_state_loopback);

        unregister_metric!(self.registry, self.accumulated_outgoing_limiter_delay);
        unregister_metric!(self.registry, self.accumulated_incoming_limiter_delay);
    }
}

impl ChannelMetrics {
    pub(super) fn new(channel: Channel, registry: &Registry) -> Result<Self, prometheus::Error> {
        let lowercase_channel = channel.to_string().to_lowercase();

        let buffer_count = IntGauge::new(
            format!("net_chan_{}_buffer_count", lowercase_channel),
            format!("number of messages buffered on channel {}", channel),
        )?;

        let buffer_bytes = IntGauge::new(
            format!("net_chan_{}_buffer_bytes", lowercase_channel),
            format!("number of payload bytes buffered on channel {}", channel),
        )?;

        let sent_count = IntCounter::new(
            format!("net_chan_{}_sent_count", lowercase_channel),
            format!("number of messages sent on channel {}", channel),
        )?;

        let sent_bytes = IntCounter::new(
            format!("net_chan_{}_sent_size", lowercase_channel),
            format!("number of payload bytes sent on channel {}", channel),
        )?;

        let received_count = IntCounter::new(
            format!("net_chan_{}_received_count", lowercase_channel),
            format!("number of messages received on channel {}", channel),
        )?;

        let received_bytes = IntCounter::new(
            format!("net_chan_{}_received_size", lowercase_channel),
            format!("number of payload bytes received on channel {}", channel),
        )?;

        registry.register(Box::new(buffer_count.clone()))?;
        registry.register(Box::new(buffer_bytes.clone()))?;
        registry.register(Box::new(sent_count.clone()))?;
        registry.register(Box::new(sent_bytes.clone()))?;
        registry.register(Box::new(received_count.clone()))?;
        registry.register(Box::new(received_bytes.clone()))?;

        Ok(ChannelMetrics {
            buffer_count,
            buffer_bytes,
            sent_count,
            sent_bytes,
            received_count,
            received_bytes,
            registry: registry.clone(),
        })
    }
}

impl Drop for ChannelMetrics {
    fn drop(&mut self) {
        unregister_metric!(self.registry, self.buffer_count);
        unregister_metric!(self.registry, self.buffer_bytes);
        unregister_metric!(self.registry, self.sent_count);
        unregister_metric!(self.registry, self.sent_bytes);
        unregister_metric!(self.registry, self.received_count);
        unregister_metric!(self.registry, self.received_bytes);
    }
}
