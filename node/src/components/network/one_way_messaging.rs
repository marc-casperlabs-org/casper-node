//! This module is home to the infrastructure to support "one-way" messages, i.e. requests which
//! expect no response.
//!
//! For now, as a side-effect of the original small_network component, all peer-to-peer messages
//! defined outside of the network component are one-way.

use std::{fmt::Debug, future::Future, io, iter, pin::Pin};

use futures::{AsyncReadExt, AsyncWriteExt, FutureExt};
use futures_io::{AsyncRead, AsyncWrite};
use libp2p::{
    request_response::{
        ProtocolSupport, RequestResponse, RequestResponseCodec, RequestResponseConfig,
    },
    PeerId,
};
use prometheus::Registry;

use super::{Config, Error, PayloadT, ProtocolId};
use crate::types::{Chainspec, NodeId};

/// The inner portion of the `ProtocolId` for the one-way message behavior.  A standard prefix and
/// suffix will be applied to create the full protocol name.
const PROTOCOL_NAME_INNER: &str = "validator/one-way";

/// Constructs a new libp2p behavior suitable for use by one-way messaging.
pub(super) fn new_behavior(
    registry: &Registry,
    config: &Config,
    chainspec: &Chainspec,
) -> RequestResponse<Codec> {
    let mut codec = Codec::from(config);
    codec.register_metrics(registry).unwrap();
    let protocol_id = ProtocolId::new(chainspec, PROTOCOL_NAME_INNER);
    let request_response_config = RequestResponseConfig::from(config);
    RequestResponse::new(
        codec,
        iter::once((protocol_id, ProtocolSupport::Full)),
        request_response_config,
    )
}

#[derive(Debug)]
pub(super) struct Outgoing {
    pub destination: PeerId,
    pub message: Vec<u8>,
}

impl Outgoing {
    pub(super) fn new<P: PayloadT>(
        destination: NodeId,
        payload: &P,
        max_size: u32,
    ) -> Result<Self, Error> {
        let serialized_message =
            bincode::serialize(payload).map_err(|error| Error::Serialization(*error))?;

        if serialized_message.len() > max_size as usize {
            return Err(Error::MessageTooLarge {
                max_size,
                actual_size: serialized_message.len() as u64,
            });
        }

        match &destination {
            NodeId::P2p(destination) => Ok(Outgoing {
                destination: destination.clone(),
                message: serialized_message,
            }),
            destination => {
                unreachable!(
                    "can't send to {} (small_network node ID) via libp2p",
                    destination
                )
            }
        }
    }
}

impl From<Outgoing> for Vec<u8> {
    fn from(outgoing: Outgoing) -> Self {
        outgoing.message
    }
}

/// Implements libp2p `RequestResponseCodec` for one-way messages, i.e. requests which expect no
/// response.
#[derive(Debug, Clone)]
pub(super) struct Codec {
    max_message_size: u32,
    in_flight_read_futures: prometheus::Gauge,
    in_flight_write_futures: prometheus::Gauge,
    registry: Option<Registry>,
}

impl Codec {
    fn register_metrics(&mut self, registry: &Registry) -> prometheus::Result<()> {
        assert!(self.registry.is_none());

        registry.register(Box::new(self.in_flight_read_futures.clone()))?;
        registry.register(Box::new(self.in_flight_write_futures.clone()))?;
        self.registry = Some(registry.clone());
        Ok(())
    }
}

impl Drop for Codec {
    fn drop(&mut self) {
        let registry = self.registry.take().unwrap();
        registry
            .unregister(Box::new(self.in_flight_read_futures.clone()))
            .unwrap();
        registry
            .unregister(Box::new(self.in_flight_write_futures.clone()))
            .unwrap();
    }
}

impl From<&Config> for Codec {
    fn from(config: &Config) -> Self {
        Codec {
            max_message_size: config.max_one_way_message_size,
            in_flight_read_futures: prometheus::Gauge::new(
                "owm_read_reaponse_futures",
                "number of do-nothing futures in flight created by `Codec::read_response`",
            )
            .unwrap(),
            in_flight_write_futures: prometheus::Gauge::new(
                "owm_write_response_futures",
                "number of do-nothing futures in flight created by `Codec::write_response`",
            )
            .unwrap(),
            registry: None,
        }
    }
}

impl RequestResponseCodec for Codec {
    type Protocol = ProtocolId;
    type Request = Vec<u8>;
    type Response = ();

    fn read_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Request>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
    {
        async move {
            // Read the length.
            let mut buffer = [0; 4];
            io.read(&mut buffer[..])
                .await
                .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
            let length = u32::from_le_bytes(buffer);
            if length > self.max_message_size {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "message size exceeds limit: {} > {}",
                        length, self.max_message_size
                    ),
                ));
            }

            // Read the payload.
            let mut buffer = vec![0; length as usize];
            io.read_exact(&mut buffer).await?;
            Ok(buffer)
        }
        .boxed()
    }

    fn read_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
    ) -> Pin<Box<dyn Future<Output = io::Result<Self::Response>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
        T: AsyncRead + Unpin + Send + 'async_trait,
    {
        self.in_flight_read_futures.inc();
        let gauge = self.in_flight_read_futures.clone();

        // For one-way messages, where no response will be sent by the peer, just return Ok(()).
        async move {
            gauge.dec();
            Ok(())
        }
        .boxed()
    }

    fn write_request<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        io: &'life2 mut T,
        request: Self::Request,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
    {
        async move {
            // Write the length.
            if request.len() > self.max_message_size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "message size exceeds limit: {} > {}",
                        request.len(),
                        self.max_message_size
                    ),
                ));
            }
            let length = request.len() as u32;
            io.write_all(&length.to_le_bytes()).await?;

            // Write the payload.
            io.write_all(&request).await?;

            io.close().await?;
            Ok(())
        }
        .boxed()
    }

    fn write_response<'life0, 'life1, 'life2, 'async_trait, T>(
        &'life0 mut self,
        _protocol: &'life1 Self::Protocol,
        _io: &'life2 mut T,
        _response: Self::Response,
    ) -> Pin<Box<dyn Future<Output = io::Result<()>> + 'async_trait + Send>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
        T: AsyncWrite + Unpin + Send + 'async_trait,
    {
        self.in_flight_write_futures.inc();
        let gauge = self.in_flight_write_futures.clone();
        // For one-way messages, where no response will be sent by the peer, just return Ok(()).
        async move {
            gauge.dec();
            Ok(())
        }
        .boxed()
    }
}
