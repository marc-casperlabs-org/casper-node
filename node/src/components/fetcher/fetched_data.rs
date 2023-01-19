use std::{
    fmt::{self, Display, Formatter},
    sync::Arc,
};

use datasize::DataSize;
use serde::Serialize;

use crate::types::{FetcherItem, NodeId};

#[derive(Clone, DataSize, Debug, PartialEq, Serialize)]
pub(crate) enum FetchedData<T> {
    FromStorage { item: Arc<T> },
    FromPeer { item: Arc<T>, peer: NodeId },
}

impl<T> FetchedData<T> {
    pub(crate) fn from_storage(item: Arc<T>) -> Self {
        FetchedData::FromStorage { item }
    }

    pub(crate) fn from_peer(item: Arc<T>, peer: NodeId) -> Self {
        FetchedData::FromPeer { item, peer }
    }

    /// Clone and convert an instances of a given fetched value.
    pub(crate) fn convert<U>(&self) -> FetchedData<U>
    where
        T: Clone,
        U: From<T>,
    {
        match self {
            FetchedData::FromStorage { item } => FetchedData::FromStorage {
                item: Arc::new((**item).clone().into()),
            },
            FetchedData::FromPeer { item, peer } => FetchedData::FromPeer {
                item: Arc::new((**item).clone().into()),
                peer: *peer,
            },
        }
    }
}

impl<T: FetcherItem> FetchedData<T> {
    pub(crate) fn id(&self) -> T::Id {
        match self {
            FetchedData::FromStorage { item } | FetchedData::FromPeer { peer: _, item } => {
                item.id()
            }
        }
    }
}

impl<T: FetcherItem> Display for FetchedData<T> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            FetchedData::FromStorage { item } => {
                write!(f, "fetched {} from storage", item.id())
            }
            FetchedData::FromPeer { item, peer } => {
                write!(f, "fetched {} from {}", item.id(), peer)
            }
        }
    }
}
