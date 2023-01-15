use std::{
    boxed::Box,
    fmt::{self, Display, Formatter},
};

use serde::{Deserialize, Serialize};

use super::GossiperItem;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(bound = "for<'a> T: Deserialize<'a>")]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub(crate) enum Message<T: GossiperItem> {
    /// Gossiped out to random peers to notify them of an item we hold.
    Gossip(T::Id),
    /// Response to a `Gossip` message.  If `is_already_held` is false, the recipient should treat
    /// this as a `GetRequest` and send a `GetResponse` containing the item.
    GossipResponse {
        item_id: T::Id,
        is_already_held: bool,
    },
    // Request to get an item we were previously told about, but the peer timed out and we never
    // received it.
    GetItem(T::Id),
    // Response to either a `GossipResponse` with `is_already_held` set to `false` or to a
    // `GetItem` message. Contains the actual item requested.
    Item(Box<T>),
}

impl<T: GossiperItem> Display for Message<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        match self {
            Message::Gossip(item_id) => write!(formatter, "gossip({})", item_id),
            Message::GossipResponse {
                item_id,
                is_already_held,
            } => write!(
                formatter,
                "gossip-response({}, {})",
                item_id, is_already_held
            ),
            Message::GetItem(item_id) => write!(formatter, "gossip-get-item({})", item_id),
            Message::Item(item) => write!(formatter, "gossip-item({})", item.id()),
        }
    }
}

#[cfg(test)]
mod specimen_support {
    use crate::{
        testing::specimen::{largest_variant, LargestSpecimen, SizeEstimator},
        types::{GossiperItem, Item},
    };

    use super::{Message, MessageDiscriminants};

    impl<T> LargestSpecimen for Message<T>
    where
        T: GossiperItem + LargestSpecimen,
        <T as Item>::Id: LargestSpecimen,
    {
        fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
            largest_variant::<Self, MessageDiscriminants, _, _>(
                estimator,
                |variant| match variant {
                    MessageDiscriminants::Gossip => {
                        Message::Gossip(LargestSpecimen::largest_specimen(estimator))
                    }
                    MessageDiscriminants::GossipResponse => Message::GossipResponse {
                        item_id: LargestSpecimen::largest_specimen(estimator),
                        is_already_held: LargestSpecimen::largest_specimen(estimator),
                    },
                    MessageDiscriminants::GetItem => {
                        Message::GetItem(LargestSpecimen::largest_specimen(estimator))
                    }
                    MessageDiscriminants::Item => {
                        Message::Item(LargestSpecimen::largest_specimen(estimator))
                    }
                },
            )
        }
    }
}
