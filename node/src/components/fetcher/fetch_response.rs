use serde::{Deserialize, Serialize};

/// Message to be returned by a peer. Indicates if the item could be fetched or not.
#[derive(Debug, Serialize, Deserialize)]
#[cfg_attr(test, derive(strum::EnumDiscriminants))]
#[cfg_attr(test, strum_discriminants(derive(strum::EnumIter)))]
pub enum FetchResponse<T, Id> {
    /// The requested item.
    Fetched(T),
    /// The sender does not have the requested item available.
    NotFound(Id),
    /// The sender chose to not provide the requested item.
    NotProvided(Id),
}

impl<T, Id> FetchResponse<T, Id> {
    /// Constructs a fetched or not found from an option and an id.
    pub(crate) fn from_opt(id: Id, item: Option<T>) -> Self {
        match item {
            Some(item) => FetchResponse::Fetched(item),
            None => FetchResponse::NotFound(id),
        }
    }

    /// Returns whether this response is a positive (fetched / "found") one.
    pub(crate) fn was_found(&self) -> bool {
        matches!(self, FetchResponse::Fetched(_))
    }
}

impl<T, Id> FetchResponse<T, Id>
where
    Self: Serialize,
{
    /// The canonical serialization for the inner encoding of the `FetchResponse` response (see
    /// [`Message::GetResponse`]).
    pub(crate) fn to_serialized(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }
}

#[cfg(test)]
mod specimen_support {
    use crate::testing::specimen::{largest_variant, LargestSpecimen, SizeEstimator};
    use serde::Serialize;

    use super::{FetchResponse, FetchResponseDiscriminants};

    impl<T: Serialize + LargestSpecimen, Id: Serialize + LargestSpecimen> LargestSpecimen
        for FetchResponse<T, Id>
    {
        fn largest_specimen<E: SizeEstimator>(estimator: &E) -> Self {
            largest_variant::<Self, FetchResponseDiscriminants, _, _>(estimator, |variant| {
                match variant {
                    FetchResponseDiscriminants::Fetched => {
                        LargestSpecimen::largest_specimen(estimator)
                    }
                    FetchResponseDiscriminants::NotFound => {
                        LargestSpecimen::largest_specimen(estimator)
                    }
                    FetchResponseDiscriminants::NotProvided => {
                        LargestSpecimen::largest_specimen(estimator)
                    }
                }
            })
        }
    }
}
