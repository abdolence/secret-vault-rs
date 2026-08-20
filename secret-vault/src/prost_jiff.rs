use jiff::{SignedDuration, Timestamp};

pub(crate) fn timestamp_from_prost(ts: gcloud_sdk::prost_types::Timestamp) -> Option<Timestamp> {
    Timestamp::new(ts.seconds, ts.nanos).ok()
}

pub(crate) fn duration_from_prost(duration: gcloud_sdk::prost_types::Duration) -> SignedDuration {
    SignedDuration::from_secs(duration.seconds)
}
