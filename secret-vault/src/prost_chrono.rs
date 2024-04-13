use chrono::prelude::*;

pub(crate) fn chrono_time_from_prost(
    ts: gcloud_sdk::prost_types::Timestamp,
) -> Option<DateTime<Utc>> {
    DateTime::<Utc>::from_timestamp(ts.seconds, ts.nanos as u32)
}

pub(crate) fn chrono_duration_from_prost(
    duration: gcloud_sdk::prost_types::Duration,
) -> chrono::Duration {
    chrono::Duration::seconds(duration.seconds)
}
