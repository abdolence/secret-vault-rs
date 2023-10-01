use chrono::prelude::*;

pub(crate) fn chrono_time_from_prost(
    ts: gcloud_sdk::prost_types::Timestamp,
) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::from_timestamp_opt(ts.seconds, ts.nanos as u32)
        .map(|dt| DateTime::<Utc>::from_naive_utc_and_offset(dt, Utc))
}

pub(crate) fn chrono_duration_from_prost(
    duration: gcloud_sdk::prost_types::Duration,
) -> chrono::Duration {
    chrono::Duration::seconds(duration.seconds)
}
