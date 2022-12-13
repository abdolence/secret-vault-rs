use chrono::prelude::*;

pub(crate) fn chrono_time_from_prost(ts: prost_types::Timestamp) -> Option<DateTime<Utc>> {
    chrono::NaiveDateTime::from_timestamp_opt(ts.seconds, ts.nanos as u32)
        .map(|dt| DateTime::<Utc>::from_utc(dt, Utc))
}

pub(crate) fn chrono_duration_from_prost(duration: prost_types::Duration) -> chrono::Duration {
    chrono::Duration::seconds(duration.seconds)
}
