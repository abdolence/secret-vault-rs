use chrono::prelude::*;

pub fn chrono_time_from_prost(ts: prost_types::Timestamp) -> DateTime<Utc> {
    DateTime::<Utc>::from_utc(
        chrono::NaiveDateTime::from_timestamp(ts.seconds, ts.nanos as u32),
        Utc,
    )
}

pub fn chrono_duration_from_prost(duration: prost_types::Duration) -> chrono::Duration {
    chrono::Duration::seconds(duration.seconds)
}
