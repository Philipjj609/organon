//! RFC 3339 timestamps (UTC, whole seconds) without a date library.

/// Seconds since the Unix epoch for `YYYY-MM-DDTHH:MM:SS…` (fraction and zone ignored: every
/// timestamp organon reads or writes is UTC).
#[must_use]
pub fn epoch_seconds(t: &str) -> Option<i64> {
    let b = t.as_bytes();
    if t.len() < 19 || b[4] != b'-' || b[10] != b'T' {
        return None;
    }
    let n = |r: std::ops::Range<usize>| t.get(r)?.parse::<i64>().ok();
    let (y, m, d) = (n(0..4)?, n(5..7)?, n(8..10)?);
    let (hh, mm, ss) = (n(11..13)?, n(14..16)?, n(17..19)?);
    // Days from civil (Howard Hinnant).
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    Some(days * 86_400 + hh * 3600 + mm * 60 + ss)
}

/// `YYYY-MM-DDTHH:MM:SSZ` for seconds since the Unix epoch.
#[must_use]
pub fn rfc3339(secs: i64) -> String {
    let (days, rem) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Civil from days (Howard Hinnant).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_across_leap_days_and_eras() {
        for t in [
            "1970-01-01T00:00:00Z",
            "2000-02-29T23:59:59Z",
            "2026-11-13T21:38:05Z",
            "2100-03-01T00:00:00Z",
        ] {
            assert_eq!(rfc3339(epoch_seconds(t).unwrap()), t);
        }
        assert_eq!(
            epoch_seconds("2026-11-13T06:55:43.112Z"),
            epoch_seconds("2026-11-13T06:55:43Z")
        );
        assert_eq!(epoch_seconds("yesterday"), None);
    }
}
