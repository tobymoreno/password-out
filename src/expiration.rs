use time::{Date, OffsetDateTime, format_description::FormatItem, macros::format_description};

pub const DEFAULT_EXPIRATION_WARNING_DAYS: i64 = 14;

const DATE_FORMAT: &[FormatItem<'static>] = format_description!("[year]-[month]-[day]");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExpirationStatus {
    NoExpiration,
    Valid,
    Warning { days_remaining: i64 },
    ExpiresToday,
    Expired { days_expired: i64 },
}

pub fn parse_expiration_date(value: &str) -> Result<Date, String> {
    Date::parse(value, DATE_FORMAT).map_err(|_| {
        format!(
            "expiration date '{value}' is invalid; expected a real calendar date in YYYY-MM-DD format"
        )
    })
}

pub fn validate_expiration_date(value: Option<&str>) -> Result<(), String> {
    if let Some(value) = value {
        parse_expiration_date(value)?;
    }

    Ok(())
}

pub fn expiration_status(
    expires_on: Option<&str>,
    today: Date,
    warning_days: i64,
) -> Result<ExpirationStatus, String> {
    if warning_days < 0 {
        return Err("expiration warning days cannot be negative".to_string());
    }

    let Some(expires_on) = expires_on else {
        return Ok(ExpirationStatus::NoExpiration);
    };

    let expiration_date = parse_expiration_date(expires_on)?;
    let days_remaining = (expiration_date - today).whole_days();

    if days_remaining < 0 {
        return Ok(ExpirationStatus::Expired {
            days_expired: -days_remaining,
        });
    }

    if days_remaining == 0 {
        return Ok(ExpirationStatus::ExpiresToday);
    }

    if days_remaining <= warning_days {
        return Ok(ExpirationStatus::Warning { days_remaining });
    }

    Ok(ExpirationStatus::Valid)
}

pub fn current_expiration_status(
    expires_on: Option<&str>,
    warning_days: i64,
) -> Result<ExpirationStatus, String> {
    let today = OffsetDateTime::now_utc().date();
    expiration_status(expires_on, today, warning_days)
}

pub fn warning_message(status: ExpirationStatus) -> Option<String> {
    match status {
        ExpirationStatus::NoExpiration | ExpirationStatus::Valid => None,

        ExpirationStatus::Warning { days_remaining: 1 } => {
            Some("Password expires in 1 day".to_string())
        }

        ExpirationStatus::Warning { days_remaining } => {
            Some(format!("Password expires in {days_remaining} days"))
        }

        ExpirationStatus::ExpiresToday => Some("Password expires today".to_string()),

        ExpirationStatus::Expired { days_expired: 1 } => {
            Some("Password expired 1 day ago".to_string())
        }

        ExpirationStatus::Expired { days_expired } => {
            Some(format!("Password expired {days_expired} days ago"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Month;

    fn test_date(year: i32, month: Month, day: u8) -> Date {
        Date::from_calendar_date(year, month, day).expect("test date should be valid")
    }

    #[test]
    fn parses_valid_iso_date() {
        let parsed = parse_expiration_date("2026-08-15").expect("date should parse");

        assert_eq!(parsed, test_date(2026, Month::August, 15));
    }

    #[test]
    fn rejects_invalid_format() {
        let error = parse_expiration_date("08/15/2026").expect_err("date should be rejected");

        assert!(error.contains("YYYY-MM-DD"));
    }

    #[test]
    fn rejects_impossible_calendar_date() {
        assert!(parse_expiration_date("2026-02-30").is_err());
    }

    #[test]
    fn missing_expiration_returns_no_expiration() {
        let status = expiration_status(
            None,
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::NoExpiration);
    }

    #[test]
    fn distant_expiration_is_valid() {
        let status = expiration_status(
            Some("2026-09-01"),
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::Valid);
    }

    #[test]
    fn expiration_inside_warning_window_returns_warning() {
        let status = expiration_status(
            Some("2026-08-10"),
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::Warning { days_remaining: 9 });
    }

    #[test]
    fn expiration_on_warning_boundary_returns_warning() {
        let status = expiration_status(
            Some("2026-08-15"),
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::Warning { days_remaining: 14 });
    }

    #[test]
    fn expiration_today_is_reported() {
        let status = expiration_status(
            Some("2026-08-01"),
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::ExpiresToday);
    }

    #[test]
    fn expired_password_reports_elapsed_days() {
        let status = expiration_status(
            Some("2026-07-29"),
            test_date(2026, Month::August, 1),
            DEFAULT_EXPIRATION_WARNING_DAYS,
        )
        .expect("status should calculate");

        assert_eq!(status, ExpirationStatus::Expired { days_expired: 3 });
    }

    #[test]
    fn warning_messages_use_correct_singular_and_plural_forms() {
        assert_eq!(
            warning_message(ExpirationStatus::Warning { days_remaining: 1 }).as_deref(),
            Some("Password expires in 1 day")
        );

        assert_eq!(
            warning_message(ExpirationStatus::Warning { days_remaining: 2 }).as_deref(),
            Some("Password expires in 2 days")
        );

        assert_eq!(
            warning_message(ExpirationStatus::Expired { days_expired: 1 }).as_deref(),
            Some("Password expired 1 day ago")
        );

        assert_eq!(
            warning_message(ExpirationStatus::Expired { days_expired: 2 }).as_deref(),
            Some("Password expired 2 days ago")
        );
    }

    #[test]
    fn negative_warning_window_is_rejected() {
        let error = expiration_status(Some("2026-08-10"), test_date(2026, Month::August, 1), -1)
            .expect_err("negative warning window should fail");

        assert_eq!(error, "expiration warning days cannot be negative");
    }
}
