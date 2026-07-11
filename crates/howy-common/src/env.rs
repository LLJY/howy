//! Strict environment-variable parsing shared by daemon and CLI entry points.

use std::ffi::OsStr;

use thiserror::Error;

#[derive(Debug, Error, Eq, PartialEq)]
#[error("{name} must be exactly 0 or 1")]
pub struct StrictBoolError {
    name: &'static str,
}

/// Parse an optional environment value as an exact `0` or `1`.
///
/// Invalid values are deliberately omitted from the error so environment
/// contents cannot be exposed in logs or command output.
pub fn parse_strict_bool(
    name: &'static str,
    value: Option<&OsStr>,
    default: bool,
) -> Result<bool, StrictBoolError> {
    match value {
        None => Ok(default),
        Some(value) if value == OsStr::new("0") => Ok(false),
        Some(value) if value == OsStr::new("1") => Ok(true),
        Some(_) => Err(StrictBoolError { name }),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_strict_bool;
    use std::ffi::{OsStr, OsString};

    #[test]
    fn accepts_only_exact_zero_and_one() {
        assert!(!parse_strict_bool("TEST_GATE", Some(OsStr::new("0")), true).unwrap());
        assert!(parse_strict_bool("TEST_GATE", Some(OsStr::new("1")), false).unwrap());

        for invalid in ["", "true", "01", " 1", "1 "] {
            let error =
                parse_strict_bool("TEST_GATE", Some(OsStr::new(invalid)), false).unwrap_err();
            assert_eq!(error.to_string(), "TEST_GATE must be exactly 0 or 1");
        }
    }

    #[test]
    fn uses_the_requested_unset_default() {
        assert!(!parse_strict_bool("TEST_GATE", None, false).unwrap());
        assert!(parse_strict_bool("TEST_GATE", None, true).unwrap());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_non_utf8_without_exposing_it() {
        use std::os::unix::ffi::OsStringExt;

        let invalid = OsString::from_vec(vec![0xff]);
        let error = parse_strict_bool("TEST_GATE", Some(&invalid), false).unwrap_err();
        assert_eq!(error.to_string(), "TEST_GATE must be exactly 0 or 1");
    }
}
