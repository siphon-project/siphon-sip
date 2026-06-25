//! Error types for the SIPhon SIP stack.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SiphonError {
    #[error("Auth error: {0}")]
    Auth(String),

    #[error("SIP parse error: {0}")]
    Parse(String),

    #[error("Transport error: {0}")]
    Transport(String),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Script error: {0}")]
    Script(String),

    #[error("RTPEngine error: {0}")]
    RtpEngine(String),

    #[error("Diameter error: {0}")]
    Diameter(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, SiphonError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_error_display() {
        let error = SiphonError::Auth("invalid credentials".to_string());
        assert_eq!(error.to_string(), "Auth error: invalid credentials");
    }

    #[test]
    fn parse_error_display() {
        let error = SiphonError::Parse("unexpected token".to_string());
        assert_eq!(error.to_string(), "SIP parse error: unexpected token");
    }

    #[test]
    fn transport_error_display() {
        let error = SiphonError::Transport("connection refused".to_string());
        assert_eq!(error.to_string(), "Transport error: connection refused");
    }

    #[test]
    fn config_error_display() {
        let error = SiphonError::Config("missing domain field".to_string());
        assert_eq!(error.to_string(), "Config error: missing domain field");
    }

    #[test]
    fn script_error_display() {
        let error = SiphonError::Script("syntax error on line 5".to_string());
        assert_eq!(error.to_string(), "Script error: syntax error on line 5");
    }

    #[test]
    fn rtpengine_error_display() {
        let error = SiphonError::RtpEngine("timeout talking to RTPEngine".to_string());
        assert_eq!(error.to_string(), "RTPEngine error: timeout talking to RTPEngine");
    }

    #[test]
    fn io_error_from_conversion() {
        let io_error = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
        let error: SiphonError = io_error.into();
        assert!(matches!(error, SiphonError::Io(_)));
        assert!(error.to_string().contains("file not found"));
    }

    #[test]
    fn error_is_debug() {
        let error = SiphonError::Parse("test".to_string());
        let debug = format!("{:?}", error);
        assert!(debug.contains("Parse"));
    }

    #[test]
    fn result_type_works_with_ok() {
        let result: Result<i32> = Ok(42);
        match result {
            Ok(value) => assert_eq!(value, 42),
            Err(error) => panic!("expected Ok, got {error:?}"),
        }
    }

    #[test]
    fn result_type_works_with_err() {
        let result: Result<i32> = Err(SiphonError::Parse("bad".to_string()));
        assert!(result.is_err());
    }
}
