//! Small shared helpers: logging, TLS configuration, HTTP, and metrics.

pub mod http;
pub mod metrics;
pub mod tls;

/// Whether the process is being run for tests, so behaviour that would touch
/// the network can be skipped.
pub fn is_test() -> bool {
    cfg!(test)
}
