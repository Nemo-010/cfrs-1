//! Counters for the tunnel, exposed on an optional local endpoint.
//!
//! cloudflared serves `/metrics` on a loopback port. The same numbers are kept
//! here so a monitoring setup works unchanged, and so `cfrs metrics` can print
//! them without binding a port.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// Shared counters. Cheap to clone; all clones share the same values.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Connections registered with the Cloudflare edge.
    pub connections_registered: AtomicU64,
    /// Registration attempts, including retries.
    pub connection_attempts: AtomicU64,
    /// Times the edge connection has been re-established after a drop.
    pub reconnects: AtomicU64,
    /// Data streams accepted from the edge.
    pub streams_total: AtomicU64,
    /// Streams that ended in an error.
    pub stream_errors: AtomicU64,
    /// Bytes received from the edge.
    pub bytes_in: AtomicU64,
    /// Bytes sent to the edge.
    pub bytes_out: AtomicU64,
    /// Requests served by an in-process origin.
    pub requests_served: AtomicU64,
}

impl Metrics {
    /// A fresh, zeroed set.
    pub fn new() -> Arc<Metrics> {
        Arc::new(Metrics::default())
    }

    /// Add to a counter and return the new value.
    pub fn add(counter: &AtomicU64, n: u64) -> u64 {
        counter.fetch_add(n, Ordering::Relaxed) + n
    }

    /// Increment a counter by one.
    pub fn incr(counter: &AtomicU64) {
        counter.fetch_add(1, Ordering::Relaxed);
    }

    /// Read a counter.
    pub fn get(counter: &AtomicU64) -> u64 {
        counter.load(Ordering::Relaxed)
    }

    /// Render the counters in the Prometheus text exposition format.
    ///
    /// The names match cloudflared's so an existing scrape config keeps working.
    pub fn render(&self) -> String {
        let mut out = String::new();
        let mut line = |name: &str, help: &str, value: u64| {
            out.push_str(&format!(
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}\n"
            ));
        };
        line(
            "cloudflared_tunnel_ha_connections",
            "registered edge connections",
            Self::get(&self.connections_registered),
        );
        line(
            "cloudflared_tunnel_total_requests",
            "requests served",
            Self::get(&self.requests_served),
        );
        line(
            "cloudflared_tunnel_request_errors",
            "request errors",
            Self::get(&self.stream_errors),
        );
        line(
            "cloudflared_tunnel_response_bytes",
            "bytes sent to the edge",
            Self::get(&self.bytes_out),
        );
        line(
            "cloudflared_tunnel_request_bytes",
            "bytes received from the edge",
            Self::get(&self.bytes_in),
        );
        line(
            "cloudflared_tunnel_concurrent_streams_per_tunnel",
            "streams accepted",
            Self::get(&self.streams_total),
        );
        line(
            "cloudflared_tunnel_server_locations",
            "reconnects",
            Self::get(&self.reconnects),
        );
        out
    }

    /// A short one-line summary for the console.
    pub fn summary(&self) -> String {
        format!(
            "conns={} streams={} in={}B out={}B errors={} reconnects={}",
            Self::get(&self.connections_registered),
            Self::get(&self.streams_total),
            Self::get(&self.bytes_in),
            Self::get(&self.bytes_out),
            Self::get(&self.stream_errors),
            Self::get(&self.reconnects),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counters_are_shared_between_clones() {
        let m = Metrics::new();
        let clone = Arc::clone(&m);
        Metrics::incr(&m.streams_total);
        Metrics::add(&m.bytes_in, 100);
        assert_eq!(Metrics::get(&clone.streams_total), 1);
        assert_eq!(Metrics::get(&clone.bytes_in), 100);
    }

    #[test]
    fn add_returns_the_running_total() {
        let m = Metrics::default();
        assert_eq!(Metrics::add(&m.bytes_out, 5), 5);
        assert_eq!(Metrics::add(&m.bytes_out, 7), 12);
    }

    #[test]
    fn render_is_prometheus_shaped() {
        let m = Metrics::default();
        Metrics::incr(&m.streams_total);
        let text = m.render();
        assert!(text.contains("# TYPE cloudflared_tunnel_concurrent_streams_per_tunnel counter"));
        assert!(text.contains("cloudflared_tunnel_concurrent_streams_per_tunnel 1\n"));
        assert!(text.lines().all(|l| l.starts_with('#') || l.contains(' ')));
    }

    #[test]
    fn summary_reads_cleanly() {
        let m = Metrics::default();
        assert!(m.summary().contains("streams=0"));
    }
}
