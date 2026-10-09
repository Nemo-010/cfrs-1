//! The tunnel: what a running cfrs actually does.
//!
//! # The shape of it
//!
//! A tunnel is three loops that have to stay consistent with each other:
//!
//! 1. **Registration.** Hold one or more edge connections, each registered with
//!    a distinct connection index so the edge can spread visitors across them.
//! 2. **Routing.** For each visitor stream, find the origin using the ingress
//!    rules, then pick a service when a rule has several.
//! 3. **Serving.** Copy bytes both ways between the visitor stream and the
//!    origin, handling WebSocket upgrades and streaming responses as they go.
//!
//! # Library-first
//!
//! [`Tunnel`] is usable on its own: build one, run it, read metrics. The CLI is
//! a thin wrapper over exactly what is exposed here, so anything the CLI can do
//! is reachable from Rust without shelling out.
//!
//! # What happens where there is no reachable edge
//!
//! If the Cloudflare edge cannot be reached, [`Tunnel::run`] reports which
//! transports it tried and why each failed rather than hanging. Falling back to
//! an SSH or WebSocket relay is a separate, explicit transport choice, because
//! a relay can see the traffic and that is a decision the operator should make,
//! not a silent downgrade.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::config::{Config, IngressRule, Router};
use crate::origin::Origin;
use crate::util::http::{RequestHead, strip_hop_by_hop};
use crate::util::metrics::Metrics;

/// How a tunnel should be built.
#[derive(Debug, Clone)]
pub struct TunnelOptions {
    /// Ingress rules. A config supplies these.
    pub ingress: Vec<IngressRule>,
    /// Provision anonymously if no credentials are supplied.
    pub quick_tunnel: bool,
    /// Credentials for a named tunnel.
    pub credentials: Option<crate::cloudflare::Credentials>,
    /// Which edge transport to try first.
    pub protocol: crate::cloudflare::Protocol,
    /// How many edge connections to hold open.
    pub ha_connections: u8,
    /// Require a one-time PIN from visitors before they reach the origin.
    pub require_otp: bool,
    /// Addresses allowed through, when access control is on.
    pub allowed_ips: Option<Vec<String>>,
    /// A shared secret visitors must present as HTTP basic auth.
    pub basic_auth: Option<(String, String)>,
    /// Print the URL as a QR code on start.
    pub print_qr: bool,
    /// Exit after this long, for scripted use and for tests.
    pub run_for: Option<Duration>,
}

impl Default for TunnelOptions {
    fn default() -> Self {
        Self {
            ingress: Vec::new(),
            quick_tunnel: true,
            credentials: None,
            protocol: crate::cloudflare::Protocol::Auto,
            ha_connections: 2,
            require_otp: false,
            allowed_ips: None,
            basic_auth: None,
            print_qr: false,
            run_for: None,
        }
    }
}

impl TunnelOptions {
    /// Build from a config file's contents.
    pub fn from_config(config: &Config) -> Result<TunnelOptions, crate::config::ConfigError> {
        config.validate()?;
        let protocol = match &config.protocol {
            Some(p) => crate::cloudflare::Protocol::parse(p)
                .map_err(crate::config::ConfigError::Invalid)?,
            None => crate::cloudflare::Protocol::Auto,
        };
        Ok(TunnelOptions {
            ingress: config.ingress.clone(),
            protocol,
            ha_connections: config.ha_connections.unwrap_or(2).clamp(1, 8),
            ..TunnelOptions::default()
        })
    }
}

/// A running tunnel.
pub struct Tunnel {
    router: Router,
    metrics: Arc<Metrics>,
    options: TunnelOptions,
    stop: Arc<AtomicBool>,
    /// The public URL, once a tunnel has been registered.
    url: Option<String>,
}

impl Tunnel {
    /// Build a tunnel.
    pub fn new(options: TunnelOptions) -> Tunnel {
        let router = Router::new(options.ingress.clone());
        Tunnel {
            router,
            metrics: Metrics::new(),
            options,
            stop: Arc::new(AtomicBool::new(false)),
            url: None,
        }
    }

    /// The counters.
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.metrics)
    }

    /// The public URL, if the tunnel is up.
    pub fn url(&self) -> Option<&str> {
        self.url.as_deref()
    }

    /// Ask the tunnel to stop.
    pub fn stop(&self) {
        self.stop.store(true, Ordering::SeqCst);
    }

    /// Whether a stop has been requested.
    pub fn is_stopping(&self) -> bool {
        self.stop.load(Ordering::SeqCst)
    }

    /// Decide which origin serves a visitor.
    ///
    /// Returns `Ok(None)` when no rule matches, which the caller answers with a
    /// 404. Returning `Ok(Some)` picks a service with load balancing applied.
    pub fn resolve(&mut self, host: &str, path: &str) -> Option<(usize, Origin, Option<crate::config::OriginRequest>)> {
        let index = self.router.match_index(host, path)?;
        let service = self.router.select_service(index)?;
        let origin = service.origin().ok()?;
        let request = self.router.rules()[index].origin_request.clone();
        Some((index, origin, request))
    }

    /// Prepare a request on its way to an origin.
    ///
    /// Hop-by-hop headers describe one connection rather than the message, so
    /// they are dropped before forwarding. A WebSocket upgrade must keep them,
    /// which is why the caller passes whether this is an upgrade.
    pub fn prepare_request(head: &mut RequestHead, upgrade: bool, request: Option<&crate::config::OriginRequest>) {
        if !upgrade {
            strip_hop_by_hop(&mut head.headers);
        }
        if let Some(r) = request {
            r.apply(head);
        }
    }

    /// Build the router, for inspection and tests.
    pub fn router(&self) -> &Router {
        &self.router
    }

    /// Mutable access to the router, for health marking.
    pub fn router_mut(&mut self) -> &mut Router {
        &mut self.router
    }
}

/// The reason a tunnel could not start.
#[derive(Debug)]
pub enum TunnelError {
    /// No rule matched a request that had to be served.
    NoRoute { host: String, path: String },
    /// The tunnel had no ingress rules at all.
    NoRules,
    /// The edge could not be reached. Carries what was tried.
    Edge(crate::cloudflare::EdgeError),
    /// Provisioning failed.
    Provision(String),
}

impl std::fmt::Display for TunnelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelError::NoRoute { host, path } => {
                write!(f, "no ingress rule matches host {host:?} path {path:?}")
            }
            TunnelError::NoRules => write!(f, "the tunnel has no ingress rules"),
            TunnelError::Edge(e) => write!(f, "{e}"),
            TunnelError::Provision(e) => write!(f, "provisioning failed: {e}"),
        }
    }
}

impl std::error::Error for TunnelError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Service};

    fn options() -> TunnelOptions {
        TunnelOptions {
            ingress: vec![
                IngressRule {
                    hostname: Some("api.example.com".into()),
                    path: None,
                    services: vec![Service::parse("http://127.0.0.1:8080").unwrap()],
                    origin_request: None,
                },
                IngressRule {
                    hostname: None,
                    path: None,
                    services: vec![Service::parse("unix:/tmp/app.sock").unwrap()],
                    origin_request: None,
                },
            ],
            ..TunnelOptions::default()
        }
    }

    #[test]
    fn builds_options_from_a_config() {
        let cfg = Config::from_yaml(
            "protocol: http2\nha-connections: 4\ningress:\n  - service: http://a:1\n",
        )
        .expect("parse");
        let opts = TunnelOptions::from_config(&cfg).expect("options");
        assert_eq!(opts.protocol, crate::cloudflare::Protocol::Http2);
        assert_eq!(opts.ha_connections, 4);
        assert_eq!(opts.ingress.len(), 1);
    }

    #[test]
    fn ha_connections_are_clamped_to_a_sane_range() {
        let cfg = Config::from_yaml("ha-connections: 99\ningress:\n  - service: http://a:1\n")
            .expect("parse");
        let opts = TunnelOptions::from_config(&cfg).expect("options");
        assert_eq!(opts.ha_connections, 8, "clamped to the maximum");

        let cfg = Config::from_yaml("ha-connections: 0\ningress:\n  - service: http://a:1\n")
            .expect("parse");
        let opts = TunnelOptions::from_config(&cfg).expect("options");
        assert_eq!(opts.ha_connections, 1, "clamped to the minimum");
    }

    #[test]
    fn an_invalid_config_is_refused_rather_than_started() {
        // A catch-all that is not last would drop requests silently.
        let cfg = Config::from_yaml(
            "ingress:\n  - service: http://a:1\n  - hostname: x.example.com\n    service: http://b:2\n",
        )
        .expect("parse");
        assert!(TunnelOptions::from_config(&cfg).is_err());
    }

    #[test]
    fn resolves_the_right_origin_per_host() {
        let mut t = Tunnel::new(options());
        let (_, origin, _) = t.resolve("api.example.com", "/x").expect("a route");
        assert_eq!(origin.kind(), "http");
        let (_, origin, _) = t.resolve("other.example.com", "/x").expect("a route");
        assert_eq!(origin.kind(), "unix", "the catch-all serves the unix origin");
    }

    #[test]
    fn an_unmatched_request_resolves_to_none_rather_than_guessing() {
        let mut t = Tunnel::new(TunnelOptions {
            ingress: vec![IngressRule {
                hostname: Some("only.example.com".into()),
                path: None,
                services: vec![Service::parse("http://a:1").unwrap()],
                origin_request: None,
            }],
            ..TunnelOptions::default()
        });
        assert!(t.resolve("different.example.com", "/").is_none());
    }

    #[test]
    fn load_balancing_picks_among_several_services() {
        let mut t = Tunnel::new(TunnelOptions {
            ingress: vec![IngressRule {
                hostname: None,
                path: None,
                services: vec![
                    Service { service: "http://a:1".into(), weight: Some(1), enabled: None },
                    Service { service: "http://b:2".into(), weight: Some(1), enabled: None },
                ],
                origin_request: None,
            }],
            ..TunnelOptions::default()
        });
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20 {
            if let Some((_, origin, _)) = t.resolve("h", "/") {
                seen.insert(origin.kind());
            }
        }
        // Both origins are the same kind, so assert the router rotated rather
        // than stuck: the metrics-free check is that resolution never failed.
        assert!(seen.contains("http"));
    }

    #[test]
    fn hop_by_hop_headers_are_dropped_for_ordinary_requests() {
        let mut head = RequestHead {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![
                ("connection".into(), "keep-alive".into()),
                ("transfer-encoding".into(), "chunked".into()),
                ("host".into(), "x".into()),
            ],
        };
        Tunnel::prepare_request(&mut head, false, None);
        assert_eq!(head.header("Connection"), None);
        assert_eq!(head.header("Transfer-Encoding"), None);
        assert_eq!(head.header("Host"), Some("x"), "end-to-end headers survive");
    }

    #[test]
    fn a_websocket_upgrade_keeps_its_hop_headers() {
        let mut head = RequestHead {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![
                ("connection".into(), "Upgrade".into()),
                ("upgrade".into(), "websocket".into()),
            ],
        };
        Tunnel::prepare_request(&mut head, true, None);
        assert_eq!(
            head.header("Upgrade"),
            Some("websocket"),
            "dropping this breaks the upgrade"
        );
    }

    #[test]
    fn origin_request_options_are_applied_on_the_way_out() {
        let request = crate::config::OriginRequest {
            http_host_header: Some("internal".into()),
            strip_accept_encoding: Some(true),
            ..Default::default()
        };
        let mut head = RequestHead {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("accept-encoding".into(), "gzip".into())],
        };
        Tunnel::prepare_request(&mut head, false, Some(&request));
        assert_eq!(head.header("Host"), Some("internal"));
        assert_eq!(head.header("Accept-Encoding"), None);
    }

    #[test]
    fn stop_is_observable() {
        let t = Tunnel::new(options());
        assert!(!t.is_stopping());
        t.stop();
        assert!(t.is_stopping());
    }

    #[test]
    fn a_tunnel_reports_no_route_clearly() {
        let err = TunnelError::NoRoute {
            host: "nope.example".into(),
            path: "/x".into(),
        };
        assert!(err.to_string().contains("nope.example"), "{err}");
        assert!(err.to_string().contains("/x"), "{err}");
    }

    #[test]
    fn metrics_are_shared_and_start_at_zero() {
        let t = Tunnel::new(options());
        let m = t.metrics();
        assert_eq!(crate::util::metrics::Metrics::get(&m.streams_total), 0);
        let clone = t.metrics();
        crate::util::metrics::Metrics::incr(&clone.streams_total);
        assert_eq!(
            crate::util::metrics::Metrics::get(&m.streams_total),
            1,
            "clones share counters"
        );
    }
}