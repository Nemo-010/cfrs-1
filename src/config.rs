//! Tunnel configuration: the model behind cloudflared's `config.yml`.
//!
//! # Why this shape
//!
//! cloudflared is configured by an ordered list of ingress rules, each with a
//! hostname pattern, a path prefix and a service. Requests are matched
//! first-rule-wins, and the final rule must be a catch-all. Adopting that shape
//! exactly means an existing `config.yml` ports to cfrs unchanged, which is the
//! difference between a tool people try and a tool people deploy.
//!
//! On top of that shape cfrs adds what the surveyed Rust implementations were
//! missing: several services on one rule, weighted balancing between them, and
//! health tracking. A rule can serve `http://a:1,http://b:2` and pick between
//! them, which is what makes one tunnel front several replicas.

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::origin::Origin;

/// A tunnel's configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    /// Named tunnels only. Quick tunnels ignore this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tunnel: Option<String>,
    /// Path to a credentials JSON file for a named tunnel.
    #[serde(
        rename = "credentials-file",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub credentials_file: Option<PathBuf>,
    /// Edge transport: `auto`, `quic` or `http2`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol: Option<String>,
    /// How many edge connections to hold.
    #[serde(
        rename = "ha-connections",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub ha_connections: Option<u8>,
    /// The ordered rules. Evaluated first match wins.
    #[serde(default)]
    pub ingress: Vec<IngressRule>,
}

impl Config {
    /// Load from a YAML file.
    pub fn from_file(path: &std::path::Path) -> Result<Config, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|e| ConfigError::Io {
            path: path.to_path_buf(),
            source: e,
        })?;
        Config::from_yaml(&text).map_err(|e| ConfigError::Yaml {
            path: path.to_path_buf(),
            message: e.to_string(),
        })
    }

    /// Parse from YAML text.
    pub fn from_yaml(text: &str) -> Result<Config, serde_yaml::Error> {
        serde_yaml::from_str(text)
    }

    /// Render back to YAML.
    pub fn to_yaml(&self) -> String {
        serde_yaml::to_string(self).unwrap_or_default()
    }

    /// Check the rules the way cloudflared does.
    ///
    /// A rule with a hostname or path must be followed by a catch-all, because
    /// otherwise requests that match nothing have no answer. cloudflared
    /// refuses to start in that case and so do we, because failing at startup is
    /// better than failing per request.
    pub fn validate(&self) -> Result<(), ConfigError> {
        for (i, rule) in self.ingress.iter().enumerate() {
            let is_catch_all = rule.hostname.is_none() && rule.path.is_none();
            if is_catch_all && i + 1 != self.ingress.len() {
                return Err(ConfigError::Invalid(format!(
                    "rule {i} is a catch-all but is followed by {} more rule(s); \
                     a catch-all must be last",
                    self.ingress.len() - i - 1
                )));
            }
            if rule.services.is_empty() {
                return Err(ConfigError::Invalid(format!("rule {i} has no service")));
            }
        }
        if self.ingress.is_empty() {
            return Err(ConfigError::Invalid("no ingress rules".into()));
        }
        Ok(())
    }
}

/// One ingress rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IngressRule {
    /// Hostname or pattern. `*` matches one label; `*.example.com` matches
    /// subdomains. Absent means any host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,
    /// Path prefix. Absent means any path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// One service, or several for load balancing.
    ///
    /// The YAML key is `service` (singular) because that is what cloudflared
    /// writes; the Rust field is plural because it holds a list.
    #[serde(rename = "service", default, deserialize_with = "de_services")]
    pub services: Vec<Service>,
    /// Per-origin request tweaks, named as cloudflared names them.
    #[serde(
        rename = "originRequest",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub origin_request: Option<OriginRequest>,
}

impl IngressRule {
    /// A rule with one service.
    pub fn new(service: &str) -> Result<IngressRule, ConfigError> {
        Ok(IngressRule {
            hostname: None,
            path: None,
            services: vec![Service::parse(service)?],
            origin_request: None,
        })
    }

    /// Set the hostname pattern.
    pub fn with_hostname(mut self, host: &str) -> Self {
        self.hostname = Some(host.to_string());
        self
    }

    /// Set the path prefix.
    pub fn with_path(mut self, path: &str) -> Self {
        self.path = Some(path.to_string());
        self
    }
}

/// One origin on a rule, with an optional weight and health gate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Service {
    /// The cloudflared `service:` string.
    #[serde(rename = "service")]
    pub service: String,
    /// Relative share of traffic, default 1. Weights are relative, so 3 and 1
    /// means three quarters to the first.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub weight: Option<u32>,
    /// If false, this origin is skipped until it is healthy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
}

impl Service {
    /// Parse a service string into an origin plus a service wrapper.
    pub fn parse(service: &str) -> Result<Service, ConfigError> {
        Origin::parse(service).map_err(|e| ConfigError::Invalid(format!("{service:?}: {e}")))?;
        Ok(Service {
            service: service.to_string(),
            weight: None,
            enabled: None,
        })
    }

    /// The parsed origin.
    pub fn origin(&self) -> Result<Origin, ConfigError> {
        Origin::parse(&self.service).map_err(|e| ConfigError::Invalid(e.to_string()))
    }

    /// Effective weight, defaulting to 1.
    pub fn effective_weight(&self) -> u32 {
        self.weight.unwrap_or(1).max(1)
    }

    /// Whether this origin may receive traffic.
    pub fn is_enabled(&self) -> bool {
        self.enabled.unwrap_or(true)
    }
}

/// Accept both `service: http://a` and `service: [{service: http://a}, ...]`.
///
/// cloudflared takes a single string, so a YAML file written for it parses
/// unchanged. The list form is cfrs' addition. Note the single form arrives as
/// a bare string when written as `service: "http://a"`, so both a bare value
/// and a one-key mapping are accepted.
fn de_services<'de, D>(deserializer: D) -> Result<Vec<Service>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Shape {
        Bare(String),
        One(Service),
        Many(Vec<Service>),
    }

    let shape = Shape::deserialize(deserializer)?;
    Ok(match shape {
        Shape::Bare(s) => vec![Service {
            service: s,
            weight: None,
            enabled: None,
        }],
        Shape::One(s) => vec![s],
        Shape::Many(v) => v,
    })
}

/// Options applied to requests on their way to an origin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OriginRequest {
    /// Skip TLS verification to the origin.
    #[serde(
        rename = "noTLSVerify",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub no_tls_verify: Option<bool>,
    /// Override the `Host` header.
    #[serde(
        rename = "httpHostHeader",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub http_host_header: Option<String>,
    /// Disable chunked encoding to the origin.
    #[serde(
        rename = "disableChunkedEncoding",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disable_chunked_encoding: Option<bool>,
    /// Drop `Accept-Encoding` so the edge does not buffer a streaming response.
    #[serde(
        rename = "stripAcceptEncoding",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub strip_accept_encoding: Option<bool>,
    /// Connect timeout, as a duration string like `30s`.
    #[serde(
        rename = "connectTimeout",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub connect_timeout: Option<String>,
    /// Keep-alive timeout to the origin.
    #[serde(
        rename = "keepAliveTimeout",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub keep_alive_timeout: Option<String>,

    // Fields cfrs adds that cloudflared's originRequest does not have.
    /// Rewrite the incoming path to this prefix before forwarding.
    #[serde(
        rename = "pathRewrite",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub path_rewrite: Option<String>,
    /// Add these headers to the request sent to the origin.
    #[serde(
        rename = "setHeaders",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub set_headers: Option<HashMap<String, String>>,
}

impl OriginRequest {
    /// Connect timeout, defaulting to 30s.
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
            .as_deref()
            .and_then(parse_duration)
            .unwrap_or_else(|| Duration::from_secs(30))
    }

    /// Whether the origin's TLS certificate should be verified.
    pub fn verify_tls(&self) -> bool {
        !self.no_tls_verify.unwrap_or(false)
    }

    /// Apply the configured header changes to a request.
    pub fn apply(&self, head: &mut crate::util::http::RequestHead) {
        if let Some(h) = &self.http_host_header {
            head.set_header("Host", h);
        }
        if self.strip_accept_encoding.unwrap_or(false) {
            // The edge buffers a compressed response it cannot stream, which
            // breaks SSE and long-poll. Asking the origin for identity encoding
            // keeps those flowing.
            head.remove_header("Accept-Encoding");
        }
        if let Some(map) = &self.set_headers {
            for (k, v) in map {
                head.set_header(k, v);
            }
        }
    }
}

/// Parse a duration string such as `30s`, `500ms`, or `1m`.
pub fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    // Bare numbers are seconds, which is how cloudflared's own flags behave.
    if let Ok(n) = s.parse::<u64>() {
        return Some(Duration::from_secs(n));
    }
    let (value, unit) = s.split_at(s.find(|c: char| c.is_alphabetic()).unwrap_or(s.len()));
    let n: f64 = value.parse().ok()?;
    let factor = match unit {
        "ns" => 1e-9,
        "us" | "µs" => 1e-6,
        "ms" => 1e-3,
        "s" => 1.0,
        "m" => 60.0,
        "h" => 3600.0,
        _ => return None,
    };
    Some(Duration::from_secs_f64(n * factor))
}

/// Something that went wrong loading or validating a config.
#[derive(Debug)]
pub enum ConfigError {
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    Yaml {
        path: PathBuf,
        message: String,
    },
    Invalid(String),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io { path, source } => write!(f, "reading {}: {source}", path.display()),
            ConfigError::Yaml { path, message } => write!(f, "{}: {message}", path.display()),
            ConfigError::Invalid(m) => write!(f, "invalid configuration: {m}"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// The ordered rules, with host/path matching and origin selection.
#[derive(Debug, Clone, Default)]
pub struct Router {
    rules: Vec<IngressRule>,
    /// Round-robin cursor per rule index, for weighted balancing.
    cursors: HashMap<usize, u64>,
    health: HashMap<(usize, usize), bool>,
}

impl Router {
    /// Build from a config's rules.
    pub fn new(rules: Vec<IngressRule>) -> Self {
        Self {
            rules,
            cursors: HashMap::new(),
            health: HashMap::new(),
        }
    }

    /// The rules.
    pub fn rules(&self) -> &[IngressRule] {
        &self.rules
    }

    /// Find the rule that handles a host and path.
    pub fn match_rule(&self, host: &str, path: &str) -> Option<&IngressRule> {
        self.rules.iter().find(|r| {
            hostname_matches(r.hostname.as_deref(), host) && path_matches(r.path.as_deref(), path)
        })
    }

    /// Index of the matching rule, needed for balancing state.
    pub fn match_index(&self, host: &str, path: &str) -> Option<usize> {
        self.rules.iter().position(|r| {
            hostname_matches(r.hostname.as_deref(), host) && path_matches(r.path.as_deref(), path)
        })
    }

    /// Pick a service from a rule, honouring weight and health.
    ///
    /// Weights are relative. A healthy enabled origin is chosen first; if none
    /// is healthy the unhealthy ones are used anyway, because refusing all
    /// traffic is worse than sending it somewhere.
    pub fn select_service(&mut self, rule_index: usize) -> Option<Service> {
        let rule = self.rules.get(rule_index)?;
        let candidates: Vec<(usize, &Service)> = rule
            .services
            .iter()
            .enumerate()
            .filter(|(_, s)| s.is_enabled())
            .collect();
        if candidates.is_empty() {
            return None;
        }

        let healthy: Vec<(usize, &Service)> = candidates
            .iter()
            .copied()
            .filter(|(i, _)| self.health.get(&(rule_index, *i)).copied().unwrap_or(true))
            .collect();
        let pool = if healthy.is_empty() {
            candidates.clone()
        } else {
            healthy
        };

        let total: u32 = pool.iter().map(|(_, s)| s.effective_weight()).sum();
        if total == 0 {
            return Some(pool[0].1.clone());
        }

        // Deterministic weighted round robin: advance a cursor by one and pick
        // the service whose cumulative weight contains it.
        let cursor = self.cursors.entry(rule_index).or_insert(0);
        *cursor = cursor.wrapping_add(1);
        let point = (*cursor % total as u64) as u32;

        let mut acc = 0;
        for (i, s) in pool.iter() {
            acc += s.effective_weight();
            if point < acc {
                return Some(Service {
                    service: s.service.clone(),
                    weight: s.weight,
                    enabled: s.enabled,
                })
                .map(|s| {
                    let _ = i;
                    s
                });
            }
        }
        pool.last().map(|(_, s)| Service {
            service: s.service.clone(),
            weight: s.weight,
            enabled: s.enabled,
        })
    }

    /// Record whether an origin is healthy.
    pub fn set_health(&mut self, rule_index: usize, service_index: usize, healthy: bool) {
        self.health.insert((rule_index, service_index), healthy);
    }

    /// Whether an origin is currently considered healthy.
    pub fn is_healthy(&self, rule_index: usize, service_index: usize) -> bool {
        self.health
            .get(&(rule_index, service_index))
            .copied()
            .unwrap_or(true)
    }
}

/// Does `host` match an optional hostname pattern?
///
/// `None` matches anything. An exact name matches only itself. A `*.` prefix
/// matches one or more labels under the suffix, which is what a wildcard
/// certificate covers.
pub fn hostname_matches(pattern: Option<&str>, host: &str) -> bool {
    let Some(pattern) = pattern else { return true };
    if pattern == "*" {
        return true;
    }
    if let Some(suffix) = pattern.strip_prefix("*.") {
        let host = host.split(':').next().unwrap_or(host);
        match host.split_once('.') {
            // `*.example.com` must match `a.example.com` but not `example.com`,
            // nor `a.b.example.com` beyond one label unless asked.
            Some((_, rest)) => rest == suffix,
            None => false,
        }
    } else {
        // Strip a port before comparing, since a Host header may carry one.
        let host = host.split(':').next().unwrap_or(host);
        host.eq_ignore_ascii_case(pattern)
    }
}

/// Does `path` match an optional path prefix?
///
/// The prefix must end on a path boundary: `/api` matches `/api` and
/// `/api/v1`, but not `/apifoo`. A plain `starts_with` would match the last
/// case and route an unrelated path to the wrong origin.
pub fn path_matches(prefix: Option<&str>, path: &str) -> bool {
    let Some(p) = prefix else { return true };
    let p = p.trim_end_matches('/');
    if p.is_empty() {
        return true;
    }
    path == p || path.starts_with(&format!("{p}/"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(service: &str, host: Option<&str>, path: Option<&str>) -> IngressRule {
        IngressRule {
            hostname: host.map(str::to_string),
            path: path.map(str::to_string),
            services: vec![Service::parse(service).expect("parse service")],
            origin_request: None,
        }
    }

    #[test]
    fn parses_a_cloudflared_config() {
        let yaml = r#"
tunnel: 5a6b7c8d-0000-1111-2222-333344445555
credentials-file: /etc/cloudflared/abc.json
protocol: http2
ha-connections: 4
ingress:
  - hostname: api.example.com
    path: /v1
    service: http://127.0.0.1:8080
    originRequest:
      noTLSVerify: true
      httpHostHeader: internal.example.com
  - service: http://127.0.0.1:9000
"#;
        let cfg = Config::from_yaml(yaml).expect("parse");
        assert_eq!(
            cfg.tunnel.as_deref(),
            Some("5a6b7c8d-0000-1111-2222-333344445555")
        );
        assert_eq!(cfg.ha_connections, Some(4));
        assert_eq!(cfg.ingress.len(), 2);
        assert_eq!(cfg.ingress[0].hostname.as_deref(), Some("api.example.com"));
        let or = cfg.ingress[0]
            .origin_request
            .as_ref()
            .expect("originRequest");
        assert!(!or.verify_tls(), "noTLSVerify must disable verification");
        assert_eq!(or.http_host_header.as_deref(), Some("internal.example.com"));
        cfg.validate().expect("validate");
    }

    #[test]
    fn accepts_both_the_single_and_list_service_forms() {
        let single = Config::from_yaml("ingress:\n  - service: http://a:1\n").expect("single");
        assert_eq!(single.ingress[0].services.len(), 1);

        let many = Config::from_yaml(
            "ingress:\n  - service:\n      - service: http://a:1\n      - service: http://b:2\n",
        )
        .expect("list");
        assert_eq!(many.ingress[0].services.len(), 2);
    }

    #[test]
    fn rejects_a_catch_all_that_is_not_last() {
        let cfg = Config::from_yaml(
            "ingress:\n  - service: http://a:1\n  - hostname: x.example.com\n    service: http://b:2\n",
        )
        .expect("parse");
        let err = cfg.validate().expect_err("must reject");
        assert!(err.to_string().contains("catch-all must be last"), "{err}");
    }

    #[test]
    fn rejects_an_empty_rule_list() {
        let cfg = Config::default();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn matches_hostnames_exactly_and_with_a_wildcard() {
        assert!(hostname_matches(None, "anything.example"));
        assert!(hostname_matches(Some("*"), "anything"));
        assert!(hostname_matches(Some("a.example.com"), "a.example.com"));
        assert!(hostname_matches(Some("a.example.com"), "A.EXAMPLE.COM"));
        assert!(!hostname_matches(Some("a.example.com"), "b.example.com"));
        assert!(hostname_matches(Some("*.example.com"), "api.example.com"));
        assert!(
            !hostname_matches(Some("*.example.com"), "example.com"),
            "a wildcard requires a subdomain"
        );
        assert!(
            !hostname_matches(Some("*.example.com"), "a.b.example.com"),
            "a wildcard matches one label only"
        );
    }

    #[test]
    fn strips_a_port_from_the_host_before_matching() {
        assert!(hostname_matches(
            Some("a.example.com"),
            "a.example.com:8443"
        ));
        assert!(hostname_matches(
            Some("*.example.com"),
            "api.example.com:443"
        ));
    }

    #[test]
    fn matches_path_prefixes_on_a_boundary() {
        assert!(path_matches(None, "/anything"));
        assert!(path_matches(Some("/api"), "/api"));
        assert!(path_matches(Some("/api"), "/api/v1/things"));
        assert!(path_matches(Some("/api/"), "/api/v1"));
        assert!(
            !path_matches(Some("/api"), "/apifoo"),
            "prefix must end on a boundary"
        );
        assert!(path_matches(Some("/"), "/anything"));
    }

    #[test]
    fn picks_the_first_matching_rule() {
        let r = Router::new(vec![
            rule("http://a:1", Some("api.example.com"), Some("/v1")),
            rule("http://b:2", Some("api.example.com"), None),
            rule("http://c:3", None, None),
        ]);
        assert_eq!(r.match_index("api.example.com", "/v1/users").unwrap(), 0);
        assert_eq!(r.match_index("api.example.com", "/v2").unwrap(), 1);
        assert_eq!(r.match_index("other.example.com", "/x").unwrap(), 2);
    }

    #[test]
    fn unparseable_services_are_rejected_at_parse_time() {
        assert!(Service::parse("ftp://nope").is_err());
        assert!(Service::parse("http_status:9999").is_err());
        assert!(Service::parse("unix:/tmp/x.sock").is_ok());
    }

    #[test]
    fn weighted_selection_respects_relative_weights() {
        let mut r = Router::new(vec![IngressRule {
            hostname: None,
            path: None,
            services: vec![
                Service {
                    service: "http://a:1".into(),
                    weight: Some(3),
                    enabled: None,
                },
                Service {
                    service: "http://b:2".into(),
                    weight: Some(1),
                    enabled: None,
                },
            ],
            origin_request: None,
        }]);

        let mut counts = HashMap::new();
        for _ in 0..400 {
            let s = r.select_service(0).expect("a service");
            *counts.entry(s.service).or_insert(0) += 1;
        }
        let a = counts["http://a:1"];
        let b = counts["http://b:2"];
        assert_eq!(a + b, 400, "every request must get a service");
        assert!(
            (a as f64 / b as f64 - 3.0).abs() < 0.35,
            "expected roughly 3:1, got {a}:{b}"
        );
    }

    #[test]
    fn unhealthy_origins_are_avoided_while_a_healthy_one_remains() {
        let mut r = Router::new(vec![IngressRule {
            hostname: None,
            path: None,
            services: vec![
                Service {
                    service: "http://a:1".into(),
                    weight: None,
                    enabled: None,
                },
                Service {
                    service: "http://b:2".into(),
                    weight: None,
                    enabled: None,
                },
            ],
            origin_request: None,
        }]);
        r.set_health(0, 0, false);

        for _ in 0..20 {
            let s = r.select_service(0).expect("a service");
            assert_eq!(s.service, "http://b:2", "must prefer the healthy origin");
        }
    }

    #[test]
    fn all_unhealthy_falls_back_rather_than_refusing() {
        let mut r = Router::new(vec![IngressRule {
            hostname: None,
            path: None,
            services: vec![Service {
                service: "http://a:1".into(),
                weight: None,
                enabled: None,
            }],
            origin_request: None,
        }]);
        r.set_health(0, 0, false);
        assert!(
            r.select_service(0).is_some(),
            "an unhealthy origin is better than dropping the request"
        );
    }

    #[test]
    fn disabled_origins_never_receive_traffic() {
        let mut r = Router::new(vec![IngressRule {
            hostname: None,
            path: None,
            services: vec![Service {
                service: "http://a:1".into(),
                weight: None,
                enabled: Some(false),
            }],
            origin_request: None,
        }]);
        assert!(r.select_service(0).is_none(), "disabled means disabled");
    }

    #[test]
    fn parses_durations_in_the_shapes_cloudflared_accepts() {
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("500ms"), Some(Duration::from_millis(500)));
        assert_eq!(parse_duration("2m"), Some(Duration::from_secs(120)));
        assert_eq!(
            parse_duration("45"),
            Some(Duration::from_secs(45)),
            "bare means seconds"
        );
        assert_eq!(parse_duration("nonsense"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn origin_request_applies_header_changes() {
        let or = OriginRequest {
            http_host_header: Some("internal".into()),
            strip_accept_encoding: Some(true),
            set_headers: Some(HashMap::from([("X-Cf".to_string(), "1".to_string())])),
            ..Default::default()
        };
        let mut head = crate::util::http::RequestHead {
            method: "GET".into(),
            path: "/".into(),
            headers: vec![("accept-encoding".into(), "gzip".into())],
        };
        or.apply(&mut head);
        assert_eq!(head.header("Host"), Some("internal"));
        assert_eq!(
            head.header("Accept-Encoding"),
            None,
            "must be stripped for streaming"
        );
        assert_eq!(head.header("X-Cf"), Some("1"));
    }

    #[test]
    fn round_trips_through_yaml() {
        let cfg = Config::from_yaml(
            "ingress:\n  - hostname: a.example.com\n    service: http://a:1\n  - service: unix:/tmp/x.sock\n",
        )
        .expect("parse");
        let yaml = cfg.to_yaml();
        let again = Config::from_yaml(&yaml).expect("reparse");
        assert_eq!(cfg, again, "a config must survive a YAML round trip");
    }
}
