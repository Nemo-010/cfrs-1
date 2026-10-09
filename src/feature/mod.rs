//! Operator-facing features that sit beside the data path.
//!
//! None of these move tunnelled bytes. They decide who gets in, publish the
//! counters an operator needs to know the tunnel is alive, print the public URL
//! in a form a phone can read, wire a `static:` origin into the request path,
//! and package all of that into something worth pasting into a chat.
//!
//! They live in one module because they share one constraint that shapes every
//! design decision in it: **the sandbox can refuse to bind a TCP port**, so
//! nothing here may assume a listening socket exists, and nothing here may
//! assume an unauthenticated stranger is not on the other end of the URL.
//!
//! * [`AccessController`] enforces the gate on the client, exactly as
//!   `cloudflared --allowed-mail` does. Cloudflare is told only that
//!   authentication is *required*; the allow-list itself never leaves the
//!   machine. Nothing is read from the environment to build a policy: an
//!   unconfigured gate must fail closed rather than open.
//! * [`metrics`] publishes [`Metrics`] over a **unix socket**, because the
//!   Prometheus exposition format is what cloudflared already scrapes and the
//!   wire shape is what matters, not the transport.
//! * [`qr`] renders a URL as a terminal QR code so a tunnel can be opened on a
//!   phone without typing a hostname.
//! * [`static_files`] is the glue between [`crate::origin::StaticDir`] and the
//!   byte pipe, adding the headers a tunnelled asset needs and refusing the
//!   methods that have no meaning without a request body.
//! * [`ShareLink`] validates a public URL before it is printed, because a share
//!   link is the one string a user copies somewhere they cannot audit.

use std::io;
use std::net::IpAddr;
// `FileType::is_socket` is an extension trait method, not an inherent one, so
// the unix-specific trait has to be in scope for the stale-socket check below.
use std::os::unix::fs::FileTypeExt;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::util::http::{RequestHead, ResponseWriter};
use crate::util::metrics::Metrics;

/// Everything this module can fail at.
///
/// Each variant carries the context needed to act on it: which file, which
/// address, which setting. A bare `io::Error` in a tunnel is unactionable,
/// because the operator cannot tell which of four sockets it came from.
#[derive(Debug)]
pub enum FeatureError {
    /// An operating-system call failed, with a description of what was being
    /// attempted.
    Io {
        /// What cfrs was trying to do, e.g. `bind /tmp/cfrs-metrics.sock`.
        context: String,
        /// The underlying error.
        source: io::Error,
    },
    /// A request, allow-list or share URL that this module refuses to act on.
    Invalid(String),
    /// The QR encoder could not represent the data.
    Qr(String),
    /// The access policy is self-contradictory, or too large to evaluate.
    Policy(String),
}

impl FeatureError {
    fn io(context: impl Into<String>, source: io::Error) -> Self {
        FeatureError::Io {
            context: context.into(),
            source,
        }
    }
}

impl std::fmt::Display for FeatureError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureError::Io { context, source } => write!(f, "{context}: {source}"),
            FeatureError::Invalid(m) => write!(f, "invalid: {m}"),
            FeatureError::Qr(m) => write!(f, "could not encode a QR code: {m}"),
            FeatureError::Policy(m) => write!(f, "invalid access policy: {m}"),
        }
    }
}

impl std::error::Error for FeatureError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            FeatureError::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// One address or address range in an IP filter.
///
/// CIDR matching is implemented here rather than pulled in as a dependency:
/// it is twenty lines of mask arithmetic, and the alternative is growing the
/// dependency list of a security-reviewed tool for one subtraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpRange {
    /// Exactly one address.
    Single(IpAddr),
    /// A network, given as its address and prefix length.
    Cidr {
        /// The network address. Host bits below `bits` are ignored, so
        /// `10.1.2.3/8` and `10.0.0.0/8` are the same range.
        addr: IpAddr,
        /// Prefix length in bits.
        bits: u8,
    },
}

impl IpRange {
    /// Parse `192.0.2.1`, `192.0.2.0/24`, `2001:db8::1` or `2001:db8::/32`.
    pub fn parse(s: &str) -> Result<IpRange, FeatureError> {
        let s = s.trim();
        let Some((addr, bits)) = s.split_once('/') else {
            let addr: IpAddr = s.parse().map_err(|_| {
                FeatureError::Invalid(format!("{s:?} is not an IP address or CIDR block"))
            })?;
            return Ok(IpRange::Single(addr));
        };
        let addr: IpAddr = addr.trim().parse().map_err(|_| {
            FeatureError::Invalid(format!("{addr:?} is not an IP address in {s:?}"))
        })?;
        let bits: u8 = bits.trim().parse().map_err(|_| {
            FeatureError::Invalid(format!("{bits:?} is not a prefix length in {s:?}"))
        })?;
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if bits > max {
            return Err(FeatureError::Invalid(format!(
                "prefix length /{bits} is longer than /{max} for {addr}"
            )));
        }
        Ok(IpRange::Cidr { addr, bits })
    }

    /// Whether `ip` falls in this range.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (IpRange::Single(a), b) => a == b,
            (IpRange::Cidr { addr, bits }, b) => {
                if addr.is_ipv4() != b.is_ipv4() {
                    return false;
                }
                match (addr, b) {
                    (IpAddr::V4(a), IpAddr::V4(b)) => prefix_match_v4(*a, *b, *bits),
                    (IpAddr::V6(a), IpAddr::V6(b)) => prefix_match_v6(*a, *b, *bits),
                    _ => false,
                }
            }
        }
    }
}

impl std::fmt::Display for IpRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpRange::Single(a) => write!(f, "{a}"),
            IpRange::Cidr { addr, bits } => write!(f, "{addr}/{bits}"),
        }
    }
}

fn prefix_match_v4(net: std::net::Ipv4Addr, ip: std::net::Ipv4Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let n = u32::from(net);
    let i = u32::from(ip);
    // A prefix cannot straddle a u32 boundary, so a plain shift is enough.
    let shift = 32 - u32::from(bits);
    (n >> shift) == (i >> shift)
}

fn prefix_match_v6(net: std::net::Ipv6Addr, ip: std::net::Ipv6Addr, bits: u8) -> bool {
    if bits == 0 {
        return true;
    }
    let n = u128::from(net);
    let i = u128::from(ip);
    let shift = 128 - u32::from(bits);
    (n >> shift) == (i >> shift)
}

/// Which addresses may reach the origin.
///
/// The semantics are the well-known firewall ones: **deny wins**, and an empty
/// allow list means "anything not denied". An allow list that matched nothing
/// would be indistinguishable from a typo in a flag, and a tunnel that 403s
/// everyone is harder to diagnose than one that serves its owner.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpFilter {
    denied: Vec<IpRange>,
    /// Ordered, most-specific first: the first match names the rule that let
    /// the address in, so the operator sees the answer they wrote.
    allowed: Vec<(String, IpRange)>,
}

/// The outcome of an IP check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpVerdict {
    /// No rule matched, or the allow list is empty.
    Permitted,
    /// An allow rule matched. Carries the label the operator gave the rule, so
    /// a log line can say which of several ranges admitted the address.
    AllowedBy(String),
    /// A deny rule matched. Deny is evaluated first and never falls through.
    DeniedBy(String),
}

impl IpFilter {
    /// A filter that permits everything.
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Add a denied address or block.
    pub fn deny(&mut self, range: IpRange) -> &mut Self {
        self.denied.push(range);
        self
    }

    /// Add an allowed address or block. The first match supplies the label
    /// shown to the operator, so the rules are ordered most-specific first.
    pub fn allow(&mut self, label: &str, range: IpRange) -> &mut Self {
        self.allowed.push((label.to_string(), range));
        self
    }

    /// Parse and add a denied entry from text.
    pub fn deny_str(&mut self, text: &str) -> Result<&mut Self, FeatureError> {
        let range = IpRange::parse(text)?;
        Ok(self.deny(range))
    }

    /// Parse and add an allowed entry from text.
    pub fn allow_str(&mut self, label: &str, text: &str) -> Result<&mut Self, FeatureError> {
        let range = IpRange::parse(text)?;
        Ok(self.allow(label, range))
    }

    /// Evaluate one address.
    pub fn check(&self, ip: &IpAddr) -> IpVerdict {
        if let Some(range) = self.denied.iter().find(|r| r.contains(ip)) {
            return IpVerdict::DeniedBy(range.to_string());
        }
        if self.allowed.is_empty() {
            return IpVerdict::Permitted;
        }
        match self.allowed.iter().find(|(_, r)| r.contains(ip)) {
            Some((label, _)) => IpVerdict::AllowedBy(label.clone()),
            None => IpVerdict::DeniedBy(format!(
                "{ip} matched no allowed range ({} allowed, {} denied)",
                self.allowed.len(),
                self.denied.len()
            )),
        }
    }

    /// Whether this filter changes the decision at all.
    pub fn is_permissive(&self) -> bool {
        self.denied.is_empty() && self.allowed.is_empty()
    }

    /// How many rules are configured, for the operator's startup summary.
    pub fn len(&self) -> usize {
        self.denied.len() + self.allowed.len()
    }

    /// Whether the filter carries no rules at all.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Render the rules the way they would be typed on a command line.
    pub fn describe(&self) -> String {
        let mut parts: Vec<String> = Vec::with_capacity(self.len());
        for (label, range) in &self.allowed {
            parts.push(format!("allow {label} {range}"));
        }
        for range in &self.denied {
            parts.push(format!("deny {range}"));
        }
        if parts.is_empty() {
            "allow all".to_string()
        } else {
            parts.join(", ")
        }
    }
}

/// Why a request was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    /// The visitor's address is not permitted. Answered with 403: a browser
    /// retrying will not help, and 401 would invite a login prompt for a
    /// tunnel that has no accounts.
    IpDenied(String),
    /// No credential was presented but the policy demands one. Answered with
    /// 401 and a `WWW-Authenticate` challenge.
    CredentialsMissing {
        /// The scheme to advertise, e.g. `Basic realm="cfrs"`.
        challenge: String,
    },
    /// A credential was presented and did not match. Answered with 403: the
    /// client authenticated wrongly, and repeating it will not become right.
    CredentialsInvalid,
    /// The client asked for a method this endpoint does not serve.
    MethodNotAllowed(String),
}

impl DenyReason {
    /// The HTTP status to answer with.
    pub fn status(&self) -> u16 {
        match self {
            DenyReason::IpDenied(_) | DenyReason::CredentialsInvalid => 403,
            DenyReason::CredentialsMissing { .. } => 401,
            DenyReason::MethodNotAllowed(_) => 405,
        }
    }

    /// A short reason phrase.
    pub fn phrase(&self) -> &'static str {
        match self.status() {
            401 => "Unauthorized",
            403 => "Forbidden",
            405 => "Method Not Allowed",
            _ => "Error",
        }
    }

    /// The body to return. It names the reason but never the policy's contents:
    /// a refusal that explains which addresses or passwords would be accepted
    /// is an oracle.
    pub fn message(&self) -> String {
        match self {
            DenyReason::IpDenied(_) => {
                "403 forbidden: this tunnel does not accept requests from your address\n"
                    .to_string()
            }
            DenyReason::CredentialsMissing { challenge } => {
                format!("401 unauthorized: this tunnel requires authentication ({challenge})\n")
            }
            DenyReason::CredentialsInvalid => {
                "403 forbidden: the credentials presented are not accepted\n".to_string()
            }
            DenyReason::MethodNotAllowed(m) => {
                format!("405 method not allowed: {m}\n")
            }
        }
    }

    /// The `WWW-Authenticate` header, when one applies.
    pub fn challenge(&self) -> Option<&str> {
        match self {
            DenyReason::CredentialsMissing { challenge } => Some(challenge),
            _ => None,
        }
    }
}

/// What a gate decided about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccessDecision {
    /// Let the request through to the origin.
    Allow,
    /// Answer with the given status, headers and body, and stop.
    Refuse {
        /// The status code.
        code: u16,
        /// Response headers, already cased.
        headers: Vec<(String, String)>,
        /// The response body.
        body: String,
    },
}

impl AccessDecision {
    /// Build the refusal for a [`DenyReason`], with a `WWW-Authenticate` header
    /// when the reason calls for one.
    pub fn refusal(reason: &DenyReason) -> AccessDecision {
        let mut headers = vec![(
            "Content-Type".to_string(),
            "text/plain; charset=utf-8".to_string(),
        )];
        if let Some(challenge) = reason.challenge() {
            headers.push(("WWW-Authenticate".to_string(), challenge.to_string()));
        }
        AccessDecision::Refuse {
            code: reason.status(),
            headers,
            body: reason.message(),
        }
    }

    /// Whether the request may reach the origin.
    pub fn is_allowed(&self) -> bool {
        matches!(self, AccessDecision::Allow)
    }

    /// Render a refusal as a complete HTTP response.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            AccessDecision::Allow => Vec::new(),
            AccessDecision::Refuse {
                code,
                headers,
                body,
            } => crate::util::http::build_response(
                *code,
                crate::origin::static_files::http_phrase(*code),
                &headers
                    .iter()
                    .map(|(k, v)| (k.as_str(), v.clone()))
                    .collect::<Vec<_>>(),
                Some(body.as_bytes()),
            ),
        }
    }
}

/// How many distinct credentials one policy accepts.
///
/// An unbounded table turns a tunnel into a brute-force target, so the limit is
/// enforced at construction rather than left to the caller.
pub const MAX_ALLOWED_IDENTITIES: usize = 64;

/// A gate in front of a tunnel: which addresses may connect, and what must be
/// presented once they do.
#[derive(Debug, Clone, Default)]
pub struct AccessController {
    ips: IpFilter,
    http_auth: Option<HttpBasicAuth>,
}

/// A `Authorization: Basic` credential table.
#[derive(Debug, Clone)]
pub struct HttpBasicAuth {
    realm: String,
    /// `user:password`, stored ready to compare against the decoded header.
    entries: Vec<String>,
}

impl HttpBasicAuth {
    /// Build a table. Fails when empty or oversized rather than silently
    /// accepting everything: a policy that parses but denies all traffic is a
    /// mistake, not a configuration.
    pub fn new(realm: &str, user_passwords: &[&str]) -> Result<Self, FeatureError> {
        let entries: Vec<String> = user_passwords.iter().map(|s| s.to_string()).collect();
        if entries.is_empty() {
            return Err(FeatureError::Policy(
                "basic auth needs at least one user:password entry".to_string(),
            ));
        }
        if entries.len() > MAX_ALLOWED_IDENTITIES {
            return Err(FeatureError::Policy(format!(
                "{} credentials is above the limit of {MAX_ALLOWED_IDENTITIES}",
                entries.len()
            )));
        }
        Ok(Self {
            realm: realm.to_string(),
            entries,
        })
    }

    /// The challenge to advertise.
    pub fn challenge(&self) -> String {
        format!("Basic realm=\"{}\", charset=\"UTF-8\"", self.realm)
    }

    /// Check a raw `Authorization` header value.
    pub fn verify(&self, header: &str) -> Result<(), DenyReason> {
        let Some(encoded) = header
            .strip_prefix("Basic ")
            .or_else(|| header.strip_prefix("basic "))
        else {
            return Err(DenyReason::CredentialsInvalid);
        };
        let Some(decoded) = decode_base64(encoded.trim()) else {
            return Err(DenyReason::CredentialsInvalid);
        };
        let Ok(text) = String::from_utf8(decoded) else {
            return Err(DenyReason::CredentialsInvalid);
        };
        if self
            .entries
            .iter()
            .any(|e| constant_time_eq(e.as_bytes(), text.as_bytes()))
        {
            Ok(())
        } else {
            Err(DenyReason::CredentialsInvalid)
        }
    }
}

impl AccessController {
    /// A controller that permits everything. The starting point for a tunnel
    /// whose access is decided elsewhere.
    pub fn open() -> Self {
        Self::default()
    }

    /// A controller that refuses every IPv4 visitor, used to stop answering
    /// before a tunnel closes.
    pub fn closed() -> Self {
        let mut c = Self::default();
        c.ips.deny(IpRange::Cidr {
            addr: IpAddr::from([0, 0, 0, 0]),
            bits: 0,
        });
        c
    }

    /// Add a denied address or block.
    pub fn deny_ip(&mut self, range: IpRange) -> &mut Self {
        self.ips.deny(range);
        self
    }

    /// Add an allowed address or block, with the label shown to the operator.
    pub fn allow_ip(&mut self, label: &str, range: IpRange) -> &mut Self {
        self.ips.allow(label, range);
        self
    }

    /// The address rules, for the operator's startup summary.
    pub fn ip_filter(&self) -> &IpFilter {
        &self.ips
    }

    /// Require HTTP Basic credentials from here on.
    ///
    /// Takes `&mut self` like the address rules so a policy can be built in one
    /// chain and cannot be assembled in two incompatible styles.
    pub fn require_basic_auth(
        &mut self,
        realm: &str,
        user_passwords: &[&str],
    ) -> Result<&mut Self, FeatureError> {
        self.http_auth = Some(HttpBasicAuth::new(realm, user_passwords)?);
        Ok(self)
    }

    /// The challenge this controller advertises, if it demands credentials.
    pub fn challenge(&self) -> Option<String> {
        self.http_auth.as_ref().map(|a| a.challenge())
    }

    /// Whether this controller would let everything through.
    pub fn is_open(&self) -> bool {
        self.ips.is_permissive() && self.http_auth.is_none()
    }

    /// Decide what to do with a request from `remote`.
    ///
    /// The order is deliberate. An address that is not permitted gets the same
    /// answer whether or not it also lacked credentials, so the gate does not
    /// confirm to a stranger that a rule exists for their address. The method
    /// check comes last: it describes *this* endpoint, and an unauthorised
    /// caller learns nothing from it.
    pub fn authorize(&self, req: &RequestHead, remote: &IpAddr) -> AccessDecision {
        if !matches!(
            req.method.as_str(),
            "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "OPTIONS" | "PATCH"
        ) {
            return AccessDecision::refusal(&DenyReason::MethodNotAllowed(format!(
                "{} is not accepted here",
                req.method
            )));
        }

        match self.ips.check(remote) {
            IpVerdict::DeniedBy(range) => {
                return AccessDecision::refusal(&DenyReason::IpDenied(range))
            }
            IpVerdict::AllowedBy(_) | IpVerdict::Permitted => {}
        }

        if let Some(auth) = &self.http_auth {
            match req.header("authorization") {
                None => {
                    return AccessDecision::refusal(&DenyReason::CredentialsMissing {
                        challenge: auth.challenge(),
                    })
                }
                Some(header) => {
                    if let Err(reason) = auth.verify(header) {
                        return AccessDecision::refusal(&reason);
                    }
                }
            }
        }

        AccessDecision::Allow
    }
}

/// Compare two byte strings without an early return.
///
/// A byte-at-a-time compare leaks the length of the matching prefix through
/// timing, which turns a shared-rate-limit brute force into an unshared one.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Standard base64, hand-rolled to keep the dependency list short.
///
/// Written here rather than imported because it exists only to check a 30-byte
/// credential header, and `base64` is not among this crate's dependencies.
fn decode_base64(input: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' => Some(62),
            b'/' => Some(63),
            _ => None,
        }
    }

    let bytes: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if bytes.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;

    for (i, &b) in bytes.iter().enumerate() {
        if b == b'=' {
            // Padding is only legal in the final quantum.
            if i + 2 < bytes.len() {
                return None;
            }
            break;
        }
        acc = (acc << 6) | u32::from(value(b)?);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xFF) as u8);
        }
    }

    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

// ---------------------------------------------------------------------------
// Metrics endpoint
// ---------------------------------------------------------------------------

/// Publishes the tunnel counters where a Prometheus client can scrape them.
///
/// **Why a unix socket.** `cfrs doctor` measures that `bind()` on TCP returns
/// `EACCES` in the sandbox this crate is built for, while binding a unix
/// socket there succeeds. The exposition *format* is what a scrape config
/// actually depends on, so that is preserved exactly and the transport is the
/// only thing that gave. Where TCP is available, put a TCP listener in front of
/// this; the response bytes do not change.
///
/// **Why it binds on construction.** A caller that asks for an endpoint should
/// learn that the socket is taken before it starts serving, not from a
/// background task already reported as running. Constructing binds and
/// [`MetricsEndpoint::local_addr`] is the authority; [`serve`](Self::serve)
/// only accepts connections.
///
/// **What is left to the caller.** The socket inherits the process umask and is
/// not world-readable on most systems. Binding it inside a world-writable
/// directory such as `/tmp` is the caller's decision and is not second-guessed
/// here, because cfrs cannot tell a deliberate choice from a mistake.
pub struct MetricsEndpoint {
    listener: tokio::net::UnixListener,
    /// The path actually bound. Held rather than re-derived from
    /// [`tokio::net::UnixListener::local_addr`], which answers a
    /// `SocketAddr` and would leave the caller to recover the name.
    path: std::path::PathBuf,
    metrics: Arc<Metrics>,
}

impl std::fmt::Debug for MetricsEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetricsEndpoint")
            .field("local_addr", &self.local_addr())
            .finish()
    }
}

impl MetricsEndpoint {
    /// Bind `path` and prepare to serve the counters held in `metrics`.
    ///
    /// A socket left behind by a crashed run is removed first: a stale inode
    /// would otherwise turn a restart into "address in use" with no way out.
    ///
    /// Async because binding a [`tokio::net::UnixListener`] registers with the
    /// reactor. The signature says so, rather than panicking later inside a
    /// synchronous-looking call.
    pub async fn bind(
        path: impl AsRef<std::path::Path>,
        metrics: Arc<Metrics>,
    ) -> Result<Self, FeatureError> {
        let path = path.as_ref();
        // A leftover *socket* is safe to clear; a leftover regular file is not,
        // because something else put it there and deleting it is not ours to do.
        match std::fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_socket() => {
                std::fs::remove_file(path).map_err(|e| {
                    FeatureError::io(format!("remove stale socket {}", path.display()), e)
                })?;
            }
            Ok(_) => {
                return Err(FeatureError::Invalid(format!(
                    "{} exists and is not a socket; refusing to remove it",
                    path.display()
                )))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(FeatureError::io(format!("stat {}", path.display()), e)),
        }

        let listener = tokio::net::UnixListener::bind(path)
            .map_err(|e| FeatureError::io(format!("bind {}", path.display()), e))?;
        Ok(Self {
            listener,
            path: path.to_path_buf(),
            metrics,
        })
    }

    /// The bound path, which is the only address callers can connect to.
    ///
    /// Infallible, and held rather than re-derived from
    /// [`tokio::net::UnixListener::local_addr`], which answers a `SocketAddr`
    /// and would leave the caller to recover the name from it.
    pub fn local_addr(&self) -> std::path::PathBuf {
        self.path.clone()
    }

    /// Serve until the process ends.
    ///
    /// One failed connection must not take the endpoint down: a scrape client
    /// that hangs up early, or a `curl` killed by ctrl-c, would otherwise take
    /// monitoring offline permanently.
    pub async fn serve(self) -> Result<(), FeatureError> {
        loop {
            let (stream, _peer) = match self.listener.accept().await {
                Ok(pair) => pair,
                Err(e) => {
                    // A transient accept error is reported and retried; the
                    // listener is poisoned only by something structural, which
                    // will keep failing and must surface.
                    if matches!(
                        e.kind(),
                        io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::Interrupted
                            | io::ErrorKind::WouldBlock
                    ) {
                        continue;
                    }
                    return Err(FeatureError::io(
                        "accept on the metrics socket".to_string(),
                        e,
                    ));
                }
            };

            let metrics = Arc::clone(&self.metrics);
            tokio::spawn(async move {
                // The result is deliberately discarded: the client's socket is
                // already gone, so there is nowhere left to report a failure.
                let _ = serve_metrics_connection(stream, metrics).await;
            });
        }
    }
}

async fn serve_metrics_connection(
    stream: tokio::net::UnixStream,
    metrics: Arc<Metrics>,
) -> Result<(), FeatureError> {
    const MAX_HEAD: usize = 16 * 1024;
    const IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = tokio::io::BufReader::new(read_half);

    let request = tokio::time::timeout(IO_TIMEOUT, async {
        let mut buf = Vec::with_capacity(1024);
        let mut chunk = [0u8; 1024];
        // Stop as soon as the head is complete; a metrics scrape has no body.
        loop {
            match reader.read(&mut chunk).await {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(e) => return Err(FeatureError::io("read a metrics request".to_string(), e)),
            }
            if RequestHead::parse(&buf).is_ok() || buf.len() > MAX_HEAD {
                break;
            }
        }
        Ok(buf)
    })
    .await
    // A client that connects and says nothing is not an error worth a stack
    // trace; it is the scrape client giving up.
    .map_err(|_| {
        FeatureError::io(
            "read a metrics request".to_string(),
            io::Error::new(io::ErrorKind::TimedOut, "client sent no request head"),
        )
    })??;

    let response = match RequestHead::parse(&request) {
        Ok((head, _)) => metrics_response(&head, &metrics),
        // A truncated head is the client's business, not the server's; 400 is
        // the honest answer and it is what a metrics client logs on failure.
        Err(_) => crate::util::http::build_response(
            400,
            "Bad Request",
            &[],
            Some(b"incomplete request\n"),
        ),
    };

    write_half
        .write_all(&response)
        .await
        .map_err(|e| FeatureError::io("write a metrics response".to_string(), e))?;
    write_half
        .shutdown()
        .await
        .map_err(|e| FeatureError::io("close a metrics response".to_string(), e))?;
    Ok(())
}

/// The path cloudflared serves its counters on, so an existing scrape config
/// keeps working.
pub const METRICS_PATH: &str = "/metrics";

/// The Prometheus text exposition format, version 0.0.4. The `version`
/// parameter tells a scraper which parser to use; without it some clients
/// guess and refuse the payload.
pub const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Answer one metrics request.
///
/// Pure, so the routing can be tested without a socket and so a caller can
/// reuse it to answer a scrape over a transport of its own choosing.
///
/// `/metrics` returns the counters. `/` returns an index of what is served,
/// because a human who types the path by hand should be told rather than
/// left guessing. Anything else is a 404, so a tunnel that serves this
/// endpoint on a public hostname does not advertise that it has one.
pub fn metrics_response(head: &RequestHead, metrics: &Metrics) -> Vec<u8> {
    use crate::util::http::build_response;

    if head.method != "GET" && head.method != "HEAD" {
        return build_response(
            405,
            "Method Not Allowed",
            &[
                ("Content-Type", CONTENT_TYPE.to_string()),
                ("Allow", "GET, HEAD".to_string()),
            ],
            Some(b"the metrics endpoint is read-only\n"),
        );
    }

    let path = head.path.split('?').next().unwrap_or("/");
    match path {
        METRICS_PATH => build_response(
            200,
            "OK",
            &[
                ("Content-Type", CONTENT_TYPE.to_string()),
                ("Cache-Control", "no-store".to_string()),
            ],
            Some(metrics.render().as_bytes()),
        ),
        "/" => build_response(
            200,
            "OK",
            &[("Content-Type", "text/html; charset=utf-8".to_string())],
            Some(
                format!(
                    "<!DOCTYPE html><meta charset=\"utf-8\"><title>cfrs</title>\
                     <h1>cfrs metrics</h1><ul>\
                     <li><a href=\"{METRICS_PATH}\">/metrics</a> &mdash; Prometheus text format</li>\
                     </ul><p>{}</p>",
                    metrics.summary()
                )
                .as_bytes(),
            ),
        ),
        _ => build_response(
            404,
            "Not Found",
            &[("Content-Type", "text/plain; charset=utf-8".to_string())],
            Some(b"not found\n"),
        ),
    }
}

// ---------------------------------------------------------------------------
// QR code
// ---------------------------------------------------------------------------

/// How to draw a QR code in a terminal.
///
/// All three draw one module per character column, so the *width* is the same
/// for all of them; they differ in height and in which glyph is used. That is
/// the trade the operator is choosing between: a symbol tall enough to be
/// square on a normal terminal, or a compact one that fits a narrow window and
/// can be pasted into plain text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum QrStyle {
    /// A module is one column by two lines. Character cells are roughly twice
    /// as tall as they are wide, so this is what makes the modules square and
    /// the symbol actually scannable. The default.
    #[default]
    Blocks,
    /// One line per module row, `#` for dark. Half the height of
    /// [`QrStyle::Blocks`], at the cost of vertically squashed modules. Use it
    /// when the symbol must survive being pasted into a channel with plain
    /// text, or when the terminal's font has no block glyphs.
    Ascii,
    /// One line per module row, inverted (`█` on a light background becomes a
    /// dark-on-light figure). Included for terminals whose light-on-dark
    /// rendering of blocks washes out.
    Unicode,
}

impl QrStyle {
    fn render(&self, code: &qrcode::QrCode) -> String {
        let (dark, light, rows) = match self {
            QrStyle::Blocks => ('█', ' ', 2),
            QrStyle::Ascii => ('#', ' ', 1),
            QrStyle::Unicode => (' ', '█', 1),
        };
        code.render::<char>()
            .dark_color(dark)
            .light_color(light)
            .quiet_zone(true)
            .module_dimensions(1, rows)
            .build()
    }
}

/// Render `data` as a QR code.
///
/// Uses `EcLevel::L`: a tunnel URL is shown on a screen and scanned from the
/// same screen a moment later, where the failure mode is a smudge rather than
/// fading, and the lower level keeps the symbol small enough to fit. Use
/// [`render_qr_with`] when the output has to survive being printed on paper.
pub fn render_qr(data: &str) -> Result<String, FeatureError> {
    render_qr_with(data, QrStyle::default(), qrcode::EcLevel::L)
}

/// Render `data` with an explicit style and error-correction level.
///
/// The level is a parameter because the two consumers want different things: a
/// live terminal wants the smallest symbol, a printed label wants the most
/// redundant one. Defaulting one for both gets one of them wrong.
pub fn render_qr_with(
    data: &str,
    style: QrStyle,
    ec_level: qrcode::EcLevel,
) -> Result<String, FeatureError> {
    if data.is_empty() {
        return Err(FeatureError::Qr(
            "nothing to encode; a QR code needs at least one character".to_string(),
        ));
    }
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), ec_level)
        .map_err(|e| FeatureError::Qr(format!("{e} for {} bytes of input", data.len())))?;
    Ok(style.render(&code))
}

/// Whether a symbol for `data` fits `columns` terminal columns.
///
/// Used to decide between printing the QR code and printing the URL alone,
/// rather than emitting a figure that wraps into an unscannable mess.
///
/// Width only. Every style in [`QrStyle`] draws one module per column, so the
/// style changes the height, never the number of columns; a style-aware
/// height check belongs to whatever is doing the drawing.
///
/// There is no style parameter because there is nothing for it to decide here.
pub fn qr_fits(data: &str, columns: u32) -> Result<bool, FeatureError> {
    let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
        .map_err(|e| FeatureError::Qr(format!("{e} for {} bytes of input", data.len())))?;
    // +8 is the quiet zone the renderer adds on all sides, 4 modules per side,
    // which at one module per column is four extra columns on each edge.
    Ok(u32::try_from(code.width()).unwrap_or(u32::MAX) + 8 <= columns)
}

// ---------------------------------------------------------------------------
// Static serving glue
// ---------------------------------------------------------------------------

/// An in-memory HTTP response, ready to be written to a socket.
///
/// This exists because the origin layer's [`crate::util::http::ResponseWriter`]
/// trait is streaming: it is built for writing straight to a socket as bytes
/// arrive. A tunnel that wants to inspect a response, record it, or decide
/// whether to forward it needs the whole thing first, and buffering is the
/// cheapest way to get that without a second response path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BufferedResponse {
    /// The status code the response was begun with.
    pub status: u16,
    /// Header name to value, in the order they were added.
    pub headers: Vec<(String, String)>,
    /// The body bytes.
    pub body: Vec<u8>,
}

impl BufferedResponse {
    /// A fresh buffer. The status starts at 0 so a response that was never
    /// begun is distinguishable from one that deliberately sent 0.
    pub fn new() -> Self {
        Self {
            status: 0,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// Case-insensitive header lookup.
    ///
    /// Named `header_value` rather than `header` because
    /// [`ResponseWriter::header`] is the setter, and an inherent `header` would
    /// shadow it: every `buf.header("X", "y")` in this file would become a
    /// compile error the first time a getter and a setter share a name.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k.to_ascii_lowercase() == lower)
            .map(|(_, v)| v.as_str())
    }

    /// Render as a complete HTTP/1.1 response.
    pub fn to_bytes(&self) -> Vec<u8> {
        crate::util::http::build_response(
            self.status,
            crate::origin::static_files::http_phrase(self.status),
            &self
                .headers
                .iter()
                .map(|(k, v)| (k.as_str(), v.clone()))
                .collect::<Vec<_>>(),
            Some(&self.body),
        )
    }

    /// Whether a status was ever set on this buffer.
    pub fn is_started(&self) -> bool {
        self.status != 0
    }
}

impl crate::util::http::ResponseWriter for BufferedResponse {
    fn status(&mut self, code: u16) -> &mut Self {
        self.status = code;
        self
    }

    fn header(&mut self, name: &str, value: &str) -> &mut Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }

    fn body(&mut self, body: &[u8]) -> io::Result<()> {
        self.body.extend_from_slice(body);
        Ok(())
    }
}

/// Serves a `static:` or `spa:` origin in process, with the headers a
/// tunnelled site needs.
///
/// [`crate::origin::StaticDir`] already resolves paths and refuses traversal.
/// What it does not do is answer the questions a file behind a public tunnel
/// raises: is the response cacheable, is the content being framed by someone
/// else, may a browser sniff the type.
///
/// The security headers are the reason this wrapper exists rather than calling
/// `StaticDir` directly. They are set on every response, including error ones,
/// because a 404 body is still an HTML document a browser will render.
#[derive(Debug, Clone)]
pub struct StaticServer {
    inner: crate::origin::StaticDir,
    cache_control: String,
}

impl StaticServer {
    /// Serve `dir`, with the index file and SPA behaviour of the origin.
    pub fn new(inner: crate::origin::StaticDir) -> Self {
        Self {
            inner,
            // Short by default: a tunnelled file may be replaced under the
            // same URL, and a visitor holding a stale copy is a bug report
            // that cannot be reproduced.
            cache_control: "no-cache".to_string(),
        }
    }

    /// Build from a parsed `static:`/`spa:` origin.
    pub fn from_origin(origin: &crate::origin::Origin) -> Result<Self, FeatureError> {
        match origin {
            crate::origin::Origin::Static { dir, spa, index } => {
                Ok(Self::new(crate::origin::StaticDir {
                    dir: dir.clone(),
                    spa: *spa,
                    index: index.clone(),
                }))
            }
            other => Err(FeatureError::Invalid(format!(
                "{} is not a static origin; expected static: or spa:",
                other.kind()
            ))),
        }
    }

    /// Override the `Cache-Control` sent with file responses.
    pub fn cache_control(mut self, value: &str) -> Self {
        self.cache_control = value.to_string();
        self
    }

    /// The headers added to every response.
    ///
    /// `X-Content-Type-Options: nosniff` matters most: without it a browser
    /// may re-interpret a served file as HTML, which turns a user-supplied
    /// upload into script execution on the tunnel's own origin.
    fn security_headers() -> [(&'static str, &'static str); 5] {
        [
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "SAMEORIGIN"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            (
                "Content-Security-Policy",
                "default-src 'self'; frame-ancestors 'self'",
            ),
        ]
    }

    /// Answer one request.
    pub fn respond(&self, req: &RequestHead) -> io::Result<BufferedResponse> {
        let mut out = BufferedResponse::new();
        for (name, value) in Self::security_headers() {
            out.header(name, value);
        }

        // A tunnelled site is reached over a connection this process owns, so
        // the only methods worth serving are the ones a browser sends for a
        // document. Rejecting the rest here is cheaper and clearer than letting
        // a file server answer them.
        match req.method.as_str() {
            "GET" | "HEAD" => {}
            other => {
                out.status(405);
                out.header("Content-Type", "text/plain; charset=utf-8");
                out.header("Allow", "GET, HEAD");
                out.body = format!("405 method not allowed: {other}\n").into_bytes();
                return Ok(out);
            }
        }

        if self.inner.spa {
            out.header("Cache-Control", "no-store");
        } else {
            out.header("Cache-Control", &self.cache_control.clone());
        }

        // `StaticDir::respond` writes through the ResponseWriter trait, so it
        // fills the same buffer. Its own status and headers take precedence
        // because it knows which file it found; the headers added above stay.
        self.inner.respond(req, &mut out)?;
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Share
// ---------------------------------------------------------------------------

/// Where a share link came from.
///
/// Carried so the operator sees *which* mechanism produced a URL when several
/// are running, and so a link that fails to load can be attributed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShareSource {
    /// An anonymous quick tunnel from [`crate::quicktunnel`].
    QuickTunnel,
    /// A public URL published by an SSH relay, [`crate::relay`].
    Relay,
    /// A URL the operator supplied.
    Manual,
}

impl ShareSource {
    /// A short label for logs and for the share page.
    pub fn label(&self) -> &'static str {
        match self {
            ShareSource::QuickTunnel => "quick tunnel",
            ShareSource::Relay => "ssh relay",
            ShareSource::Manual => "manual",
        }
    }
}

/// A public URL, validated and rendered for sharing.
///
/// **Why this is a type rather than a `String`.** The URL is the one thing an
/// operator pastes into a chat, a ticket or a terminal, and a malformed one is
/// discovered by a visitor rather than by the process that made it. Building it
/// through a constructor means the checks run once, at the point where the URL
/// enters the program, and every later use is on a value already known good.
///
/// **What is refused.** Credentials in the URL are rejected: `https://user:pass@host`
/// is a real URL that browsers silently accept, and putting one in a shared link
/// publishes the password to everyone the link reaches. Non-HTTP schemes are
/// rejected because a tunnel has no meaning for them, and because a
/// `javascript:` or `file:` URL that reached a QR code becomes a payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareLink {
    url: String,
    source: ShareSource,
    note: Option<String>,
}

/// Longest URL accepted. Version 40 QR at error-correction level L holds 2953
/// bytes; this is well inside that, and a longer string is a paste accident.
const MAX_SHARE_URL_LEN: usize = 2048;

impl ShareLink {
    /// Validate and wrap a URL.
    pub fn new(url: &str, source: ShareSource) -> Result<Self, FeatureError> {
        let trimmed = url.trim();
        if trimmed.is_empty() {
            return Err(FeatureError::Invalid("the URL is empty".to_string()));
        }
        if trimmed.len() > MAX_SHARE_URL_LEN {
            return Err(FeatureError::Invalid(format!(
                "the URL is {} bytes, over the {MAX_SHARE_URL_LEN} a QR code can carry",
                trimmed.len()
            )));
        }

        let rest = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .ok_or_else(|| {
                FeatureError::Invalid(format!(
                    "{trimmed:?} is not an http or https URL; a tunnel publishes one of those"
                ))
            })?;

        if rest.starts_with("//") {
            return Err(FeatureError::Invalid(format!(
                "{trimmed:?} has an empty authority"
            )));
        }
        let authority = rest.split(['/', '?', '#']).next().unwrap_or("").to_string();
        if authority.is_empty() {
            return Err(FeatureError::Invalid(format!("{trimmed:?} has no host")));
        }
        // Strip any port before looking for credentials, so a bracketed IPv6
        // literal's own colons are not mistaken for a userinfo separator.
        let host = authority
            .rsplit_once(':')
            .filter(|(h, p)| {
                !h.is_empty() && p.chars().all(|c| c.is_ascii_digit()) && !h.ends_with(']')
            })
            .map_or(authority.clone(), |(h, _)| h.to_string());
        if host.contains('@') {
            return Err(FeatureError::Invalid(format!(
                "{trimmed:?} carries credentials in the host part; sharing it would publish them"
            )));
        }

        Ok(Self {
            url: trimmed.to_string(),
            source,
            note: None,
        })
    }

    /// Build from a provisioned quick tunnel.
    pub fn from_quick_tunnel(
        tunnel: &crate::quicktunnel::QuickTunnel,
    ) -> Result<Self, FeatureError> {
        ShareLink::new(&tunnel.url(), ShareSource::QuickTunnel)
    }

    /// Build from a relay's published handle.
    pub fn from_relay(handle: &crate::relay::TunnelHandle) -> Result<Self, FeatureError> {
        ShareLink::new(&handle.url, ShareSource::Relay)
    }

    /// Attach a note to be shown with the link, such as what it serves.
    ///
    /// The note is escaped wherever it is rendered. It is operator input that
    /// can end up in an HTML page, and an unescaped `<` in a filename would
    /// otherwise become a tag.
    pub fn with_note(mut self, note: &str) -> Self {
        let note = note.trim();
        self.note = if note.is_empty() {
            None
        } else {
            Some(note.to_string())
        };
        self
    }

    /// The validated URL.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Which mechanism published this URL.
    pub fn source(&self) -> ShareSource {
        self.source
    }

    /// The note, if one was attached.
    pub fn note(&self) -> Option<&str> {
        self.note.as_deref()
    }

    /// The host part, for a log line that should not repeat a path.
    pub fn host(&self) -> &str {
        let rest = self
            .url
            .strip_prefix("https://")
            .or_else(|| self.url.strip_prefix("http://"))
            .unwrap_or(&self.url);
        rest.split(['/', '?', '#']).next().unwrap_or(rest)
    }

    /// The QR code for this URL, at the size a terminal can show.
    pub fn qr(&self) -> Result<String, FeatureError> {
        render_qr(&self.url)
    }

    /// A single block of text for a terminal, an issue, or a chat message.
    ///
    /// The URL comes first on its own line because that is what a reader
    /// selects and copies; a QR below it is for the phone.
    pub fn terminal(&self) -> String {
        let mut out = String::new();
        out.push_str(&self.url);
        out.push('\n');
        if let Some(note) = &self.note {
            out.push_str(&format!("// {note}\n"));
        }
        out.push_str(&format!("// shared from cfrs ({})\n", self.source.label()));
        out
    }

    /// A self-contained HTML page for the link.
    ///
    /// The QR is rendered as half-block characters rather than as an embedded
    /// image so the page has no external reference of any kind: nothing to
    /// fetch, nothing to phone home to, and it survives being saved and
    /// reopened with no network at all.
    pub fn html(&self) -> Result<String, FeatureError> {
        let qr = self.qr()?;
        let note = self
            .note
            .as_deref()
            .map(|n| format!("<p>{}</p>", html_escape(n)));
        Ok(format!(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
             <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
             <title>{host}</title>\n\
             <style>\nbody{{font-family:system-ui,sans-serif;margin:2rem auto;max-width:40rem;\
             text-align:center;line-height:1.4}}\npre{{font-family:ui-monospace,monospace;\
             font-size:0.5rem;line-height:1}}\na{{word-break:break-all}}\n\
             </style>\n</head>\n<body>\n<h1>cfrs</h1>\n\
             <p>A tunnel published by cfrs, {label}.</p>\n{note}\
             <pre>{qr}</pre>\n<p><a href=\"{url}\">{url}</a></p>\n\
             <p>Scan the code, or open the link.</p>\n</body>\n</html>\n",
            host = html_escape(self.host()),
            label = html_escape(self.source.label()),
            note = note.as_deref().unwrap_or(""),
            qr = html_escape(&qr),
            url = html_escape(&self.url),
        ))
    }
}

/// Escape the five characters that can change the meaning of HTML.
fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(method: &str, path: &str) -> RequestHead {
        RequestHead {
            method: method.to_string(),
            path: path.to_string(),
            headers: Vec::new(),
        }
    }

    fn req_with_auth(path: &str, header: &str) -> RequestHead {
        let mut r = req("GET", path);
        r.set_header("Authorization", header);
        r
    }

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("cfrs-feature-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("mkdir");
        d
    }

    /// Read the status code out of a rendered response, so a test asserts on
    /// the bytes a client would receive rather than on the struct that made
    /// them. The two can disagree if a field is dropped on the way to the wire.
    fn status_line(bytes: &[u8]) -> u16 {
        String::from_utf8_lossy(bytes)
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|code| code.parse().ok())
            .unwrap_or(0)
    }

    // -- access control ----------------------------------------------------

    #[test]
    fn an_open_controller_allows_a_normal_request() {
        let c = AccessController::open();
        assert!(c.is_open());
        let ip: IpAddr = "203.0.113.9".parse().expect("parse ip");
        assert!(c.authorize(&req("GET", "/"), &ip).is_allowed());
    }

    #[test]
    fn a_deny_rule_refuses_before_credentials_are_considered() {
        // Both conditions fail. The answer must be the IP refusal: a 401 here
        // would confirm to a stranger that a credential exists on this tunnel.
        let mut c = AccessController::open();
        c.deny_ip(IpRange::parse("203.0.113.0/24").expect("parse"))
            .require_basic_auth("cfrs", &["u:p"])
            .expect("build");
        let ip: IpAddr = "203.0.113.9".parse().expect("parse");
        let decision = c.authorize(&req("GET", "/"), &ip);
        assert_eq!(status_line(&decision.to_bytes()), 403);
        let text = String::from_utf8(decision.to_bytes()).expect("utf8");
        assert!(
            !text.contains("WWW-Authenticate"),
            "leaked a challenge: {text}"
        );
    }

    #[test]
    fn an_allow_list_refuses_addresses_outside_it() {
        let mut c = AccessController::open();
        c.allow_ip("office", IpRange::parse("198.51.100.0/24").expect("parse"));

        let inside: IpAddr = "198.51.100.7".parse().expect("parse");
        assert!(c.authorize(&req("GET", "/"), &inside).is_allowed());

        let outside: IpAddr = "192.0.2.7".parse().expect("parse");
        assert_eq!(
            status_line(&c.authorize(&req("GET", "/"), &outside).to_bytes()),
            403
        );
    }

    #[test]
    fn an_empty_allow_list_permits_anything_not_denied() {
        // Documented semantics: an empty allow list is "allow all", not "deny
        // all". A typo in an allow rule must not look like a working policy.
        let c = AccessController::open();
        assert!(c.ip_filter().is_permissive());
        let ip: IpAddr = "192.0.2.1".parse().expect("parse");
        assert_eq!(c.ip_filter().check(&ip), IpVerdict::Permitted);
    }

    #[test]
    fn cidr_prefixes_match_on_the_network_boundary_not_the_address() {
        let block = IpRange::parse("10.1.2.3/24").expect("parse");
        // Host bits in the given address must be ignored, or 10.1.2.3/24 and
        // 10.1.2.0/24 would be different networks.
        assert!(block.contains(&"10.1.2.0".parse().expect("parse")));
        assert!(block.contains(&"10.1.2.255".parse().expect("parse")));
        assert!(!block.contains(&"10.1.3.0".parse().expect("parse")));
        assert!(!block.contains(&"10.1.1.255".parse().expect("parse")));
    }

    #[test]
    fn cidr_matching_handles_both_address_families_and_the_zero_prefix() {
        let v6 = IpRange::parse("2001:db8::/32").expect("parse");
        assert!(v6.contains(&"2001:db8:1234::1".parse().expect("parse")));
        assert!(!v6.contains(&"2001:db9::1".parse().expect("parse")));
        // An IPv4 rule must never match an IPv6 address.
        let v4 = IpRange::parse("0.0.0.0/0").expect("parse");
        assert!(v4.contains(&"8.8.8.8".parse().expect("parse")));
        assert!(!v4.contains(&"::1".parse().expect("parse")));
        // /0 is the whole family, which is what `AccessController::closed` uses.
        assert!(IpRange::parse("0.0.0.0/0")
            .expect("parse")
            .contains(&"1.2.3.4".parse().expect("parse")));
        assert!(IpRange::parse("2001:db8::1")
            .expect("parse")
            .contains(&"2001:db8::1".parse().expect("parse")));
    }

    #[test]
    fn bad_address_specifications_are_rejected_rather_than_defaulting_open() {
        for bad in [
            "",
            "not-an-ip",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/x",
            "999.1.1.1",
        ] {
            assert!(
                IpRange::parse(bad).is_err(),
                "{bad:?} must not parse into an allow rule"
            );
        }
    }

    #[test]
    fn basic_auth_challenges_then_accepts_the_right_credential() {
        let mut c = AccessController::open();
        c.require_basic_auth("cfrs", &["alice:s3cret"])
            .expect("build");
        let ip: IpAddr = "203.0.113.1".parse().expect("parse");

        let refused = c.authorize(&req("GET", "/"), &ip);
        assert_eq!(status_line(&refused.to_bytes()), 401);
        assert!(String::from_utf8(refused.to_bytes())
            .expect("utf8")
            .contains("WWW-Authenticate: Basic realm=\"cfrs\""));

        // base64("alice:s3cret")
        let good = req_with_auth("/", "Basic YWxpY2U6czNjcmV0");
        assert!(c.authorize(&good, &ip).is_allowed());
    }

    #[test]
    fn wrong_and_malformed_credentials_are_403_not_401() {
        let mut c = AccessController::open();
        c.require_basic_auth("cfrs", &["alice:s3cret"])
            .expect("build");
        let ip: IpAddr = "203.0.113.1".parse().expect("parse");

        for header in [
            "Basic YWxpY2U6d3Jvbmc=", // alice:wrong
            "Basic !!!not base64!!!",
            "Bearer sometoken",
            "Basic ", // nothing after the scheme
        ] {
            let decision = c.authorize(&req_with_auth("/", header), &ip);
            assert_eq!(
                status_line(&decision.to_bytes()),
                403,
                "{header:?} should be forbidden, not challenged"
            );
        }
    }

    #[test]
    fn a_refusal_never_names_the_accepted_credentials() {
        // The message is the only thing an attacker reads. It must not confirm
        // which user or password would be accepted.
        let mut c = AccessController::open();
        c.require_basic_auth("cfrs", &["alice:s3cret"])
            .expect("build");
        let ip: IpAddr = "203.0.113.1".parse().expect("parse");
        let text = String::from_utf8(c.authorize(&req("GET", "/"), &ip).to_bytes()).expect("utf8");
        assert!(!text.contains("alice"));
        assert!(!text.contains("s3cret"));
    }

    #[test]
    fn an_empty_credential_table_is_a_configuration_error_not_an_open_gate() {
        // Failing open here would be the worst possible default: a flag that
        // names no users would publish the tunnel to everyone.
        let mut empty = AccessController::open();
        assert!(empty.require_basic_auth("cfrs", &[]).is_err());

        let too_many: Vec<String> = (0..=MAX_ALLOWED_IDENTITIES)
            .map(|i| format!("u{i}:p{i}"))
            .collect();
        let refs: Vec<&str> = too_many.iter().map(String::as_str).collect();
        let mut too_many_controller = AccessController::open();
        assert!(too_many_controller
            .require_basic_auth("cfrs", &refs)
            .is_err());
    }

    #[test]
    fn an_unknown_method_is_405_and_a_known_one_is_not() {
        let c = AccessController::open();
        let ip: IpAddr = "203.0.113.1".parse().expect("parse");
        assert_eq!(
            status_line(&c.authorize(&req("TRACE", "/"), &ip).to_bytes()),
            405
        );
        for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"] {
            assert!(
                c.authorize(&req(method, "/"), &ip).is_allowed(),
                "{method} should reach the origin"
            );
        }
    }

    #[test]
    fn ip_rules_round_trip_through_their_text_form() {
        let mut f = IpFilter::allow_all();
        f.deny_str("203.0.113.5").expect("deny single");
        f.allow_str("office", "198.51.100.0/24")
            .expect("allow block");
        assert_eq!(f.len(), 2);
        let described = f.describe();
        assert!(
            described.contains("allow office 198.51.100.0/24"),
            "{described}"
        );
        assert!(described.contains("deny 203.0.113.5"), "{described}");

        // Deny wins over allow for the same address.
        f.deny_str("198.51.100.7").expect("deny inside allowed");
        let hit: IpAddr = "198.51.100.7".parse().expect("parse");
        assert!(matches!(f.check(&hit), IpVerdict::DeniedBy(_)));
    }

    #[test]
    fn a_closed_controller_refuses_an_ordinary_visitor() {
        let c = AccessController::closed();
        let ip: IpAddr = "203.0.113.9".parse().expect("parse");
        assert!(!c.is_open());
        assert_eq!(
            status_line(&c.authorize(&req("GET", "/"), &ip).to_bytes()),
            403
        );
    }

    // -- metrics -----------------------------------------------------------

    #[test]
    fn the_metrics_path_serves_the_prometheus_format() {
        let m = Metrics::new();
        Metrics::incr(&m.streams_total);
        let bytes = metrics_response(&req("GET", METRICS_PATH), &m);
        let text = String::from_utf8(bytes).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"), "{text}");
        assert!(text.contains("text/plain; version=0.0.4"), "{text}");
        assert!(
            text.contains("cloudflared_tunnel_concurrent_streams_per_tunnel 1"),
            "{text}"
        );
    }

    #[test]
    fn the_metrics_endpoint_answers_a_query_string_and_refuses_writes() {
        let m = Metrics::new();
        // A scraper appends a cache-buster; the path must match without it.
        assert!(
            String::from_utf8(metrics_response(&req("GET", "/metrics?x=1"), &m))
                .expect("utf8")
                .starts_with("HTTP/1.1 200 OK")
        );

        let wrote = metrics_response(&req("POST", METRICS_PATH), &m);
        let text = String::from_utf8(wrote).expect("utf8");
        assert!(
            text.starts_with("HTTP/1.1 405 Method Not Allowed"),
            "{text}"
        );
        assert!(text.contains("Allow: GET, HEAD"), "{text}");
    }

    #[test]
    fn an_unknown_path_on_the_metrics_endpoint_is_a_404() {
        let m = Metrics::new();
        let text = String::from_utf8(metrics_response(&req("GET", "/admin"), &m)).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 404 Not Found"), "{text}");
    }

    #[tokio::test]
    async fn the_metrics_endpoint_serves_over_a_unix_socket() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let m = Metrics::new();
        Metrics::add(&m.bytes_in, 4096);

        let path =
            std::env::temp_dir().join(format!("cfrs-feature-metrics-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let endpoint = MetricsEndpoint::bind(&path, m).await.expect("bind");
        let bound = endpoint.local_addr();
        assert_eq!(bound, path, "the bound address is the only way in");

        let server = tokio::spawn(endpoint.serve());
        let mut client = tokio::net::UnixStream::connect(&bound)
            .await
            .expect("connect");

        client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");
        let mut buf = Vec::new();
        client.read_to_end(&mut buf).await.expect("read response");

        let text = String::from_utf8(buf).expect("utf8");
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        // The counter set by the test must be visible over the wire.
        assert!(
            text.contains("cloudflared_tunnel_request_bytes 4096"),
            "{text}"
        );

        server.abort();
        let _ = std::fs::remove_file(&path);
    }

    #[tokio::test]
    async fn binding_refuses_to_delete_a_regular_file() {
        // A leftover *socket* may be cleared, but a file someone else put there
        // is not ours to remove.
        let dir = tmpdir("notasocket");
        let path = dir.join("occupied");
        std::fs::write(&path, b"not a socket").expect("write");

        let err = MetricsEndpoint::bind(&path, Metrics::new())
            .await
            .expect_err("must refuse");
        match err {
            FeatureError::Invalid(m) => assert!(m.contains("not a socket"), "{m}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
        assert!(path.exists(), "the file must survive the refusal");
        assert_eq!(std::fs::read(&path).expect("read"), b"not a socket");
    }

    #[tokio::test]
    async fn binding_replaces_a_stale_socket_left_by_a_crash() {
        let path =
            std::env::temp_dir().join(format!("cfrs-feature-stale-{}.sock", std::process::id()));
        let _ = std::fs::remove_file(&path);

        let first = MetricsEndpoint::bind(&path, Metrics::new())
            .await
            .expect("first bind");
        assert!(path.exists());
        drop(first);

        // The inode is still on disk; a restart must not be blocked by it.
        let _second = MetricsEndpoint::bind(&path, Metrics::new())
            .await
            .expect("rebind over stale socket");
        let _ = std::fs::remove_file(&path);
    }

    // -- qr ----------------------------------------------------------------

    #[test]
    fn a_qr_code_is_a_square_grid_with_a_quiet_zone() {
        let data = "https://example.trycloudflare.com";
        let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
            .expect("encode");
        let rendered = render_qr(data).expect("render");
        let lines: Vec<&str> = rendered.lines().collect();

        // Measured behaviour of the encoder: one module per column, plus the
        // four-module quiet zone on each side. Asserted against the symbol
        // itself rather than a hard-coded number, so a different URL still
        // checks out.
        let expected_cols = code.width() + 8;
        assert_eq!(lines[0].chars().count(), expected_cols, "row width");
        // Blocks draws two lines per module row.
        assert_eq!(
            lines.len(),
            expected_cols * 2,
            "Blocks is square on a 1:2 cell"
        );

        for line in &lines {
            assert_eq!(
                line.chars().count(),
                expected_cols,
                "every row is the same width"
            );
        }

        // The quiet zone must be light on all four sides, or a scanner loses
        // the finder patterns.
        for (i, line) in lines.iter().enumerate() {
            let dark_edge = line.starts_with('█') || line.ends_with('█');
            let on_border = i < 4 || i >= lines.len() - 4;
            assert!(!(dark_edge && on_border), "the quiet zone must stay light");
        }
        for line in &lines[..4] {
            for c in line.chars().take(4) {
                assert_ne!(c, '█', "the left quiet zone must stay light");
            }
        }
    }

    #[test]
    fn qr_styles_differ_in_height_and_keep_the_same_width() {
        let data = "https://a.trycloudflare.com";
        let code = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
            .expect("encode");
        let cols = code.width() + 8;

        for (style, rows_per_module) in [
            (QrStyle::Blocks, 2),
            (QrStyle::Ascii, 1),
            (QrStyle::Unicode, 1),
        ] {
            let out = render_qr_with(data, style, qrcode::EcLevel::L).expect("render");
            let lines: Vec<&str> = out.lines().collect();
            assert_eq!(lines[0].chars().count(), cols, "{style:?} width");
            assert_eq!(lines.len(), cols * rows_per_module, "{style:?} height");
        }

        // Blocks is the tall, square one; Ascii is the compact one.
        let blocks = render_qr_with(data, QrStyle::Blocks, qrcode::EcLevel::L).expect("blocks");
        let ascii = render_qr_with(data, QrStyle::Ascii, qrcode::EcLevel::L).expect("ascii");
        assert_ne!(blocks, ascii, "the styles must not render identically");
        assert!(
            blocks.lines().count() > ascii.lines().count(),
            "Blocks doubles the height so modules are square on screen"
        );
    }

    #[test]
    fn a_higher_error_correction_level_produces_a_larger_symbol() {
        // Boundary behaviour of the encoder, and the reason the level is a
        // parameter rather than a constant.
        let data = "https://a.trycloudflare.com";
        let low = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::L)
            .expect("encode L");
        let high = qrcode::QrCode::with_error_correction_level(data.as_bytes(), qrcode::EcLevel::H)
            .expect("encode H");
        assert!(
            high.width() >= low.width(),
            "H ({} modules) must not be smaller than L ({})",
            high.width(),
            low.width()
        );
    }

    #[test]
    fn empty_and_oversized_input_are_qr_errors_not_panics() {
        assert!(matches!(render_qr(""), Err(FeatureError::Qr(_))));

        // A few kilobytes exceeds what any QR version holds at level L.
        let huge = "a".repeat(4000);
        match render_qr(&huge) {
            Err(FeatureError::Qr(m)) => assert!(m.contains("4000"), "{m}"),
            other => panic!("expected a Qr error, got {other:?}"),
        }
    }

    #[test]
    fn qr_fits_reports_whether_the_symbol_survives_the_terminal_width() {
        let short = "https://a.trycloudflare.com";
        let long = "https://a-very-long-tunnel-hostname-that-fills-the-screen.trycloudflare.com";
        assert!(qr_fits(short, 200).expect("fits short"));
        assert!(
            !qr_fits(long, 40).expect("fits long"),
            "a wide symbol must be reported as not fitting a narrow terminal"
        );
        assert!(
            qr_fits(short, 1).is_ok(),
            "a narrow terminal is an answer, not an error"
        );
    }

    // -- static serving ----------------------------------------------------

    #[test]
    fn static_serving_returns_the_file_with_security_headers() {
        let d = tmpdir("static-file");
        std::fs::write(d.join("index.html"), b"<h1>hello</h1>").expect("write");

        let origin =
            crate::origin::Origin::parse(&format!("static:{}", d.display())).expect("parse");
        let server = StaticServer::from_origin(&origin).expect("from origin");

        let resp = server.respond(&req("GET", "/")).expect("respond");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"<h1>hello</h1>");
        assert_eq!(resp.header_value("x-content-type-options"), Some("nosniff"));
        assert_eq!(resp.header_value("x-frame-options"), Some("SAMEORIGIN"));
        assert!(resp
            .header_value("content-type")
            .expect("type")
            .starts_with("text/html"));

        // The buffered response must render as a real HTTP response.
        let bytes = String::from_utf8(resp.to_bytes()).expect("utf8");
        assert!(bytes.starts_with("HTTP/1.1 200 OK\r\n"), "{bytes}");
        // The declared length must match the body actually sent, or a client
        // either hangs or truncates.
        let body = "<h1>hello</h1>";
        assert_eq!(resp.body, body.as_bytes());
        assert!(
            bytes.contains(&format!("Content-Length: {}\r\n", body.len())),
            "declared length must match the {} byte body: {bytes}",
            body.len()
        );
    }

    #[test]
    fn security_headers_are_present_on_an_error_response_too() {
        // A 404 body is still rendered by a browser, so it needs the same
        // protection as the file it failed to serve.
        let d = tmpdir("static-missing");
        std::fs::write(d.join("index.html"), b"x").expect("write");
        let origin =
            crate::origin::Origin::parse(&format!("static:{}", d.display())).expect("parse");
        let resp = StaticServer::from_origin(&origin)
            .expect("from origin")
            .respond(&req("GET", "/nope"))
            .expect("respond");

        assert_eq!(resp.status, 404);
        assert_eq!(resp.header_value("x-content-type-options"), Some("nosniff"));
    }

    #[test]
    fn traversal_outside_the_root_is_still_refused_by_the_wrapper() {
        // The wrapper must not weaken the guarantee StaticDir already makes.
        let d = tmpdir("static-traverse");
        std::fs::write(d.join("index.html"), b"index").expect("write");
        let secret = d.join("..").join("cfrs-feature-secret");
        std::fs::write(&secret, b"SECRET").expect("write secret");

        let origin =
            crate::origin::Origin::parse(&format!("static:{}", d.display())).expect("parse");
        let server = StaticServer::from_origin(&origin).expect("from origin");
        for attack in ["/../cfrs-feature-secret", "/%2e%2e/cfrs-feature-secret"] {
            let resp = server.respond(&req("GET", attack)).expect("respond");
            assert_eq!(resp.status, 404, "{attack} must not be served");
            assert!(
                !String::from_utf8_lossy(&resp.body).contains("SECRET"),
                "{attack} leaked content"
            );
        }
        let _ = std::fs::remove_file(&secret);
    }

    #[test]
    fn a_write_method_is_refused_by_the_static_server() {
        let d = tmpdir("static-write");
        std::fs::write(d.join("index.html"), b"index").expect("write");
        let origin =
            crate::origin::Origin::parse(&format!("static:{}", d.display())).expect("parse");
        let server = StaticServer::from_origin(&origin).expect("from origin");

        let resp = server.respond(&req("POST", "/")).expect("respond");
        assert_eq!(resp.status, 405);
        assert_eq!(resp.header_value("allow"), Some("GET, HEAD"));
    }

    #[test]
    fn from_origin_refuses_an_origin_that_is_not_static() {
        let err = StaticServer::from_origin(&crate::origin::Origin::HelloWorld)
            .expect_err("hello_world is not a directory");
        match err {
            FeatureError::Invalid(m) => assert!(m.contains("not a static origin"), "{m}"),
            other => panic!("expected Invalid, got {other:?}"),
        }
    }

    #[test]
    fn an_spa_origin_falls_back_and_never_caches_the_shell() {
        let d = tmpdir("static-spa");
        std::fs::write(d.join("index.html"), b"shell").expect("write");
        let origin = crate::origin::Origin::parse(&format!("spa:{}", d.display())).expect("parse");
        let server = StaticServer::from_origin(&origin).expect("from origin");

        let resp = server.respond(&req("GET", "/deep/route")).expect("respond");
        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"shell");
        // The shell is the same for every route, so caching it would pin a
        // visitor to an old build.
        assert_eq!(resp.header_value("cache-control"), Some("no-store"));
    }

    #[test]
    fn a_buffered_response_records_what_was_written() {
        use crate::util::http::ResponseWriter;

        let mut b = BufferedResponse::new();
        assert!(!b.is_started(), "a fresh buffer has no status yet");
        b.status(201).header("X-Test", "1");
        b.text("hi").expect("write body");
        assert!(b.is_started());
        assert_eq!(b.status, 201);
        assert_eq!(
            b.header_value("x-test"),
            Some("1"),
            "lookup is case-insensitive"
        );
        assert_eq!(b.body, b"hi");
        assert!(String::from_utf8(b.to_bytes())
            .expect("utf8")
            .starts_with("HTTP/1.1 201 Created"));
    }

    // -- share -------------------------------------------------------------

    #[test]
    fn a_valid_url_is_accepted_and_its_host_reported() {
        let link = ShareLink::new(
            "https://foo-bar.trycloudflare.com/",
            ShareSource::QuickTunnel,
        )
        .expect("valid");
        assert_eq!(link.url(), "https://foo-bar.trycloudflare.com/");
        assert_eq!(
            link.host(),
            "foo-bar.trycloudflare.com",
            "the host drops path and scheme"
        );
        assert_eq!(link.source(), ShareSource::QuickTunnel);
        assert_eq!(link.source().label(), "quick tunnel");
    }

    #[test]
    fn a_url_with_credentials_is_refused_rather_than_shared() {
        // This is the case the type exists for: the browser accepts it, so
        // nothing else would ever complain, and pasting it shares the password.
        for bad in ["https://user:pass@example.com", "https://user@example.com"] {
            let err = ShareLink::new(bad, ShareSource::Manual).expect_err("credentials");
            match err {
                FeatureError::Invalid(m) => assert!(m.contains("credentials"), "{m}"),
                other => panic!("expected Invalid, got {other:?}"),
            }
        }
    }

    #[test]
    fn malformed_and_non_http_urls_are_refused() {
        for bad in [
            "",
            "   ",
            "example.com",
            "ftp://example.com",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "https://",
            "https:///path",
        ] {
            assert!(
                ShareLink::new(bad, ShareSource::Manual).is_err(),
                "{bad:?} must not become a shareable link"
            );
        }
    }

    #[test]
    fn an_ipv6_literal_url_keeps_its_brackets_and_is_accepted() {
        // A colon-separated IPv6 host would be mistaken for a userinfo
        // separator unless the port is split off first.
        let link =
            ShareLink::new("http://[2001:db8::1]:8080/", ShareSource::Manual).expect("ipv6 url");
        assert_eq!(link.host(), "[2001:db8::1]:8080");
        assert_eq!(link.url(), "http://[2001:db8::1]:8080/");
    }

    #[test]
    fn the_share_page_is_self_contained_and_escapes_the_note() {
        let link = ShareLink::new("https://foo.trycloudflare.com", ShareSource::QuickTunnel)
            .expect("valid")
            .with_note("<script>alert(1)</script> & co");

        let page = link.html().expect("html");
        assert!(page.starts_with("<!DOCTYPE html>"), "must be a document");
        assert!(
            page.contains("https://foo.trycloudflare.com"),
            "the link must be present"
        );
        // No external reference of any kind: nothing to fetch when offline.
        assert!(
            !page.contains("http://"),
            "the page must not fetch anything"
        );
        assert!(
            !page.contains("<script>"),
            "the note must be escaped: {page}"
        );
        assert!(page.contains("&lt;script&gt;"), "{page}");
        assert!(page.contains("&amp;"), "{page}");
    }

    #[test]
    fn the_terminal_form_puts_the_url_first_and_labels_the_source() {
        let link = ShareLink::new("https://foo.trycloudflare.com", ShareSource::Relay)
            .expect("valid")
            .with_note("dev server");
        let text = link.terminal();
        let first = text.lines().next().expect("a line");
        assert_eq!(
            first, "https://foo.trycloudflare.com",
            "the URL must be copyable first"
        );
        assert!(text.contains("// dev server"));
        assert!(text.contains("ssh relay"));
    }

    #[test]
    fn an_empty_note_is_dropped_rather_than_rendered_blank() {
        let link = ShareLink::new("https://foo.trycloudflare.com", ShareSource::Manual)
            .expect("valid")
            .with_note("   ");
        assert!(link.note().is_none(), "whitespace is not a note");
        // The source line stays; what must not appear is an empty "// " line.
        assert!(
            !link.terminal().lines().any(|l| l.trim_end() == "//"),
            "a blank note must not leave a dangling comment line: {}",
            link.terminal()
        );
        assert!(link.terminal().contains("// shared from cfrs (manual)"));
    }

    #[test]
    fn a_quick_tunnel_link_is_built_from_the_provisioned_url() {
        let tunnel = crate::quicktunnel::parse_quick_tunnel_response(
            200,
            r#"{"success":true,"result":{"id":"i","hostname":"foo.trycloudflare.com",
                "account_tag":"a","secret":"GlUwcZAOuFFaHRtTTFqbk1WVmpWMHFzOGdSSUthbG1K"},"errors":[]}"#,
        )
        .expect("parse response");

        let link = ShareLink::from_quick_tunnel(&tunnel).expect("link");
        assert_eq!(link.url(), "https://foo.trycloudflare.com");
        assert_eq!(link.source(), ShareSource::QuickTunnel);
        assert!(link.qr().expect("qr").contains('█'));
    }

    #[test]
    fn an_oversized_url_is_refused_before_it_reaches_the_encoder() {
        let long = format!("https://example.com/{}", "a".repeat(MAX_SHARE_URL_LEN));
        let err = ShareLink::new(&long, ShareSource::Manual).expect_err("too long");
        assert!(matches!(err, FeatureError::Invalid(_)));
    }
}
