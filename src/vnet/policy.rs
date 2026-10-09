//! Connect-time access policy.
//!
//! Because every connection is a userspace socket, routing policy can decide
//! which virtual addresses a process may reach, per process, without a kernel
//! netfilter rule, an eBPF program or any privilege. The reactor evaluates
//! this when a connect command arrives and returns a policy error to the
//! caller (`PermissionDenied`, which a shimmed program sees as `EACCES`).

use std::fmt;
use std::net::IpAddr;

use anyhow::{bail, Result};

/// What to do with a destination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AclAction {
    Allow,
    Deny,
}

impl AclAction {
    pub fn parse(value: &str) -> Result<Self> {
        match value.to_ascii_lowercase().as_str() {
            "allow" | "accept" | "pass" => Ok(Self::Allow),
            "deny" | "reject" | "drop" => Ok(Self::Deny),
            other => bail!("ACL action {other:?} is not allow or deny"),
        }
    }

    pub fn is_allow(self) -> bool {
        self == Self::Allow
    }
}

impl fmt::Display for AclAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        })
    }
}

/// An address range, v4 or v6, or everything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IpNet {
    Any,
    V4 { base: [u8; 4], prefix: u8 },
    V6 { base: [u8; 16], prefix: u8 },
}

impl IpNet {
    /// Parse `10.66.0.0/24`, `10.66.0.2` (host), `fd00:66::/64`, `::/0` or `*`.
    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value == "*" || value.eq_ignore_ascii_case("any") {
            return Ok(Self::Any);
        }
        match value.split_once('/') {
            Some((addr, prefix)) => {
                let prefix: u8 = prefix
                    .parse()
                    .map_err(|_| anyhow::anyhow!("bad prefix length in {value:?}"))?;
                Self::host(addr, prefix)
            }
            None => {
                // No prefix: a host route. Pick the family's full length.
                if value.parse::<std::net::Ipv4Addr>().is_ok() {
                    Self::host(value, 32)
                } else {
                    Self::host(value, 128)
                }
            }
        }
    }

    fn host(addr: &str, prefix: u8) -> Result<Self> {
        let ip: IpAddr = addr
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("bad IP address {addr:?}"))?;
        match ip {
            IpAddr::V4(ip) => {
                if prefix > 32 {
                    bail!("IPv4 prefix {prefix} is over 32");
                }
                Ok(Self::V4 { base: ip.octets(), prefix })
            }
            IpAddr::V6(ip) => {
                if prefix > 128 {
                    bail!("IPv6 prefix {prefix} is over 128");
                }
                Ok(Self::V6 { base: ip.octets(), prefix })
            }
        }
    }

    /// A host route for one address (prefix 32/128).
    pub fn host_route(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(ip) => Self::V4 { base: ip.octets(), prefix: 32 },
            IpAddr::V6(ip) => Self::V6 { base: ip.octets(), prefix: 128 },
        }
    }

    pub fn contains(&self, ip: &IpAddr) -> bool {
        match (self, ip) {
            (Self::Any, _) => true,
            (Self::V4 { base, prefix }, IpAddr::V4(ip)) => {
                prefix_match(&base[..], &ip.octets(), *prefix)
            }
            (Self::V6 { base, prefix }, IpAddr::V6(ip)) => {
                prefix_match(&base[..], &ip.octets(), *prefix)
            }
            _ => false,
        }
    }
}

fn prefix_match(base: &[u8], candidate: &[u8], prefix: u8) -> bool {
    let whole = (prefix / 8) as usize;
    let bits = prefix % 8;
    if base[..whole] != candidate[..whole] {
        return false;
    }
    if bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - bits);
    (base[whole] & mask) == (candidate[whole] & mask)
}

/// One rule: an action, a network, and optional ports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AclRule {
    pub action: AclAction,
    pub net: IpNet,
    pub ports: PortRange,
}

/// A port selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortRange {
    Any,
    Single(u16),
    Range(u16, u16),
}

impl PortRange {
    pub fn contains(&self, port: u16) -> bool {
        match self {
            Self::Any => true,
            Self::Single(value) => *value == port,
            Self::Range(low, high) => (*low..=*high).contains(&port),
        }
    }

    pub fn parse(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.is_empty() {
            return Ok(Self::Any);
        }
        match value.split_once('-') {
            Some((low, high)) => {
                let low: u16 = low.trim().parse().map_err(|_| anyhow::anyhow!("bad port {low:?}"))?;
                let high: u16 = high.trim().parse().map_err(|_| anyhow::anyhow!("bad port {high:?}"))?;
                if low > high {
                    bail!("port range {low}-{high} is reversed");
                }
                Ok(Self::Range(low, high))
            }
            None => {
                let port: u16 = value.parse().map_err(|_| anyhow::anyhow!("bad port {value:?}"))?;
                Ok(Self::Single(port))
            }
        }
    }
}

impl AclRule {
    /// Parse `allow 10.66.0.0/24:80-90`, `deny *`, `allow 10.66.0.2:443`.
    ///
    /// The action is the first whitespace-separated token; the target may be
    /// attached to the network with `:` (and IPv6 uses `[...]` when a port is
    /// given, as in `deny [fd00::1]:22`).
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            bail!("empty ACL rule");
        }
        let (action, rest) = match line.split_once(char::is_whitespace) {
            Some((action, rest)) => (action, rest.trim()),
            None => bail!("ACL rule {line:?} has no action"),
        };
        let action = AclAction::parse(action)?;
        // An IPv6 literal with a port is written [addr]:port; strip brackets.
        let (net_part, ports) = if let Some(rest) = rest.strip_prefix('[') {
            match rest.split_once(']') {
                Some((addr, after)) => (
                    addr.to_string(),
                    after.strip_prefix(':').unwrap_or(""),
                ),
                None => bail!("unclosed IPv6 bracket in {line:?}"),
            }
        } else if rest.matches(':').count() > 1 {
            // Bare IPv6 literal, no port.
            (rest.to_string(), "")
        } else {
            match rest.rsplit_once(':') {
                Some((addr, port)) if !addr.is_empty() => (addr.to_string(), port),
                _ => (rest.to_string(), ""),
            }
        };
        Ok(Self {
            action,
            net: IpNet::parse(&net_part)?,
            ports: PortRange::parse(ports)?,
        })
    }
}

/// An ordered rule set with a default action.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Acl {
    pub rules: Vec<AclRule>,
    pub default: AclAction,
    /// These addresses are always reachable, whatever the rules say. The
    /// gateway is the usual entry, because the virtual resolver lives there.
    pub always_allow: Vec<IpAddr>,
}

impl Default for Acl {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: AclAction::Allow,
            always_allow: Vec::new(),
        }
    }
}

impl Acl {
    pub fn allow_all() -> Self {
        Self::default()
    }

    /// Deny everything not explicitly allowed.
    pub fn default_deny() -> Self {
        Self { default: AclAction::Deny, ..Self::default() }
    }

    pub fn rule(mut self, rule: AclRule) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn always_allow(mut self, ip: IpAddr) -> Self {
        self.always_allow.push(ip);
        self
    }

    pub fn from_lines(lines: &[String]) -> Result<Self> {
        let mut acl = Self::default_deny();
        for line in lines {
            if line.trim().is_empty() || line.trim_start().starts_with('#') {
                continue;
            }
            if let Some(rest) = line.trim().strip_prefix("default") {
                acl.default = AclAction::parse(rest.trim())?;
                continue;
            }
            acl.rules.push(AclRule::parse(line)?);
        }
        Ok(acl)
    }

    pub fn evaluate(&self, ip: &IpAddr, port: u16) -> AclAction {
        if self.always_allow.iter().any(|allowed| allowed == ip) {
            return AclAction::Allow;
        }
        for rule in &self.rules {
            if rule.net.contains(ip) && rule.ports.contains(port) {
                return rule.action;
            }
        }
        self.default
    }

    pub fn allows(&self, ip: &IpAddr, port: u16) -> bool {
        self.evaluate(ip, port).is_allow()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(value: &str) -> IpAddr {
        value.parse().unwrap()
    }

    #[test]
    fn parses_networks() {
        assert!(IpNet::parse("*").unwrap().contains(&ip("1.2.3.4")));
        let net = IpNet::parse("10.66.0.0/24").unwrap();
        assert!(net.contains(&ip("10.66.0.2")));
        assert!(!net.contains(&ip("10.66.1.2")));
        let host = IpNet::parse("10.66.0.2").unwrap();
        assert!(host.contains(&ip("10.66.0.2")));
        assert!(!host.contains(&ip("10.66.0.3")));
        let v6 = IpNet::parse("fd00:66::/64").unwrap();
        assert!(v6.contains(&ip("fd00:66::2")));
        assert!(!v6.contains(&ip("fd00:67::2")));
        // A /0 covers its family only.
        let all6 = IpNet::parse("::/0").unwrap();
        assert!(all6.contains(&ip("fd00::1")));
        assert!(!all6.contains(&ip("10.0.0.1")));
        // A /25 boundary.
        let net = IpNet::parse("10.0.0.0/25").unwrap();
        assert!(net.contains(&ip("10.0.0.127")));
        assert!(!net.contains(&ip("10.0.0.128")));
    }

    #[test]
    fn parses_rules() {
        let rule = AclRule::parse("allow 10.66.0.0/24:80-90").unwrap();
        assert_eq!(rule.action, AclAction::Allow);
        assert!(rule.ports.contains(85));
        assert!(!rule.ports.contains(91));
        let rule = AclRule::parse("deny *").unwrap();
        assert_eq!(rule.action, AclAction::Deny);
        assert!(rule.ports.contains(1));
        let rule = AclRule::parse("allow [fd00::1]:443").unwrap();
        assert!(rule.net.contains(&ip("fd00::1")));
        assert!(rule.ports.contains(443));
        let rule = AclRule::parse("allow fd00::1").unwrap();
        assert!(rule.net.contains(&ip("fd00::1")));
        assert!(AclRule::parse("maybe 10.0.0.1").is_err());
        assert!(AclRule::parse("allow").is_err());
    }

    #[test]
    fn evaluates_in_order_with_default() {
        let acl = Acl::default_deny()
            .rule(AclRule::parse("allow 10.66.0.2:443").unwrap())
            .rule(AclRule::parse("deny 10.66.0.0/24").unwrap());
        assert!(acl.allows(&ip("10.66.0.2"), 443));
        assert!(!acl.allows(&ip("10.66.0.2"), 80));
        assert!(!acl.allows(&ip("10.66.0.9"), 443));
        assert!(!acl.allows(&ip("8.8.8.8"), 53));
    }

    #[test]
    fn always_allow_overrides() {
        let acl = Acl::default_deny().always_allow(ip("10.66.0.1"));
        assert!(acl.allows(&ip("10.66.0.1"), 53));
        assert!(!acl.allows(&ip("10.66.0.2"), 53));
    }

    #[test]
    fn parses_line_sets() {
        let acl = Acl::from_lines(&[
            "# comment".into(),
            "default allow".into(),
            "deny 10.66.0.9:22".into(),
        ])
        .unwrap();
        assert_eq!(acl.default, AclAction::Allow);
        assert!(!acl.allows(&ip("10.66.0.9"), 22));
        assert!(acl.allows(&ip("10.66.0.9"), 80));
    }
}
