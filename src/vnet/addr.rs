//! Addresses, the abstract-namespace encoding, and the virtual subnet.
//!
//! A *virtual endpoint* is an ordinary `IP:port` that the kernel never sees.
//! The shim and the stack agree to render it as an `AF_UNIX` abstract name:
//!
//! ```text
//! \0cfrsnet/<family>/<address>/<port>
//! ```
//!
//! `/` separates the fields precisely because IPv6 literals contain `:`.
//! The leading NUL belongs to the abstract namespace, not to the name itself,
//! so [`VirtAddr::abstract_name`] returns the name without it and the shim
//! adds it back when it fills `sun_path[0]`.
//!
//! RFC 5952 formatting is implemented here rather than delegated to
//! [`std::net::Ipv6Addr`]'s `Display`, so the exact bytes that appear in a
//! socket name are pinned by tests and cannot drift with a Rust release.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{bail, Result};

/// The abstract-name prefix, without the leading NUL.
pub const ABSTRACT_PREFIX: &str = "cfrsnet";
/// The control socket name, without the leading NUL.
pub const CONTROL_NAME: &str = "cfrsnet/ctl";
/// Longest `sun_path` name, in bytes: `sizeof(sun_path) - 1`.
pub const MAX_NAME: usize = 107;

/// Address family of a virtual endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Family {
    V4,
    V6,
}

impl Family {
    pub fn number(self) -> u8 {
        match self {
            Family::V4 => 4,
            Family::V6 => 6,
        }
    }

    pub fn from_number(n: u8) -> Result<Self> {
        match n {
            4 => Ok(Family::V4),
            6 => Ok(Family::V6),
            other => bail!("unknown address family {other} (want 4 or 6)"),
        }
    }

    pub fn from_ip(ip: &IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Family::V4,
            IpAddr::V6(_) => Family::V6,
        }
    }
}

/// An `IP:port` in the virtual network.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VirtAddr {
    pub ip: IpAddr,
    pub port: u16,
}

impl VirtAddr {
    pub const fn new(ip: IpAddr, port: u16) -> Self {
        Self { ip, port }
    }

    pub const fn v4(ip: Ipv4Addr, port: u16) -> Self {
        Self { ip: IpAddr::V4(ip), port }
    }

    pub const fn v6(ip: Ipv6Addr, port: u16) -> Self {
        Self { ip: IpAddr::V6(ip), port }
    }

    pub fn family(&self) -> Family {
        Family::from_ip(&self.ip)
    }

    /// Encode as the abstract name, without the leading NUL.
    ///
    /// Returns an error when the rendered name cannot fit `sun_path`, which
    /// cannot happen for a well-formed IP literal but is checked anyway so a
    /// caller never builds a truncated `sockaddr_un`.
    pub fn abstract_name(&self) -> Result<String> {
        let host = match self.ip {
            IpAddr::V4(ip) => ip.to_string(),
            IpAddr::V6(ip) => format_ipv6_rfc5952(&ip),
        };
        let port = self.port;
        let name = format!(
            "{ABSTRACT_PREFIX}/{}/{}/{port}",
            self.family().number(),
            host
        );
        if name.len() > MAX_NAME {
            bail!(
                "abstract name is {} bytes, over the {MAX_NAME}-byte sun_path limit",
                name.len()
            );
        }
        Ok(name)
    }

    /// The name as it appears in `sun_path`, NUL-terminated (Linux abstract
    /// sockets address by the byte after the leading NUL).
    pub fn abstract_name_bytes(&self) -> Result<Vec<u8>> {
        let name = self.abstract_name()?;
        let mut bytes = vec![0u8];
        bytes.extend_from_slice(name.as_bytes());
        Ok(bytes)
    }

    /// Parse `cfrsnet/4/10.66.0.2/8080`, with or without a leading NUL.
    pub fn from_abstract_name(name: &str) -> Result<Self> {
        let name = name.strip_prefix('\0').unwrap_or(name);
        let mut parts = name.split('/');
        let prefix = parts.next().unwrap_or_default();
        if prefix != ABSTRACT_PREFIX {
            bail!("not a cfrsnet name: {name:?}");
        }
        let family = Family::from_number(
            parts
                .next()
                .unwrap_or_default()
                .parse()
                .map_err(|_| anyhow::anyhow!("cfrsnet name has no family: {name:?}"))?,
        )?;
        let host = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("cfrsnet name has no address: {name:?}"))?;
        let port: u16 = parts
            .next()
            .ok_or_else(|| anyhow::anyhow!("cfrsnet name has no port: {name:?}"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("cfrsnet name has a bad port: {name:?}"))?;
        if parts.next().is_some() {
            bail!("cfrsnet name has trailing fields: {name:?}");
        }
        let ip: IpAddr = host
            .parse()
            .map_err(|_| anyhow::anyhow!("cfrsnet name has a bad address: {name:?}"))?;
        if Family::from_ip(&ip) != family {
            bail!("cfrsnet name family {family:?} does not match address {host:?}");
        }
        Ok(Self { ip, port })
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.ip {
            IpAddr::V4(ip) => write!(f, "{ip}:{}", self.port),
            IpAddr::V6(ip) => write!(f, "[{}]:{}", format_ipv6_rfc5952(&ip), self.port),
        }
    }
}

impl From<SocketAddr> for VirtAddr {
    fn from(value: SocketAddr) -> Self {
        Self { ip: value.ip(), port: value.port() }
    }
}

impl From<VirtAddr> for SocketAddr {
    fn from(value: VirtAddr) -> Self {
        SocketAddr::new(value.ip, value.port)
    }
}

impl std::str::FromStr for VirtAddr {
    type Err = anyhow::Error;

    /// Parse `10.66.0.2:8080` or `[fd00::2]:443`, the same syntax as a
    /// [`SocketAddr`].
    fn from_str(value: &str) -> Result<Self> {
        let addr: SocketAddr = value
            .trim()
            .parse()
            .map_err(|_| anyhow::anyhow!("{value:?} is not an IP:port endpoint"))?;
        Ok(Self::from(addr))
    }
}

/// Format an IPv6 address exactly as RFC 5952 requires:
///
/// * lowercase hex, no leading zeros in a group,
/// * the longest run of two or more zero groups replaced by `::`,
/// * the leftmost run when there is a tie,
/// * never a single zero group, never more than one `::`.
pub fn format_ipv6_rfc5952(ip: &Ipv6Addr) -> String {
    let groups = ip.segments();
    // Find the longest run of zero groups of length >= 2; ties go leftmost.
    let mut best_start = None;
    let mut best_len = 0usize;
    let mut i = 0usize;
    while i < 8 {
        if groups[i] == 0 {
            let start = i;
            while i < 8 && groups[i] == 0 {
                i += 1;
            }
            let len = i - start;
            if len > best_len {
                best_len = len;
                best_start = Some(start);
            }
        } else {
            i += 1;
        }
    }
    let (start, len) = match best_start {
        Some(start) if best_len >= 2 => (start, best_len),
        _ => (8, 0),
    };
    let mut out = String::new();
    let mut index = 0usize;
    while index < 8 {
        if index == start {
            out.push_str("::");
            index += len;
            continue;
        }
        if !out.is_empty() && !out.ends_with(':') {
            out.push(':');
        }
        out.push_str(&format!("{:x}", groups[index]));
        index += 1;
    }
    if out.is_empty() {
        out.push_str("::");
    }
    out
}

/// The private address space the stack owns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtualSubnet {
    pub v4: Ipv4Addr,
    pub v4_prefix: u8,
    pub v6: Ipv6Addr,
    pub v6_prefix: u8,
}

impl Default for VirtualSubnet {
    fn default() -> Self {
        Self {
            v4: Ipv4Addr::new(10, 66, 0, 0),
            v4_prefix: 24,
            v6: Ipv6Addr::new(0xfd00, 0x66, 0, 0, 0, 0, 0, 0),
            v6_prefix: 64,
        }
    }
}

impl VirtualSubnet {
    /// The gateway (`.1`) for a family. Services are normally numbered from
    /// `.2`, matching the document's plan.
    pub fn gateway(&self, family: Family) -> IpAddr {
        match family {
            Family::V4 => {
                let mut octets = self.v4.octets();
                octets[3] = 1;
                IpAddr::V4(Ipv4Addr::from(octets))
            }
            Family::V6 => {
                let mut segments = self.v6.segments();
                segments[7] = 1;
                IpAddr::V6(Ipv6Addr::from(segments))
            }
        }
    }

    /// Whether `ip` belongs to the virtual subnet.
    pub fn contains(&self, ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => prefix_contains_v4(self.v4, self.v4_prefix, *ip),
            IpAddr::V6(ip) => prefix_contains_v6(self.v6, self.v6_prefix, *ip),
        }
    }

    /// The next free host address after `used`, starting at `.2`.
    pub fn allocate_v4(&self, used: &[IpAddr]) -> Option<Ipv4Addr> {
        let base = u32::from(self.v4);
        let host_mask = if self.v4_prefix >= 32 {
            0
        } else {
            (1u32 << (32 - self.v4_prefix)) - 1
        };
        for offset in 2..=host_mask.saturating_sub(1) {
            let candidate = Ipv4Addr::from(base | offset);
            if !used.contains(&IpAddr::V4(candidate)) {
                return Some(candidate);
            }
        }
        None
    }

    /// A stable host address derived from a service name. The low octet is
    /// forced into `2..=254` so a name never collides with the gateway or the
    /// network/broadcast addresses.
    pub fn derive_v4(&self, name: &str) -> Ipv4Addr {
        let mut octets = self.v4.octets();
        let hash = fnv1a64(name.as_bytes());
        octets[3] = 2 + (hash % 253) as u8;
        Ipv4Addr::from(octets)
    }
}

fn prefix_contains_v4(base: Ipv4Addr, prefix: u8, ip: Ipv4Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix >= 32 {
        return base == ip;
    }
    let mask = u32::MAX << (32 - prefix);
    (u32::from(base) & mask) == (u32::from(ip) & mask)
}

fn prefix_contains_v6(base: Ipv6Addr, prefix: u8, ip: Ipv6Addr) -> bool {
    if prefix == 0 {
        return true;
    }
    if prefix >= 128 {
        return base == ip;
    }
    let mask = u128::MAX << (128 - prefix);
    (u128::from(base) & mask) == (u128::from(ip) & mask)
}

/// FNV-1a 64-bit, used only to spread service names across host addresses.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// `127.0.0.1:8080` -> `10.66.0.2:8080` for names a program hard-codes.
///
/// Loopback is the common case for dev servers and MCP servers. Returning the
/// mapped endpoint unchanged when the port is the well-known gateway port lets
/// a caller decide policy; the shim calls this for `127.0.0.1` and `localhost`.
/// A listener address inside the virtual subnet, for tests and for
/// configuration that names a port explicitly.
///
/// [`map_loopback`] folds loopback into the subnet and cannot fail, which is
/// right for the shim's loose mode but wrong where a caller asked for a
/// specific address: the subnet is `10.66.0.0/24`, so `127.0.0.1` is outside it,
/// and a helper that quietly accepted it would report a bound listener that the
/// stack never has. This refuses instead.
pub fn subnet_addr(subnet: &VirtualSubnet, host: &str, port: u16) -> Result<VirtAddr> {
    let ip: IpAddr = host
        .parse()
        .map_err(|_| anyhow::anyhow!("{host:?} is not an IP address"))?;
    if !subnet.contains(&ip) {
        bail!("{ip} is outside the virtual subnet {}/{}", subnet.v4, subnet.v4_prefix);
    }
    Ok(VirtAddr { ip, port })
}

pub fn map_loopback(addr: SocketAddr, subnet: &VirtualSubnet) -> VirtAddr {
    match addr {
        SocketAddr::V4(v4) if v4.ip().is_loopback() => {
            VirtAddr::v4(subnet.derive_v4("loopback"), v4.port())
        }
        other => VirtAddr::from(other),
    }
}

/// Destructure a `SocketAddr` into its family-specific parts, including the
/// IPv6 scope id the shim can then carry through.
pub fn scope_id(addr: &SocketAddr) -> Option<u32> {
    match addr {
        SocketAddr::V6(v6) => Some(v6.scope_id()),
        SocketAddr::V4(_) => None,
    }
}

/// Build a `SocketAddrV6` preserving `scope_id` and `flowinfo`.
pub fn v6_socket_addr(addr: Ipv6Addr, port: u16, scope_id: u32) -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(addr, port, 0, scope_id))
}

/// Build a v4 `SocketAddr`.
pub fn v4_socket_addr(addr: Ipv4Addr, port: u16) -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(addr, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(name: &str) -> Ipv4Addr {
        name.parse().unwrap()
    }

    #[test]
    fn abstract_names_round_trip() {
        let a = VirtAddr::v4(v4("10.66.0.2"), 8080);
        assert_eq!(a.abstract_name().unwrap(), "cfrsnet/4/10.66.0.2/8080");
        assert_eq!(VirtAddr::from_abstract_name("cfrsnet/4/10.66.0.2/8080").unwrap(), a);
        assert_eq!(
            VirtAddr::from_abstract_name("\0cfrsnet/4/10.66.0.2/8080").unwrap(),
            a
        );
        let b = VirtAddr::v6("fd00::2".parse().unwrap(), 443);
        assert_eq!(b.abstract_name().unwrap(), "cfrsnet/6/fd00::2/443");
        assert_eq!(VirtAddr::from_abstract_name("cfrsnet/6/fd00::2/443").unwrap(), b);
        // Family must match the literal.
        assert!(VirtAddr::from_abstract_name("cfrsnet/4/fd00::2/443").is_err());
        assert!(VirtAddr::from_abstract_name("cfrsnet/6/10.66.0.2/443").is_err());
    }

    #[test]
    fn abstract_name_rejects_junk() {
        assert!(VirtAddr::from_abstract_name("cfrsnet/4/10.66.0.2").is_err());
        assert!(VirtAddr::from_abstract_name("cfrsnet/9/10.66.0.2/1").is_err());
        assert!(VirtAddr::from_abstract_name("other/4/10.66.0.2/1").is_err());
        assert!(VirtAddr::from_abstract_name("cfrsnet/4/10.66.0.2/1/extra").is_err());
        assert!(VirtAddr::from_abstract_name("cfrsnet/4/999.1.1.1/1").is_err());
    }

    #[test]
    fn abstract_bytes_are_nul_terminated() {
        let bytes = VirtAddr::v4(v4("10.66.0.2"), 80).abstract_name_bytes().unwrap();
        assert_eq!(bytes[0], 0);
        assert_eq!(&bytes[1..], b"cfrsnet/4/10.66.0.2/80");
    }

    #[test]
    fn rfc5952_formatting() {
        assert_eq!(format_ipv6_rfc5952(&"::".parse().unwrap()), "::");
        assert_eq!(format_ipv6_rfc5952(&"::1".parse().unwrap()), "::1");
        assert_eq!(format_ipv6_rfc5952(&"fd00::2".parse().unwrap()), "fd00::2");
        // A single zero group is not compressed.
        assert_eq!(
            format_ipv6_rfc5952(&"2001:db8:0:1:1:1:1:1".parse().unwrap()),
            "2001:db8:0:1:1:1:1:1"
        );
        // Leftmost longest run wins.
        assert_eq!(
            format_ipv6_rfc5952(&"2001:0:0:1:0:0:0:1".parse().unwrap()),
            "2001:0:0:1::1"
        );
        // Leading and trailing runs; the longer (trailing) run wins.
        assert_eq!(
            format_ipv6_rfc5952(&"0:0:0:1:0:0:0:0".parse().unwrap()),
            "0:0:0:1::"
        );
        assert_eq!(
            format_ipv6_rfc5952(&"1:0:0:0:0:1:0:0".parse().unwrap()),
            "1::1:0:0"
        );
        // Ties: leftmost.
        assert_eq!(
            format_ipv6_rfc5952(&"1:0:0:1:0:0:1:1".parse().unwrap()),
            "1::1:0:0:1:1"
        );
        // Uppercase must be lowered.
        assert_eq!(
            format_ipv6_rfc5952(&"FD00:ABCD:0:0:0:0:0:2".parse().unwrap()),
            "fd00:abcd::2"
        );
        // Full-length, no zeros.
        assert_eq!(
            format_ipv6_rfc5952(&"1:2:3:4:5:6:7:8".parse().unwrap()),
            "1:2:3:4:5:6:7:8"
        );
        // IPv4-mapped keeps its dotted tail.
        assert_eq!(
            format_ipv6_rfc5952(&"::ffff:192.0.2.1".parse().unwrap()),
            "::ffff:c000:201"
        );
    }

    #[test]
    fn name_length_is_bounded() {
        let longest = VirtAddr::v6(
            "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff".parse().unwrap(),
            65535,
        );
        let name = longest.abstract_name().unwrap();
        assert!(name.len() <= MAX_NAME, "{name} is {} bytes", name.len());
        // 10 + 39 + 1 + 5 = 55.
        assert_eq!(name.len(), 55);
    }

    #[test]
    fn subnet_membership_and_allocation() {
        let subnet = VirtualSubnet::default();
        assert!(subnet.contains(&v4("10.66.0.2").into()));
        assert!(!subnet.contains(&v4("10.66.1.2").into()));
        assert!(subnet.contains(&"fd00:66::2".parse::<IpAddr>().unwrap()));
        assert!(!subnet.contains(&"fd00:67::2".parse::<IpAddr>().unwrap()));
        assert_eq!(subnet.gateway(Family::V4), std::net::IpAddr::V4(v4("10.66.0.1")));
        assert_eq!(subnet.gateway(Family::V6), "fd00:66::1".parse::<IpAddr>().unwrap());
        assert_eq!(subnet.allocate_v4(&[]), Some(v4("10.66.0.2")));
        assert_eq!(subnet.allocate_v4(&[v4("10.66.0.2").into()]), Some(v4("10.66.0.3")));
    }

    #[test]
    fn derived_addresses_are_stable_and_in_range() {
        let subnet = VirtualSubnet::default();
        let a = subnet.derive_v4("web");
        assert_eq!(a, subnet.derive_v4("web"));
        assert_ne!(a, subnet.derive_v4("db"));
        assert!(subnet.contains(&a.into()));
        assert!((2..=254).contains(&a.octets()[3]));
    }

    #[test]
    fn loopback_maps_into_the_subnet() {
        let subnet = VirtualSubnet::default();
        let mapped = map_loopback("127.0.0.1:8080".parse().unwrap(), &subnet);
        assert!(subnet.contains(&mapped.ip));
        assert_eq!(mapped.port, 8080);
        let other: SocketAddr = "10.9.9.9:22".parse().unwrap();
        assert_eq!(map_loopback(other, &subnet), VirtAddr::from(other));
    }

    #[test]
    fn scope_id_round_trips() {
        let addr = v6_socket_addr("fe80::1".parse().unwrap(), 53, 7);
        assert_eq!(scope_id(&addr), Some(7));
        assert_eq!(scope_id(&"127.0.0.1:1".parse().unwrap()), None);
    }

    #[test]
    fn parses_endpoints() {
        assert_eq!(
            "10.66.0.2:8080".parse::<VirtAddr>().unwrap(),
            VirtAddr::v4(v4("10.66.0.2"), 8080)
        );
        assert_eq!(
            "[fd00::2]:443".parse::<VirtAddr>().unwrap(),
            VirtAddr::v6("fd00::2".parse().unwrap(), 443)
        );
        assert!("10.66.0.2".parse::<VirtAddr>().is_err());
        assert!("not an endpoint".parse::<VirtAddr>().is_err());
    }
}
