//! SOCKS5 and HTTP `CONNECT` for programs that cannot be interposed.
//!
//! A statically linked program, or one running under a loader the shim cannot
//! reach, still honours `ALL_PROXY`. The stack therefore exposes SOCKS5 and
//! HTTP `CONNECT` listeners on an `AF_UNIX` socket:
//!
//! ```text
//! ALL_PROXY=socks5h:///run/cfrsnet.socks
//! ```
//!
//! This module is only the wire protocol. The caller maps the requested host
//! to a virtual address (through [`crate::vnet::dns::Resolver`] or a fixed
//! value) and splices the two streams.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const SOCKS_VERSION: u8 = 5;
const AUTH_NONE: u8 = 0x00;
const AUTH_UNACCEPTABLE: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
#[allow(dead_code)]
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_COMMAND_UNSUPPORTED: u8 = 0x07;

/// The host a proxy client asked for: a literal or a name to resolve.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyHost {
    Ip(IpAddr),
    Domain(String),
}

impl std::fmt::Display for ProxyHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(ip) => write!(f, "{ip}"),
            Self::Domain(name) => f.write_str(name),
        }
    }
}

/// A parsed proxy request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProxyRequest {
    pub host: ProxyHost,
    pub port: u16,
}

/// Perform the SOCKS5 method negotiation and read the request.
///
/// Only the no-auth method is offered. A client that requests user/password
/// or GSSAPI is rejected with `0xff`, which is the correct SOCKS5 behaviour
/// when no acceptable method exists.
pub async fn socks5_read_request<S>(stream: &mut S) -> Result<ProxyRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut intro = [0u8; 2];
    stream.read_exact(&mut intro).await.context("SOCKS5 greeting")?;
    if intro[0] != SOCKS_VERSION {
        bail!("SOCKS5 greeting has version {} not 5", intro[0]);
    }
    let nmethods = intro[1] as usize;
    if nmethods == 0 {
        bail!("SOCKS5 greeting offers no methods");
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await.context("SOCKS5 methods")?;
    if methods.contains(&AUTH_NONE) {
        stream.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;
    } else {
        stream.write_all(&[SOCKS_VERSION, AUTH_UNACCEPTABLE]).await?;
        stream.flush().await?;
        bail!("SOCKS5 client offered no method this proxy accepts");
    }
    stream.flush().await?;

    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.context("SOCKS5 request")?;
    if header[0] != SOCKS_VERSION {
        bail!("SOCKS5 request has version {} not 5", header[0]);
    }
    if header[1] != CMD_CONNECT {
        socks5_reply(stream, REP_COMMAND_UNSUPPORTED, None).await?;
        bail!("SOCKS5 command {} is not CONNECT", header[1]);
    }
    let host = match header[3] {
        ATYP_IPV4 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            ProxyHost::Ip(IpAddr::V4(Ipv4Addr::from(octets)))
        }
        ATYP_IPV6 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            ProxyHost::Ip(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        ATYP_DOMAIN => {
            let len = stream.read_u8().await? as usize;
            if len == 0 {
                bail!("SOCKS5 domain name is empty");
            }
            let mut name = vec![0u8; len];
            stream.read_exact(&mut name).await?;
            ProxyHost::Domain(String::from_utf8_lossy(&name).into_owned())
        }
        other => bail!("SOCKS5 address type {other} is not supported"),
    };
    let port = stream.read_u16().await?;
    Ok(ProxyRequest { host, port })
}

/// Send a SOCKS5 reply. `bound` is reported as the server-side address; a
/// zero address is used when there is none.
pub async fn socks5_reply<S>(stream: &mut S, code: u8, bound: Option<SocketAddr>) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let bound = bound.unwrap_or(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
    let mut out = vec![SOCKS_VERSION, code, 0x00];
    match bound {
        SocketAddr::V4(v4) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&v4.ip().octets());
        }
        SocketAddr::V6(v6) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&v6.ip().octets());
        }
    }
    out.extend_from_slice(&bound.port().to_be_bytes());
    stream.write_all(&out).await?;
    stream.flush().await?;
    Ok(())
}

/// Map an [`anyhow::Error`]-style failure to the closest SOCKS5 reply code.
pub fn socks5_code_for_error(message: &str) -> u8 {
    let lower = message.to_ascii_lowercase();
    if lower.contains("denied") || lower.contains("acl") || lower.contains("refused") {
        REP_HOST_UNREACHABLE
    } else {
        REP_GENERAL_FAILURE
    }
}

/// Read an HTTP request line and headers up to the blank line, preserving any
/// bytes after it (there should be none for `CONNECT`).
///
/// Reading one byte at a time is deliberate: a buffered reader would consume
/// into the tunnelled stream and lose it.
pub async fn http_read_connect<S>(stream: &mut S) -> Result<ProxyRequest>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    const MAX_HEADER: usize = 64 * 1024;
    let mut header = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            bail!("connection closed before the HTTP request was complete");
        }
        header.push(byte[0]);
        if header.len() > MAX_HEADER {
            bail!("HTTP proxy request header exceeds {MAX_HEADER} bytes");
        }
        if header.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    let text = String::from_utf8_lossy(&header);
    let mut lines = text.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default();
    let target = parts.next().unwrap_or_default();
    if !method.eq_ignore_ascii_case("CONNECT") {
        http_connect_reply(stream, 405, "Method Not Allowed").await?;
        bail!("HTTP proxy method {method} is not CONNECT");
    }
    let (host, port) = split_host_port(target).context("CONNECT target is not host:port")?;
    let host = match host.parse::<IpAddr>() {
        Ok(ip) => ProxyHost::Ip(ip),
        Err(_) => ProxyHost::Domain(host),
    };
    Ok(ProxyRequest { host, port })
}

fn split_host_port(target: &str) -> Result<(String, u16)> {
    if let Some(rest) = target.strip_prefix('[') {
        let (host, rest) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("unclosed IPv6 bracket"))?;
        let port = rest
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("IPv6 target has no port"))?
            .parse()
            .map_err(|_| anyhow::anyhow!("bad port in {target:?}"))?;
        return Ok((host.to_string(), port));
    }
    let (host, port) = target
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("target {target:?} has no port"))?;
    if host.is_empty() {
        bail!("target has an empty host");
    }
    Ok((
        host.to_string(),
        port.parse().map_err(|_| anyhow::anyhow!("bad port in {target:?}"))?,
    ))
}

/// Send an HTTP/1.1 response with no body, then the caller may start splicing.
pub async fn http_connect_reply<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let response = format!("HTTP/1.1 {status} {reason}\r\n\r\n");
    stream.write_all(response.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// A convenience wrapper for the successful case.
pub async fn http_connect_ok<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    http_connect_reply(stream, 200, "Connection Established").await
}

/// Rewrite the destination of an absolute-form HTTP request
/// (`GET http://host/path HTTP/1.1`) into origin form, so a plain HTTP proxy
/// request works without CONNECT. Returns the request bytes and the target.
pub fn rewrite_absolute_form(request: &[u8]) -> Option<(ProxyRequest, Vec<u8>)> {
    let text = std::str::from_utf8(request).ok()?;
    let (head, rest) = text.split_once("\r\n")?;
    let mut parts = head.split_whitespace();
    let method = parts.next()?;
    let target = parts.next()?;
    let version = parts.next().unwrap_or("HTTP/1.1");
    if !target.starts_with("http://") {
        return None;
    }
    let after_scheme = &target["http://".len()..];
    let (authority, path) = match after_scheme.find('/') {
        Some(index) => (&after_scheme[..index], &after_scheme[index..]),
        None => (after_scheme, "/"),
    };
    let (host, port) = split_host_port(authority).unwrap_or((authority.to_string(), 80));
    let host = match host.parse::<IpAddr>() {
        Ok(ip) => ProxyHost::Ip(ip),
        Err(_) => ProxyHost::Domain(host),
    };
    let rewritten = format!("{method} {path} {version}\r\n{rest}");
    Some((ProxyRequest { host, port }, rewritten.into_bytes()))
}

/// Whether the first bytes look like SOCKS5 rather than HTTP.
pub fn looks_like_socks5(first: u8) -> bool {
    first == SOCKS_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn socks5_ipv4_connect() {
        let (mut client, mut server) = duplex(256);
        let task = tokio::spawn(async move {
            client.write_all(&[5, 1, 0]).await.unwrap();
            let mut reply = [0u8; 2];
            client.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply, [5, 0]);
            client
                .write_all(&[5, 1, 0, 1, 10, 66, 0, 2, 0x1f, 0x90])
                .await
                .unwrap();
            client
        });
        let request = socks5_read_request(&mut server).await.unwrap();
        assert_eq!(
            request,
            ProxyRequest {
                host: ProxyHost::Ip("10.66.0.2".parse().unwrap()),
                port: 8080
            }
        );
        let bound: SocketAddr = "10.66.0.2:8080".parse().unwrap();
        socks5_reply(&mut server, REP_SUCCEEDED, Some(bound)).await.unwrap();
        let mut client = task.await.unwrap();
        let mut reply = [0u8; 10];
        client.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], REP_SUCCEEDED);
        assert_eq!(&reply[4..8], &[10, 66, 0, 2]);
    }

    async fn socks5_request_with(client_to_server: &[u8]) -> ProxyRequest {
        let (mut client, mut server) = duplex(256);
        let payload = client_to_server.to_vec();
        tokio::spawn(async move {
            client.write_all(&payload).await.unwrap();
            let _ = client.flush().await;
            // Keep the connection open long enough for the server to read.
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        });
        socks5_read_request(&mut server).await.unwrap()
    }

    #[tokio::test]
    async fn socks5_domain_target() {
        let request = socks5_request_with(&[5, 1, 0, 5, 1, 0, 3, 3, b'a', b'p', b'i', 0x00, 0x50]).await;
        assert_eq!(request.host, ProxyHost::Domain("api".into()));
        assert_eq!(request.port, 80);
    }

    #[tokio::test]
    async fn socks5_ipv6_target() {
        let request = socks5_request_with(&[
            5, 1, 0, 5, 1, 0, 4, 0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0x01, 0xbb,
        ])
        .await;
        assert_eq!(request.host, ProxyHost::Ip("fd00::2".parse().unwrap()));
        assert_eq!(request.port, 443);
    }

    #[tokio::test]
    async fn socks5_rejects_missing_no_auth() {
        let (mut client, mut server) = duplex(64);
        tokio::spawn(async move {
            client.write_all(&[5, 1, 2]).await.unwrap();
            let mut reply = [0u8; 2];
            let _ = client.read_exact(&mut reply).await;
            assert_eq!(reply, [5, 0xff]);
        });
        assert!(socks5_read_request(&mut server).await.is_err());
    }

    #[tokio::test]
    async fn http_connect_reads_target() {
        let (mut client, mut server) = duplex(256);
        tokio::spawn(async move {
            client
                .write_all(b"CONNECT [fd00::2]:443 HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let mut buf = [0u8; 39];
            // 200 reply is 39 bytes: "HTTP/1.1 200 Connection Established\r\n\r\n"
            let _ = client.read(&mut buf).await;
        });
        let request = http_read_connect(&mut server).await.unwrap();
        assert_eq!(request.host, ProxyHost::Ip("fd00::2".parse().unwrap()));
        assert_eq!(request.port, 443);
        http_connect_ok(&mut server).await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_rejects_other_methods() {
        let (mut client, mut server) = duplex(256);
        tokio::spawn(async move {
            client.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            let mut buf = [0u8; 128];
            let _ = client.read(&mut buf).await;
        });
        assert!(http_read_connect(&mut server).await.is_err());
    }

    #[test]
    fn rewrites_absolute_form() {
        let (request, rewritten) =
            rewrite_absolute_form(b"GET http://api:8080/v1?x=1 HTTP/1.1\r\nHost: api\r\n\r\n").unwrap();
        assert_eq!(request.host, ProxyHost::Domain("api".into()));
        assert_eq!(request.port, 8080);
        assert!(rewritten.starts_with(b"GET /v1?x=1 HTTP/1.1\r\n"));
        assert!(rewrite_absolute_form(b"GET / HTTP/1.1\r\n\r\n").is_none());
    }

    #[test]
    fn detects_socks() {
        assert!(looks_like_socks5(5));
        assert!(!looks_like_socks5(b'G'));
    }
}
