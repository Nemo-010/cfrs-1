//! Discover local TCP ports that are already listening, so a session can be
//! pointed at one. Linux reads `/proc/net/tcp{,6}`; other platforms return an
//! empty list.

use std::collections::BTreeSet;

/// Listening TCP ports on loopback (and wildcard binds).
pub fn listening_ports() -> Vec<u16> {
    #[cfg(target_os = "linux")]
    {
        let mut ports = BTreeSet::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6"] {
            if let Ok(text) = std::fs::read_to_string(path) {
                parse_proc_net(&text, &mut ports);
            }
        }
        ports.into_iter().collect()
    }
    #[cfg(not(target_os = "linux"))]
    {
        Vec::new()
    }
}

#[cfg(target_os = "linux")]
fn parse_proc_net(text: &str, ports: &mut BTreeSet<u16>) {
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 {
            continue;
        }
        // state 0A == LISTEN
        if fields[3] != "0A" {
            continue;
        }
        let Some((_, port_hex)) = fields[1].rsplit_once(':') else {
            continue;
        };
        if let Ok(port) = u16::from_str_radix(port_hex, 16) {
            if port != 0 {
                ports.insert(port);
            }
        }
    }
}

/// Probe a loopback port with a minimal HTTP request; returns the port when
/// something HTTP-ish answers.
pub async fn confirm_local_http(port: u16) -> anyhow::Result<u16> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .map_err(|_| anyhow::anyhow!("port {port} did not accept a connection"))?
    .map_err(|e| anyhow::anyhow!("cannot connect to 127.0.0.1:{port}: {e}"))?;
    stream
        .write_all(b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        .await?;
    let mut buf = [0u8; 64];
    let n = tokio::time::timeout(std::time::Duration::from_secs(3), stream.read(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("port {port} did not answer HTTP"))?
        .map_err(|e| anyhow::anyhow!("port {port} read failed: {e}"))?;
    if n == 0 || !buf[..n].starts_with(b"HTTP/") {
        anyhow::bail!("port {port} does not look like an HTTP server");
    }
    Ok(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_listen_rows() {
        let sample = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                      0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000 0 1 1\n\
                      1: 00000000:0050 00000000:0000 01 00000000:00000000 00:00000000 00000000  0 0 2 1\n";
        let mut ports = BTreeSet::new();
        parse_proc_net(sample, &mut ports);
        assert_eq!(ports.into_iter().collect::<Vec<_>>(), vec![8080]);
    }
}
