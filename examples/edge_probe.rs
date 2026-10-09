//! Probe: can an SSH relay actually reach the Cloudflare tunnel edge for us?
//!
//! # The trap this probe exists to avoid
//!
//! Free SSH relays frequently accept a `direct-tcpip` channel and then answer
//! on their **own** HTTP handler instead of dialing the requested destination.
//! An earlier version of this probe opened a channel, read some bytes, saw a
//! plausible-looking reply, and printed "EDGE REACHABLE". That was a false
//! positive: pinggy returned the byte-identical response
//!
//! ```text
//! HTTP/1.1 200 OK
//! Content-Length: 11
//! {"urls":[]}
//! ```
//!
//! for **every** destination tried, including `10.255.255.1`, a
//! non-routable address that cannot possibly have a server behind it.
//!
//! # How this version avoids that
//!
//! It queries **two different destinations** and compares the replies. A relay
//! that genuinely proxies returns different bytes for each. A relay answering
//! from its own handler returns the same bytes, and the probe reports
//! `NOT A PROXY` regardless of what those bytes look like.
//!
//! Run: `cargo run --example edge_probe -- [relay] [proxy] [host] [port]`

use std::sync::Arc;
use std::time::Duration;

use russh::client::{Config, Handler};
use russh::keys::ssh_key::rand_core::UnwrapErr;
use russh::keys::ssh_key::Algorithm;
use russh::keys::PrivateKey;
use russh::keys::PrivateKeyWithHashAlg;
use russh::keys::PublicKeyOrCertificate;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

struct Client;

impl Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _k: &PublicKeyOrCertificate) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let relay = args
        .first()
        .cloned()
        .unwrap_or_else(|| "free.pinggy.io:443".into());
    let proxy = args
        .get(1)
        .cloned()
        .unwrap_or_else(|| "169.254.169.1:44561".into());
    let target_host = args
        .get(2)
        .cloned()
        .unwrap_or_else(|| "region1.v2.argotunnel.com".into());
    let target_port: u16 = args.get(3).and_then(|p| p.parse().ok()).unwrap_or(7844);

    let (rhost, rport) = relay.rsplit_once(':').expect("relay as host:port");
    let rport: u16 = rport.parse().expect("relay port");

    println!("== direct-tcpip probe, with a false-positive control ==");
    println!("proxy    : {proxy}");
    println!("relay    : {relay}");
    println!("target   : {target_host}:{target_port}");

    let Some(mut handle) = connect(&proxy, rhost, rport).await else {
        return;
    };

    println!("auth     : success=true");

    // The real question.
    let target_reply = fingerprint(&mut handle, &target_host, target_port).await;
    // The control: a second, unrelated destination. 10.255.255.1 is on a
    // private range with no route, so no real proxy can ever connect to it.
    let control_reply = fingerprint(&mut handle, "10.255.255.1", target_port).await;

    match (target_reply, control_reply) {
        (Ok(a), Ok(b)) => {
            println!("target   : {} bytes", a.len());
            println!("control  : {} bytes", b.len());
            if a == b && !a.is_empty() {
                println!();
                println!("RESULT   : NOT A PROXY");
                println!("           The relay returned byte-identical replies for");
                println!("           {target_host} and for 10.255.255.1, which has no");
                println!("           server behind it. It is answering from its own");
                println!("           handler, not dialing the destination.");
                println!(
                    "           Reply: {}",
                    String::from_utf8_lossy(&a[..a.len().min(120)]).replace('\n', " ")
                );
            } else if a.is_empty() {
                println!("RESULT   : channel opened but no data came back");
            } else {
                println!();
                println!("RESULT   : GENUINE PROXY - replies differ per destination.");
                println!(
                    "target   : {}",
                    String::from_utf8_lossy(&a[..a.len().min(160)]).replace('\n', " ")
                );
            }
        }
        (Ok(a), Err(e)) => {
            println!("target   : {} bytes", a.len());
            println!("control  : refused ({e})");
            println!("RESULT   : GENUINE PROXY - the control destination was refused.");
            println!(
                "target   : {}",
                String::from_utf8_lossy(&a[..a.len().min(160)]).replace('\n', " ")
            );
        }
        (Err(e), Ok(b)) => {
            println!("target   : refused ({e})");
            println!("control  : {} bytes back", b.len());
            println!(
                "RESULT   : relay answers from its own handler; it cannot reach {target_host}"
            );
        }
        (Err(a), Err(b)) => {
            println!("target   : {a}");
            println!("control  : {b}");
            println!("RESULT   : no usable direct-tcpip on this relay");
        }
    }
}

/// Send a unique marker to `host:port` and return whatever comes back.
async fn fingerprint(
    handle: &mut russh::client::Handle<Client>,
    host: &str,
    port: u16,
) -> Result<Vec<u8>, String> {
    let mut channel = handle
        .channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0)
        .await
        .map_err(|e| format!("channel refused: {e}"))?;
    let mut writer = channel.make_writer();
    writer
        .write_all(b"cfrs-direct-tcpip-probe\r\n\r\n")
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut reader = channel.make_reader();
    let mut buf = vec![0u8; 1024];
    let n = tokio::time::timeout(Duration::from_secs(10), reader.read(&mut buf))
        .await
        .map_err(|_| "timeout".to_string())?
        .map_err(|e| format!("read: {e}"))?;
    Ok(buf[..n].to_vec())
}

async fn connect(proxy: &str, host: &str, port: u16) -> Option<russh::client::Handle<Client>> {
    let raw = match cfrs::proxy::connect_tunnel(proxy, host, port, Duration::from_secs(20)) {
        Ok(v) => v,
        Err(e) => {
            println!("proxy    : FAILED {e}");
            return None;
        }
    };
    let (stream, leftover) = raw.into_parts();
    if stream.set_nonblocking(true).is_err() {
        println!("stream   : could not set nonblocking");
        return None;
    }
    let stream = match tokio::net::TcpStream::from_std(stream) {
        Ok(s) => s,
        Err(e) => {
            println!("stream   : FAILED {e}");
            return None;
        }
    };
    let stream = Prefixed::new(leftover, stream);

    let key = match PrivateKey::random(
        &mut UnwrapErr(ssh_key::getrandom::SysRng),
        Algorithm::Ed25519,
    ) {
        Ok(k) => k,
        Err(e) => {
            println!("key      : FAILED {e}");
            return None;
        }
    };
    let mut cfg = Config::default();
    cfg.inactivity_timeout = Some(Duration::from_secs(600));

    let mut handle = match russh::client::connect_stream(Arc::new(cfg), stream, Client).await {
        Ok(h) => h,
        Err(e) => {
            println!("ssh      : handshake FAILED {e}");
            return None;
        }
    };

    match handle
        .authenticate_publickey("cfrs", PrivateKeyWithHashAlg::new(Arc::new(key), None))
        .await
    {
        Ok(a) if a.success() => Some(handle),
        Ok(_) => {
            println!("auth     : refused");
            None
        }
        Err(e) => {
            println!("auth     : FAILED {e}");
            None
        }
    }
}

struct Prefixed {
    prefix: Vec<u8>,
    offset: usize,
    inner: tokio::net::TcpStream,
}

impl Prefixed {
    fn new(prefix: Vec<u8>, inner: tokio::net::TcpStream) -> Self {
        Self {
            prefix,
            offset: 0,
            inner,
        }
    }
}

impl tokio::io::AsyncRead for Prefixed {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.offset < this.prefix.len() {
            let rem = this.prefix.len() - this.offset;
            let n = rem.min(buf.remaining());
            buf.put_slice(&this.prefix[this.offset..this.offset + n]);
            this.offset += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for Prefixed {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        b: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, b)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
