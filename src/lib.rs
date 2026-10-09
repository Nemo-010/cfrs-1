//! cfrs: a Cloudflare quick-tunnel client in Rust, built for sandboxes where
//! the stock `cloudflared` binary cannot run.
//!
//! The crate is split by responsibility:
//!
//! * [`proxy`] opens a raw byte pipe through an HTTP CONNECT proxy. That is
//!   the only egress most sandboxes offer, and it is what carries the SSH relay.
//! * [`quicktunnel`] provisions an anonymous Cloudflare quick tunnel, the same
//!   credential-free `POST /tunnel` call `cloudflared` makes. This works from a
//!   restricted sandbox because it is ordinary HTTPS on an allow-listed host.
//! * [`relay`] exposes a unix-socket origin on the public internet over an SSH
//!   remote forward, splicing each visitor's `forwarded-tcpip` channel to the
//!   unix socket. This is what actually produces a working public URL here.
//!
//! A genuine Cloudflare tunnel needs the edge at
//! `region*.v2.argotunnel.com:7844`, which a restricted sandbox blocks on both
//! the QUIC and HTTP/2 paths. [`quicktunnel`] gets real credentials for that
//! edge; [`relay`] is the transport that completes a working public URL without
//! it. See `README.md` for the measurements behind that split.

pub mod cloudflare;
pub mod config;
pub mod feature;
pub mod origin;
pub mod proxy;
pub mod quicktunnel;
pub mod relay;
pub mod transport;
pub mod tunnel;
pub mod util;
