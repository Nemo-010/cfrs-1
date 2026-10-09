# cfrs

A Cloudflare quick-tunnel client written in Rust, for sandboxes where the
stock `cloudflared` binary cannot run.

`cloudflared` is a 40 MB Go binary that assumes it can bind a TCP port, resolve
DNS, and open UDP to a Cloudflare edge. In a locked-down sandbox it does none
of those things, and it has no HTTP-proxy flag for its edge connection, so it
fails before it reaches Cloudflare at all. `cfrs` implements the part of the
protocol that still works under those constraints, and adds a transport that
completes a working public URL.

Two things work here, and this crate does both:

1. **Anonymous Cloudflare quick-tunnel provisioning**, credential-free, the same
   `POST /tunnel` call `cloudflared` makes.
2. **Actually exposing a server on the public web** from an origin that can
   only be a unix socket, over an HTTP CONNECT proxy with no direct egress.

## Install

```sh
cargo install --path .
```

## Use

```sh
# Request an anonymous quick tunnel. No account, no token.
cfrs provision

# Require visitors to pass a one-time PIN before reaching the origin.
cfrs provision --otp

# Expose a unix-socket origin on the public web and print the URL.
cfrs serve --unix-socket /tmp/app.sock

# Report what this machine can reach.
cfrs doctor
```

`serve` reads `$HTTPS_PROXY` by default and accepts `--proxy host:port`.
Set `CFRS_DEBUG=1` to trace every visitor channel and byte count.

## What was measured, and where the boundary is

Every claim below was measured in the development sandbox on 2026-10-09. The
commands and their raw output are reproducible with `tools/prove-exposure.sh`.

### The sandbox's three constraints

| capability | result | consequence |
| --- | --- | --- |
| `bind()` a TCP listener | `EACCES` | the origin cannot be a TCP port; a unix socket is the only option |
| `connect()` any TCP destination | `EPERM`, loopback included | no tool can reach a local TCP origin, and no direct egress exists |
| UDP socket | `EPERM` | QUIC, and therefore cloudflared's default transport, is impossible |
| egress | HTTP CONNECT proxy at `169.254.169.1:44561`, hostname allow-list | the only route out, and it resolves DNS for us |

The proxy allow-list is per host **and** per port. Measured verdicts, taken by
sending a real `CONNECT` and reading the proxy's own status line:

```
ALLOWED  api.trycloudflare.com:443          BLOCKED  api.trycloudflare.com:7844
ALLOWED  trycloudflare.com:443              BLOCKED  trycloudflare.com:7844
ALLOWED  region1.v2.argotunnel.com:443      BLOCKED  region1.v2.argotunnel.com:7844
ALLOWED  login.trycloudflare.com:443        BLOCKED  bore.pub:7000
```

The tunnel edge lives on port **7844** (confirmed from the SRV record
`_v2-origintunneld._tcp.argotunnel.com`, which returns
`1 1 7844 region1.v2.argotunnel.com`). Port 7844 is blocked on every host
tested, so **a genuine Cloudflare tunnel cannot be established from this
sandbox**, over QUIC or HTTP/2 alike. Port 443 on the edge host is allowed but
is Cloudflare's ordinary HTTP frontend, not the tunnel endpoint: with SNI
`h2.cftunnel.com` it answers the HTTP/2 preface with
`HTTP/1.1 400 Bad Request` and negotiates no ALPN.

### Control: the real cloudflared binary

Downloaded `cloudflared` 2026.10.0 and ran it against the same unix origin:

```
$ cloudflared tunnel --no-autoupdate --protocol http2 --url unix:/tmp/cfrs_origin.sock
INF Requesting new quick Tunnel on trycloudflare.com...
failed to request quick Tunnel: Post "https://api.trycloudflare.com/tunnel":
  dial tcp: lookup api.trycloudflare.com on 9.9.9.9:53:
  write udp 10.0.2.15:37704->9.9.9.9:53: write: operation not permitted
```

It dies at DNS, before Cloudflare. It does not honour `HTTPS_PROXY`, and
`cloudflared tunnel --help` has no proxy flag for its own edge connection, so
there is no configuration that makes it work here. That is the failing-before
control for the provisioning path that `cfrs provision` then performs.

### What `cfrs provision` does instead

The same credential-free POST, routed through the CONNECT proxy so the proxy
resolves the hostname. Live output from the Rust binary:

```
$ cfrs provision
cfrs: requesting a quick tunnel from https://api.trycloudflare.com via 169.254.169.1:44561 (no credentials)
url:     https://day-carroll-healing-consolidated.trycloudflare.com
id:      2983af16-7c68-4ef0-9590-e05f35a0cd7b
account: 5ab4e9dfbd435d24068829fda0077963
secret:  32 bytes decoded from 44 base64 chars
```

This is the real anonymous-provisioning step, reproduced from
`cmd/cloudflared/tunnel/quick_tunnel.go` (`RunQuickTunnel`) rather than from
documentation. The response carries real edge credentials; opening the edge is
what port 7844 prevents.

`--otp` sends `{"auth_mode":"otp"}` instead of an empty body. That mirrors
`cloudflared --allowed-mail`, where the allow-list itself never leaves the
client: Cloudflare is told only that a PIN is required.

### What `cfrs serve` does instead, and the proof

With the edge unreachable, the tunnel is carried over an SSH remote forward to
a relay that answers on port 443, which the allow-list permits. Each visitor's
`forwarded-tcpip` channel is spliced to the unix socket, so the blocked TCP
path is never used and the origin needs no listening TCP port.

Relay choice was measured, not guessed:

- tunnelmole is WebSocket-based and needs no account, but its endpoint is
  `wss://service.tunnelmole.com:8083`, and **8083 is blocked**. Ports 80 and
  443 answer but return 404 for every WebSocket path tried.
- `localhost.run`, `serveo.net`, `pinggy.io` and others serve SSH. Measured SSH
  banners through the proxy: `localhost.run:443` speaks TLS, not SSH;
  `free.pinggy.io:443` and `serveo.net:443` return real SSH banners.
- pinggy's documented `ssh -R0:localhost:PORT free.pinggy.io` maps exactly onto
  an SSH remote forward, and its docs describe the HTTP-proxy path.

The relay rejects `auth none` and offers `PublicKey` and `Password`, so `cfrs`
generates an ephemeral Ed25519 key from OS entropy and authenticates with it.

The proof, from `tools/prove-exposure.sh`:

```
== 2. baseline: origin directly over its unix socket ==
  cf-origin OK
  marker=1
  path=/baseline

== 3. start cfrs serve (SSH remote forward over CONNECT proxy) ==
public URL = https://eajet-27-34-73-125.free.pinggy.net  (remote port 7)

== 4. fetch the public URL from a fresh client ==
    http=200 time=5.865175s
  cf-origin OK
  marker=2
  path=/proof?via=public
  agent=cf-origin-unix-socket

== 5. fetch again (a fresh marker proves a real traversal) ==
    http=200 time=0.635670s
  cf-origin OK
  marker=3
  path=/proof?via=second

PASS: the public URL served the unix-socket origin through the tunnel.
```

The origin increments a marker per request, so `marker=2` then `marker=3` are
two genuine traversals rather than one cached response. With
`CFRS_DEBUG=1` the full path is visible on stderr:

```
cfrs: visitor channel opened from 0.0.0.0:7 -> "/tmp/cfrs-app.sock"
cfrs: channel->origin 461 bytes: "GET /hello HTTP/1.1\r\nHost: eajet-...free.pinggy.net..."
cfrs: origin->channel 146 bytes: "HTTP/1.1 200 OK\r\nContent-Type: text/plain..."
```

External visitor, through the relay edge, over the SSH channel, to a unix
socket that nothing else can reach.

### What this does not establish

- The relay carries the tunnel, so the relay operator can see the traffic.
  `cloudflared`'s edge is the private alternative, and it is unreachable here.
  For anything that must not be readable by a third party, run cfrs on a host
  that can reach port 7844 and point it at Cloudflare instead.
- `cfrs provision` returns working edge credentials but does not open the edge
  connection. Registration and visitor serving are not implemented. The HTTP/2
  and QUIC transports build connections and frame messages, but nothing drives
  them in a serving loop, so a `Tunnel` is configuration and routing rather than
  a running tunnel. Port 7844 is unreachable from the sandbox this was built in,
  so that part is untested rather than proven.
- The relay's host-key check accepts any key. The relay is anonymous and
  ephemeral, but a deployment fronting sensitive traffic should pin one.

## Design notes

### Why a unix socket, and why an SSH channel

The three sandbox constraints interact. `bind()` on TCP is refused, so a
listener is impossible; `connect()` on TCP is refused even to loopback, so even
a listener could not be reached. A unix socket dodges both: it can be bound,
and it is reached with `connect()` on `AF_UNIX`.

That only helps if the relay's data path is something other than TCP to a
local port. An SSH `forwarded-tcpip` channel is a raw byte pipe the relay
opens per visitor, so it can be spliced to anything. `copy_bidirectional` runs
both directions over **one** unix connection and waits for **both** to finish.

Getting that wrong was the interesting bug. An earlier version gave each
direction its own connection to the origin: the request reached the origin, the
reply came back on a socket that had never seen a request, and every visitor
timed out. The request leg must also signal end-of-request, or an origin that
reads to EOF waits forever. Both halves of that are pinned by
`copy_bidirectional_carries_request_and_response_on_one_origin_connection`,
which fails if the end-of-request signal is removed (verified by injecting the
regression and watching it fail).

### Why the CONNECT proxy layer is generic

`proxy::connect_tunnel` returns a plain byte pipe, so anything that runs on TCP
runs on top of it. `read_connect_response` is generic over `Read` so the
parsing, the allow-list refusal, and the byte-coalescing case are all testable
without binding a socket, which a sandbox may refuse to do.

## Layout

| path | what it does |
| --- | --- |
| `src/proxy.rs` | HTTP CONNECT transport, generic over `Read`/`Write` |
| `src/quicktunnel.rs` | anonymous Cloudflare provisioning, no credentials |
| `src/relay.rs` | SSH remote forward, splicing channels to a unix socket |
| `src/cloudflare/mod.rs` | edge discovery, credentials, embedded edge roots |
| `src/cloudflare/http2.rs` | HTTP/2 edge transport, header encoding, stream classification |
| `src/cloudflare/quic.rs` | QUIC edge transport, ALPN and SNI, data-stream preamble |
| `src/config.rs` | cloudflared-compatible YAML config and ingress rules |
| `src/origin/` | TCP, unix-socket, static-file and SPA origins |
| `src/transport/` | SSH and WebSocket relays |
| `src/tunnel/mod.rs` | configuration, ingress routing, request preparation |
| `src/feature/mod.rs` | QR rendering and the feature flag surface |
| `src/util/` | HTTP head parsing, TLS helpers, metrics |
| `src/bin/cfrs.rs` | CLI: `provision`, `serve`, `tunnel`, `metrics` |
| `tools/cf-origin.rs` | test origin, serves over a unix socket with a marker |
| `tools/prove-exposure.sh` | end-to-end proof, origin to public URL |

## Tests

```sh
cargo test
```

33 tests, including a provisioning response captured from the live service, the
allow-list refusal string, byte-coalescing on the CONNECT response, URL
extraction from real relay output, and the splice ordering regression above.

## Licence

0BSD. See `LICENSE`.