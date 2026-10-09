# Third-party notices

## cf-edge-roots.pem

`src/cloudflare/cf-edge-roots.pem` contains the three root certificates the
Cloudflare tunnel edge presents, extracted verbatim from
`tlsconfig/cloudflare_ca.go` in [cloudflare/cloudflared][cloudflared] at
commit `master` (fetched 2026-10-09). They are the roots cloudflared adds on top
of the platform trust store, and they are not in any public trust store.

Those certificates are part of Cloudflare's source distribution and remain
under **Apache-2.0**, as cloudflared is. cfrs itself is 0BSD; this file is the
one Apache-2.0 item in the tree, and it is data rather than code.

The certificates are used only to verify the tunnel edge. cfrs adds them to the
platform roots rather than replacing them, so ordinary public CAs continue to
work.

[cloudflared]: https://github.com/cloudflare/cloudflared

## The capnp schemas and the edge protocol

`tunnelrpc` describes the registration RPC and per-stream framing. The field
names and stream preamble in `src/cloudflare` were implemented from the
published description of that protocol and from the observable behaviour of the
edge; no Cloudflare source is vendored for it.