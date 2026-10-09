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

## The userspace virtual network

`src/vnet/` and `shim/cfrsnet.c` implement the design in
[`VIRTUAL-NETWORK.md`](./VIRTUAL-NETWORK.md), a private IPv4/IPv6 address space
that exists without a network namespace, a TUN device or `CAP_NET_ADMIN`. It
began as a port of [`Nemo-010/cfrs`][nemo], which is also 0BSD, and the port
carried over code rather than ideas. The substantive changes made here are
listed under *What changed in the port* below, and the defects fixed are named
in the module documentation and in `tests/vnet_regressions.rs`.

The dependency is [smoltcp][smoltcp] 0.11, also 0BSD, pinned exactly because its
device and wire APIs are not covered by semver. `SMOLTCP_IFACE_MAX_ADDR_COUNT`
is raised in `.cargo/config.toml`; smoltcp's default of 2 cannot hold the four
addresses this stack needs.

## What changed in the port

Nine defects were found in the ported code, each reproduced before it was fixed
and each now pinned by a test that fails without the fix. They are the reason
this section exists: a port is not the same as a copy, and the differences are
the review.

| defect | symptom | where it is pinned |
| --- | --- | --- |
| `close`, `dup*`, `getpeername`, `getsockname`, `listen` never ran the lazy symbol resolver | every program that closes a descriptor before opening a socket died with `SIGSEGV` | `tests/shim_no_socket.rs` |
| `getsockname` zeroed a 128-byte `sockaddr_storage` into the caller's buffer | stack smashing on any buffer smaller than 128 bytes | `tests/shim_no_socket.rs` |
| `getsockname(fd, NULL, &len)` dereferenced the null pointer | `SIGSEGV` on the standard length-query idiom | `tests/shim_no_socket.rs` |
| a short buffer returned `EINVAL` | Linux truncates and reports the true length | `tests/shim_no_socket.rs` |
| `fcntl` read a `va_arg` that was never passed | undefined behaviour at `-O2` | `shim/cfrsnet.c` |
| `accept` clamped the copy against the kernel's length, not the caller's capacity | the comment promised a bound the code could not honour | `shim/cfrsnet.c` |
| `ControlMessage::encode` truncated an `Error` at a byte budget that could split a UTF-8 character | panic: byte index is not a char boundary | `tests/vnet_regressions.rs` |
| the control decoder returned its error with the bad byte still at the head | the stream wedged permanently and the buffer grew without bound | `tests/vnet_regressions.rs` |
| closed sockets were never removed from the smoltcp `SocketSet`, and a dropped `TcpStream` was never noticed | every connection leaked its buffers for the life of the process | `tests/vnet_regressions.rs` |

Four more changed without a reproduction, because they are correctness rather
than crashes: the proxy reported success before the connection existed,
`FrameDecoder` wedged on a zero-length frame, `max_poll_interval` was
overridden by a hardcoded clamp, and the static-file origin's traversal check was
lexical, so a symlink out of the served root was served.

[nemo]: https://github.com/Nemo-010/cfrs
[smoltcp]: https://github.com/smoltcp-rs/smoltcp

## The capnp schemas and the edge protocol

`tunnelrpc` describes the registration RPC and per-stream framing. The field
names and stream preamble in `src/cloudflare` were implemented from the
published description of that protocol and from the observable behaviour of the
edge; no Cloudflare source is vendored for it.