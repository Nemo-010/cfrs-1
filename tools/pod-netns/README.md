# pod-netns

Run a program with a userspace network, and **no shims**.

```
pod-netns [OPTIONS] -- PROGRAM [ARGS...]
```

No `LD_PRELOAD`, no interposer, no source change, no wrapper binary. A statically
linked Go program is handled exactly like a libc-linked C one, because the
kernel mediates the syscalls rather than a library interposing on them.

## Why this exists

Every namespace-based virtual network tool (`nsproxy`, `socksns`, `proxy-ns`,
`netns-proxy`, `netns_tcp_bridge`, ...) needs `unshare(CLONE_NEWNET)` and
`/dev/net/tun`. In a sealed host both are denied, so none of them can run. The
remaining usual answer is an `LD_PRELOAD` shim, which cannot reach a statically
linked binary at all, so the programs most worth isolating are exactly the ones
it cannot help.

What is left is `SECCOMP_RET_USER_NOTIF`: the kernel offers us each matching
syscall and lets us choose its result. Measured working here, 64 of 64
notifications served, with no errors.

## What it does

1. pre-creates a pool of `AF_UNIX` socket pairs before `exec`, so the child
   inherits real descriptors;
2. installs one seccomp user-notify filter **into the child**, from a pre-exec
   hook, and hands the listener back to the supervisor over `SCM_RIGHTS`;
3. answers `socket(AF_INET, SOCK_STREAM)` with the number of a pooled socketpair
   end, so everything the child does with that fd lands on a stream the
   supervisor owns the other end of;
4. reads the child's `sockaddr` from `/proc/<pid>/mem`, answers `connect`, and
   relays both directions;
5. for `--listen`, binds an `AF_UNIX` socket, and `accept` hands the child a
   pooled fd carrying the queued connection.

## Verified in this cage

Both directions carry real bytes, with byte counts:

```
outbound   child connect() -> 0; origin received b'GET / HTTP/1.0\r\n...';
           62 bytes came back including the token; log: "62,32 bytes each way"
inbound    client connected to the backing AF_UNIX socket; the child's accept
           returned fd 6 and read b'GET /inbound HTTP/1.0' (34 bytes)
```

`cargo test --release`: 31 tests, 0 failures, 0 compiler warnings.

## Options

| option | effect |
| --- | --- |
| `--listen ADDR:PORT` | the child may `bind` this; traffic is served on an `AF_UNIX` socket whose path is printed at startup |
| `--connect ADDR:PORT` | the child may `connect` this; the flow is carried to `--upstream` |
| `--upstream HOST:PORT` | where a proxied flow goes, by TCP |
| `--upstream-unix PATH` | where a proxied flow goes, by `AF_UNIX` socket |
| `--proxy HOST:PORT` | send the flow through this HTTP CONNECT or SOCKS5 proxy |
| `--socks5` | speak SOCKS5 to `--proxy`, rather than HTTP CONNECT |
| `--no-proxy` | dial `--upstream` directly |
| `--pool N` | pre-inherited socket pairs (default 16) |
| `--verbose` | log every intercepted syscall to stderr |

## Scope, stated plainly

This is **not** a network namespace, and the difference is observable:

- a bind is virtual only for the syscalls intercepted, and only in this process
  tree. A second process binding the same port does not collide, because nothing
  was added to the kernel's port tables.
- everything not intercepted is the kernel's own behaviour, which in a sealed host
  usually means `EPERM`.
- UDP is not proxied. UDP `send` is `EPERM` here, so no datagram can leave the
  host to be relayed, and `SOCK_STREAM` is the only thing claimed.
- `io_uring` is a real hole **on any host that permits it**: the kernel performs
  the submitted operation itself, so there is no syscall left for a filter to
  mediate. Here `io_uring_setup` returns `EPERM`, which is why this has not bitten.

## Not implemented

Named so they are not mistaken for oversights:

- no `doctor` subcommand. The cage facts are in this README, but a
  machine-readable capability probe is the right shape for a tool that has to
  degrade across hosts.
- no `sendto`/`sendmsg`/`sendmmsg` interception, so a program that writes with
  `sendto` rather than `write` gets the kernel's own behaviour on a socketpair.
- no DNS interception. UDP `send` is `EPERM` here, so a fake-IP pool has nowhere
  to send the upstream query anyway.
- no proxy chaining, no front door, no per-destination routing rules. The
  connector layer is a single upstream, chosen once at startup.
- no `io_uring` interception, which cannot be done by seccomp at all on a host
  that permits it.

## Five measurements that shaped the code

Each of these contradicts something this project previously believed, and each
cost a wrong turn first. Every claim is reproducible: `probe/` has a standalone C
file per measurement, and `src/seccomp.rs`'s module docs name the probe bug
behind each superseded claim, because a correction without its cause is one the
next reader repeats.

**1. `seccomp_notif` must be zeroed before every `NOTIF_RECV`.** The kernel
rejects a struct with any field set, returning `EINVAL`, which is
indistinguishable from a spent listener. A caller that reuses the struct sees
one good notification then `EINVAL` forever and concludes the listener serves one
notification. It does not: **64 of 64 served**.

**2. The BPF miss offset must be 0, not `n-j+1`.** A miss has to fall through to
the next comparison. With the wrong value it jumps past the rest of the chain to
`RET ALLOW`, so only `TARGETS[0]` is ever intercepted and the rest of the list is
dead code. Measured with a matrix over every syscall at every position: the old
builder notified **8 of 36** cells, a clean position-0 diagonal; the correct one
notifies **36 of 36**.

**3. The filter must be installed into the child, not into the supervisor.** A
filter installed in the supervisor applies to every thread the tool creates, so
the supervisor's own `connect` to an upstream raises a notification that the
supervisor, being the thread blocked in that connect, cannot service. The tool
deadlocks with the child frozen inside its own `connect`. `probe/selfdl.c` shows
a process whose own `connect` notifies never returning from it.

**4. `/proc/<pid>/mem` is read-only here.** `O_RDONLY` succeeds; `O_WRONLY` and
`O_RDWR` both return `EACCES`, because the kernel gates write access on
`CAP_SYS_RESOURCE` and `CapEff` is 0. `process_vm_writev` and `ptrace` are both
`EPERM`. Reading works, so the child's sockaddr can be recovered on the way in,
but nothing can be put back. An earlier note here claimed the file was writable;
the probe opened it and never wrote through it.

**5. `setsockopt` must be answered 0 for a socket we handed out.** The child's fd
is an `AF_UNIX` socketpair, so the kernel returns `EOPNOTSUPP` for every IP-level
option, and glibc's resolver **aborts** when one of its options fails. Passing it
through made every glibc program under pod-netns unable to resolve a name, and the
symptom was a name-resolution error pointing at DNS rather than at a proxy. Measured
on the same option: bare, `setsockopt(IPPROTO_IP, IP_TOS)` returns 0; through the
socketpair it returns `EOPNOTSUPP`.

## Two open items

- **`SECCOMP_IOCTL_NOTIF_ADDFD` works here**, in all four flag combinations. It
  was recorded as unavailable and the pooled-descriptor design was built to route
  around that; the record was a probe bug (`probe/addfd_clean.c`). Migrating to
  ADDFD is the right fix and is not done, because ADDFD hands over a descriptor
  without resolving the pending syscall, so the supervisor must answer the
  notification too and loses control of the fd numbering.
- **`getsockname` cannot report the bound address.** Doing so means writing the
  sockaddr into the child's own buffer, and `/proc/<pid>/mem` is read-only here
  (`O_RDWR` returns `EACCES`, gated on `CAP_SYS_RESOURCE`; `process_vm_writev`
  and `ptrace` are both `EPERM`). The call is passed through and the operator is
  told what would have been said. A test asserts it is never silently faked.

## Building

A standalone crate under `tools/`, not a workspace member, so it builds and tests
on its own:

```
cd tools/pod-netns
CARGO_HOME=/workspace/.cargo cargo build --release
CARGO_HOME=/workspace/.cargo cargo test --release
```

Dependencies: `libc` and `nix`. Nothing else.

## Tests

`cargo test --release` runs 31 tests. Compiled fixtures are **not** committed, so
build them once first:

```
(cd testdata/sg && CGO_ENABLED=0 go build -o sg .)
(cd testdata/gs && CGO_ENABLED=0 go build -o gs .)
cc -O1 -o testdata/cdyn/cdyn testdata/cdyn.c
cc -O1 -o testdata/relayer testdata/relayer.c
cc -O1 -o testdata/srv     testdata/srv.c
cc -O1 -o testdata/ucli    testdata/ucli.c
cc -O1 -o testdata/iclient testdata/iclient.c
cc -O1 -o testdata/dnsfix  testdata/dnsfix.c
```

`every_fixture_is_built` fails and prints the command for anything missing. That
test exists because `cargo test` captures stderr and discards it on success, so a
test that prints SKIP and returns still reports `ok`: without the gate, a checkout
with no fixtures looks identical to a green run.

The tests that matter are the data-path ones. They fail if the relay stops
carrying bytes, which was checked by planting the defect and reading the exit code
rather than by inspection. The fixture that catches it is an `AF_UNIX` origin
rather than a local TCP one, because this host refuses `bind` on loopback
outright, so there is no way to stand up a TCP origin to talk to.

`probe/` holds a standalone C file per measurement in this README. See
`probe/README.md`.