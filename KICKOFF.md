# cfrs: resume and finish

You are picking up a Rust project in a fresh container. You have no prior
context and no memory of any earlier session. Everything you need is in this
file. Do not assume anything that is not stated here, and verify anything this
file claims about the machine before you rely on it.

Do the setup, then work. Do not stop to report that setup worked. If a setup step
fails, report its exact output and hold.

---

## 0. Setup

### 0.1 Install the toolchain

This is the verbatim bootstrap line from the sandhome route document. There is
nothing to clone and nothing to fill in:

```sh
curl -fsSL https://raw.githubusercontent.com/talaria0101/sandhome/main/bootstrap.sh | sh -s -- --toolset developer
```

It installs a global hook into every writable `PATH` directory that runs
binaries, so a fresh shell finds `sandhome` on its own and you do not source
anything. The route document it comes from is
https://github.com/talaria0101/sandhome/raw/refs/heads/main/ROUTE.md

One flag worth passing. `--exec DIR` chooses where build artifacts land, and the
exec root is where every build artifact must go because the home often refuses
`execve`. Give it a roomy path, because section 2 is about storage:

```sh
curl -fsSL https://raw.githubusercontent.com/talaria0101/sandhome/main/bootstrap.sh | sh -s -- --toolset developer --exec /workspace/exec
```

Then confirm readiness. `doctor` ends in `doctor_failures=N` and exits non-zero
when N is not zero; treat a non-zero exit as the task not being ready:

```sh
sandhome doctor && echo READY
```

**On this host the previous session saw `global=none`**, meaning the host had no
writable directory that runs binaries, so the hook was not installed and
`sandhome` was not on `PATH`. If `sandhome` is not found, the entry point beside
the durable home is the way in and needs no `PATH` and no login shell:

```sh
. "${XDG_DATA_HOME:-$HOME/.local/share}/sandhome/entry.sh"
sandhome doctor
```

That is the cold-shell path and it works whether or not the hook installed.
Source it in every shell you use, since a child cannot change its parent.

### 0.2 Fix the cargo environment

Two environment problems were measured in the previous session on this image.
Verify rather than assume, then fix:

```sh
ls "$HOME" >/dev/null 2>&1 && echo "HOME readable" || echo "HOME NOT readable"
echo "CARGO_HOME=${CARGO_HOME:-unset}"
printf 'TMPDIR=%s\n' "${TMPDIR:-/tmp}"
mkdir -p /tmp/probe.d && printf 'int main(void){return 0;}\n' > /tmp/probe.d/p.c \
  && cc -o /tmp/probe.d/p /tmp/probe.d/p.c 2>/dev/null \
  && /tmp/probe.d/p && echo "tmp can exec" || echo "tmp CANNOT exec"
```

Then, in every shell:

```sh
export TMPDIR="$SANDHOME_EXEC/tmp"; mkdir -p "$TMPDIR"
export CARGO_HOME="$SANDHOME_EXEC/cargo-home"
```

Both redirects are needed and both were needed before:

- **`TMPDIR`.** `/tmp` compiles but refuses to run binaries on this image. Any
  test that compiles a C program and runs it fails with `Permission denied`
  there. This is not a `noexec` mount flag: the mount shows no refusal anywhere
  and still refuses to execute, which is why it has to be probed rather than
  inferred from the mount table.
- **`CARGO_HOME`.** The inherited value pointed into a directory that uid 0 cannot
  read here, so cargo failed with `Permission denied` writing its index cache.

### 0.3 Get the code

```sh
cd /workspace
git clone https://github.com/talaria0101/cfrs.git
cd cfrs
```

Already pushed, not to be redone: commit `0f9c992` is on `main` and on branch
`userspace-virtual-net`. It carries a userspace virtual network, 332 passing
tests, and the fixes listed in section 4.

```sh
cargo test
```

If that is not green, the environment is still wrong. Do not start work on a red
baseline.

---

## 1. What this project is

`cfrs` exposes services from a sealed sandbox on the public internet through
Cloudflare tunnels, from a single Rust binary, with no `cloudflared` subprocess
and no account needed for quick tunnels. 0BSD.

A sealed sandbox here means: no `bind(2)` on `AF_INET`, no network namespace, no
TUN device, no `CAP_NET_ADMIN`. The host can leave only through an HTTP CONNECT
proxy on an allow-list, where port 443 is permitted and Cloudflare's tunnel port
7844 is not.

Read these four things before deciding anything. Each is load-bearing:

- **`README.md`** states plainly what works and what does not. Both halves
  matter. It has already been corrected once for claims that turned out false.
- **`THIRD_PARTY_NOTICES.md`** names every defect found in code ported from
  Nemo-010/cfrs, and explains why the tunnel core was not ported.
- **`VIRTUAL-NETWORK.md`** is the design and specification of the userspace
  network in `src/vnet/`. §11 reconciles it against the code and is honest about
  what is not built.
- **Issue #1**, https://github.com/talaria0101/cfrs/issues/1, is the full
  write-up of where this stands: what is better than the reference
  implementation, what was dropped, and what each fix was pinned by. Read it end
  to end.

---

## 2. Mind the space

**The previous session died after writing past 11 GiB.** Read that as a fact
about the container, not as a warning to skip. The filesystem has room, but a
container can be killed by a quota that `df` does not show.

- Build output goes on the exec root, one `CARGO_TARGET_DIR`, never inside the
  repository and never in `/tmp`. `env.sh` points `CARGO_TARGET_DIR` at the exec
  root already; check it rather than trusting it.
- Check before a large build, not after:

```sh
df -h /workspace "$SANDHOME_EXEC" 2>/dev/null; du -sh "$SANDHOME_EXEC" 2>/dev/null
```

- Keep the exec root under a few gigabytes. When cargo reports it needs more,
  clean the target directory rather than hoping:

```sh
cargo clean    # rebuilds from scratch, so do it between phases, not mid-task
```

- Do not run two builds at once into different target directories. Each debug
  build of this dependency tree is hundreds of megabytes, and the previous
  session ended holding two of them plus two cargo homes.
- A second checkout for comparison is cheap; a second target directory is not.
  If you need to compare against another tree, share the target directory or
  clean the first one.
- Watch it during long operations. A build that is not making progress may be
  filling the disk.

---

## 3. Three rules that decide how the work is done

### 3.1 No unaudited crates. Implement the protocol here.

A previous session refused to adopt `cloudflare-quick-tunnel`, a third-party
crate that performs every provisioning call, every edge discovery and every
credential path, with source that is not vendored or reviewed. Adopting it would
have replaced a checkable implementation with an uncheckable one and lost
`tools/check-header-oracle.sh`, which diffs our header encoding against a
verbatim copy of cloudflared's own Go `SerializeHeaders`.

So the Cloudflare protocol is implemented in this repository, against
`cloudflare/cloudflared` as the reference. Extend that. When you add a wire
format, add the oracle case with it. A unit test written from the same reading
that produced the bug is not evidence: the header encoding was wrong in three
separate ways that way, including a base64 literal wrong in a single character,
and every such test passed.

Dependencies already in use, all with visible source: `russh`, `quinn`, `h2`,
`tokio-rustls`, `rustls`, `hickory-resolver`, `serde_yaml`, `qrcode`, `smoltcp`,
`ureq`. Prefer extending these. `smoltcp` is the userspace TCP/IP stack and is
the right dependency for that job. Anything new needs a stated reason for not
being implementable here, plus a licence check.

### 3.2 Measure from below the thing you are measuring.

`cfrs net demo` once printed "kernel AF_INET bind/connect used: none" from a
field set to a literal zero. A userspace stack cannot observe its own syscalls, so
that line was a claim about a number nothing counted, and it would have stayed
true if a direct `AF_INET` connect were added anywhere on the path.

The real measurement reads the socket inode from `/proc/self/fd/N` and asserts
which kernel protocol table holds it. Note that `getsockname` cannot be used for
this: the shim interposes it and answers with the logical address it recorded, so
a probe built on it measures the shim's bookkeeping. That was tried first and it
answered `inet`.

Same discipline everywhere: a function named verify, check or prove that does not
measure is a defect. A counter compared against its own initial value is a
defect. A test that passes both with a fix and without it is not a test.

### 3.3 Every claim carries a failing-before control.

Reproduce the failure first, then fix it, then confirm the test goes red when the
fix is removed. All nine defects in section 4 were done that way. Do not skip the
last step. Three separate tests in this repository passed for the wrong reason and
were caught only by removing the fix.

This matters more than usual with the work below, because the reference
implementation's own suite could not see its worst bug: every one of its tests
opened a socket as its first action, so the shim's failure on programs that do
not open one was invisible to all of them.

---

## 4. What was already fixed

Do not redo any of this. Listed so you know the state and do not reintroduce it.

In code ported from Nemo-010/cfrs, each reproduced, each pinned by a test that
goes red without the fix:

| defect | symptom |
| --- | --- |
| `close`, `dup*`, `listen`, `getpeername`, `getsockname` never ran the lazy symbol resolver | `SIGSEGV` for any program closing a descriptor before opening a socket |
| `getsockname` zeroed a 128-byte `sockaddr_storage` | stack smashing for any buffer under 128 bytes |
| `getsockname(fd, NULL, &len)` dereferenced null | `SIGSEGV` on the standard length-query idiom |
| a short buffer returned `EINVAL` | Linux truncates and reports the true length |
| `fcntl` read a `va_arg` that was never passed | undefined behaviour at `-O2` |
| `accept` clamped against the kernel's length, not the caller's capacity | the comment promised a bound the code could not honour |
| `ControlMessage::encode` truncated at a byte budget that could split a UTF-8 character | panic: byte index is not a char boundary |
| the control decoder kept the bad byte at the head | the stream wedged permanently, buffer grew unboundedly |
| closed sockets were never removed from the smoltcp `SocketSet` | every connection leaked its buffers for the process lifetime |

In older code, on correctness grounds rather than because something crashed:

- `static:` served files through a symlink pointing out of the served root. The
  traversal check is now canonicalise-then-compare. A symlink inside the root
  still works.
- A response's hop-by-hop headers were replayed next to the edge's HTTP/2
  framing, giving two disagreeing answers about where the body ends. Both
  directions filter them now.
- `build_visitor_request` replaced the whole request with a bare `GET /` when the
  `http` crate rejected any header, so one bad header turned a visitor's POST
  into a GET. It now drops only the offending header.
- A provisioning decode error printed the tunnel secret, because the response
  body is mostly credentials. Now redacted, with the clip on a character
  boundary.

One claim was withdrawn rather than fixed, as described in rule 3.2.

---

## 5. What is missing

Priority order. Each item says what "done" looks like, so there is no debate at
the end.

### A. Serve traffic over the Cloudflare edge

The largest gap, and the one that changes what the tool is. `cfrs tunnel` loads
ingress rules, resolves the edge, provisions credentials and prints a URL, and
then does not serve. The HTTP/2 and QUIC transports in `src/cloudflare/` build
connections and frame messages; no serving loop consumes them. No connection is
registered with the edge and no visitor is ever served.

Drive them: registration, the per-stream `ConnectRequest` preamble, the visitor
request and response, reconnect with backoff, HA over `conn_index`.

Honesty required: port 7844 is blocked on the development host, over QUIC and
over HTTP/2 alike, so this may be untestable here. If it is, say so explicitly,
do not claim it works, and get as close to the edge as the constraint allows: a
serving loop over a recorded or synthetic edge, so the state machine is exercised
even though the real edge is not reached. An untested claim marked untested is
acceptable. An untested claim marked working is not.

### B. The features dropped with the tunnel core

These exist in the reference implementation and are absent here. Port them from
`cloudflare/cloudflared`, not from Nemo-010/cfrs.

- **Named tunnels.** `--token` and `--credentials-file`, and the
  `credentials-file:` key in a config file. Read the credentials JSON locally;
  never log the secret or the account tag.
- **cloudflared-compatible `config.yml`.** Ordered ingress rules, hostname and
  path matching, the catch-all last rule, `originRequest` settings including
  `noTLSVerify` and `connectTimeout`. `src/config.rs` parses part of this shape
  already; finish it.
- **`--forward` and `cfrs connect`.** A quick tunnel is an HTTP tunnel, but it
  proxies WebSocket upgrades, and a WebSocket is a byte pipe. `--forward` exposes
  one at a fixed path; `cfrs connect -L` turns a local socket into connections
  through it. This is the websocat idea and it removes the HTTP-only limit, so
  raw TCP, unix sockets and interactive protocols cross the tunnel. Every
  accepted local connection opens its own WebSocket, so framing is preserved.
- **`cfrs share` as a working service.** The gate is already here and correct:
  `src/share.rs` compares the token in constant time, rate limits the PIN, and
  answers a wrong token with 404 so a prober learns nothing. Missing is the HTTP
  service behind it: multipart upload with per-file and count caps, single-file
  download, proxy mode. The reference version ships with no authentication on its
  primary paths, which is how it passed review there and would fail here.

### C. The rest of the virtual network

From §11 of `VIRTUAL-NETWORK.md`, in full, including what is already listed open:

- **The control server.** The codec in `src/vnet/control.rs` encodes and decodes
  every op and resynchronises past a bad frame, but nothing binds
  `\0cfrsnet/ctl`. Switch mode is therefore not wired end to end, which is why
  cross-host is not available today. This is the item that makes the virtual
  network a network rather than a namespace, so it is the one worth doing.
- **Fault injection.** `smoltcp` ships `FaultInjector` and `FuzzInjector`.
  Wrapping the virtual link lets a test drop, reorder, duplicate or corrupt
  packets on demand, so retransmission and RTO behaviour become reproducible
  instead of flaky.
- **Bounded link queues.** `LinkDevice` builds unbounded queues, so the
  documented drop-when-full policy is unreachable and a stalled pump buffers
  without limit. Add the capacity to the device and to the pump.
- **The single-waker slot** in `PacketQueue`. `NetStack::link_in` hands out
  clones while the reactor parks on the same queue, so a second waiter overwrites
  the first's registration and can starve it. Support multiple waiters, or make
  `recv_or` the only way to obtain one.
- **`LinkDevice::wait`** is not implemented, and the MTU is floored at 1280 so
  §8's "set `max_transmission_unit` to the link's maximum" cannot be followed.
- **`PcapFile::decode`** accepts only the exact flavour it writes. It rejects
  `incl_len < orig_len`, which is what `tcpdump -s 96` produces, and it rejects
  big-endian and nanosecond captures. Fix it, with the three tests that prove it.

### D. Security and durability

- **SSH host key pinning.** Both `src/relay.rs` and `src/transport/ssh.rs` return
  `Ok(true)` from `check_server_key`. The relay path is the only one that produces
  a working public URL on this host, so this is a live exposure: a network
  attacker on the path reads and modifies all tunnel traffic in both directions,
  and can substitute responses. The URL being unguessable does not help, because
  the attacker obtains it from the same unauthenticated channel. Add a pinned-key
  or known-hosts path and a flag that says so when it is off. The current comment
  argues the traffic "is only as sensitive as the public URL itself", which does
  not hold; replace it with the real trade-off.
- **Resource limits on internet-facing paths.** No cap on concurrent visitor
  channels, no per-connection timeout on the splice, no timeout on
  `UnixStream::connect` in the relay path. A client that opens a channel and says
  nothing holds a task and an origin fd until the one-hour session timeout, and
  that timeout is on the SSH session, not the channel.
- **`cfrs connect -L unix:/path`** unlinks whatever is at that path without
  checking whether it is a stale socket, and discards the result. A destructive
  default on a path the user named explicitly.

---

## 6. Working notes for this host

Both of the first two produced failures that looked like code defects and were
not.

- **`/tmp` compiles but refuses `execve`.** Any test that compiles C and runs it
  needs `TMPDIR` on the exec root. With the inherited `TMPDIR` the shim test
  suite fails 3 of 4 with `Permission denied`.
- **An abstract socket name is one global namespace for the whole host**, and
  `cargo test` runs tests in a file in parallel threads. Two tests binding the
  same port produce a `bind-failed` that reads exactly like a shim that failed to
  interpose. Every test that binds uses its own port: `1809x` for
  `af_inet_kernel`, `1818x` for `shim_no_socket`, `18080`/`18081`/`19999` for
  `shim_direct`.
- **`cargo clippy --all-targets`** is available, and the tree is warning-clean
  apart from deliberate `#[allow]`s that carry the reason in a comment.

---

## 7. Finishing

- `cargo test` is the gate. Green means green, and a passing count beside an
  error line means a file never ran. Read the exit code, not the count.
- Update `README.md` honestly. If something still does not work, say so in the
  "What does not work yet" paragraph rather than leaving it to be discovered.
- Update `VIRTUAL-NETWORK.md` §11 and `THIRD_PARTY_NOTICES.md` to match the code.
- Port from `cloudflare/cloudflared`, cite the commit, and extend
  `tools/check-header-oracle.sh` for every wire format you add.
- Commit as `Talaria <324092415+talaria0101@users.noreply.github.com>`. Do not
  pass `-c user.name`, `-c user.email`, `--author`, or set `GIT_AUTHOR_*`.
- Say plainly what you did not finish, and why. A partial with the gap named is
  worth more than a complete-sounding report with a hole in it.