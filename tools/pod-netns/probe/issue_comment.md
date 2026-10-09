I built `pod-netns` from this issue's design and measured it in the sealed cage.
Three of the claims in the implementation notes above are contradicted by
measurement on this host, and one of them was load-bearing for my own
implementation, where it hid a real defect.

The code is at **`tools/pod-netns`** in this repository: a standalone crate, 30
passing tests, zero warnings, with a runnable C probe behind every number below
(`tools/pod-netns/probe/`, indexed in its own README).

## What works, confirmed

The seccomp-notification backend does work here, and I have it carrying real
bytes in both directions:

```
outbound   child connect() -> 0; origin received b'GET / HTTP/1.0\r\nHost: origin\r\n\r\n';
           62 bytes returned including the token; log: "62,32 bytes each way"
inbound    client connected to the backing AF_UNIX socket; the child's accept
           returned fd 6 and read b'GET /inbound HTTP/1.0' (34 bytes relayed)
```

A statically linked Go binary and a dynamic libc binary both work, so the claim
that no loader is needed holds.

## Three claims that do not hold on this host

### 1. `ADDFD` works. The pool is a workaround for a limitation that does not exist.

The notes say `ADDFD` injects a descriptor. That is right, and stronger than
stated: it works in **all four** combinations, including `newfd_flags=0`, which
the notes describe as impossible.

```
flags=0              newfd_flags=0        -> rc=3 OK
flags=0              newfd_flags=O_CLOEXEC -> rc=3 OK
FLAG_SEND            newfd_flags=0        -> rc=3 OK
FLAG_SEND            newfd_flags=O_CLOEXEC -> rc=3 OK
```

`tools/pod-netns/probe/addfd_clean.c`, one notification per attempt. That detail
is the whole story: my first probe made four `ADDFD` calls against a *single*
notification, the first call succeeded and consumed it, and the remaining three
returned `ENOENT`. I recorded "ENOENT for all flag combinations, therefore
unavailable" from that and built a pool to route around it. A probe that reports
a resource as absent because its own earlier call consumed it is a probe bug
wearing a measurement's clothes, and it cost a design decision.

There is no `SECCOMP_ADDFD_FLAG_RECV` in the uapi header, only `FLAG_SEND`, so a
`SEND|RECV` combination cannot be expressed.

I have **not** migrated to `ADDFD`. It is the right fix and it is not a swap:
`ADDFD` hands over a descriptor without resolving the pending syscall, so the
supervisor must also answer the notification, and the fd numbering stops being
something we control. Until then the pool is correct and my earlier claim that
`ADDFD` is unavailable was wrong.

### 2. A UDP ASSOCIATE round trip cannot run here.

UDP `send` is `EPERM`:

```
socket(AF_INET, SOCK_DGRAM) -> 3 (ok)
connect 1.1.1.1:53           -> 0 (ok)
send    2 bytes             -> -1 (Operation not permitted)
sendto                      -> -1 (Operation not permitted)
```

No datagram leaves the host, so the relay described cannot function in this cage
and the "UDP echo round trip" test was not run here. It is probably a genuine
result on a host with UDP. The same reasoning applies to the fake-IP DNS pool: it
intercepts UDP/53 and needs to send a reply through a socketpair, which works, but
the claim that "`getaddrinfo("example.com")` resolves to `198.18.0.0`" as a
*passing* test implies a resolver that can complete.

### 3. `io_uring` is denied by the cage, not by the filter.

```
io_uring_setup(8 entries) -> -1 Operation not permitted
```

So the reasoning in the notes is right and the conclusion is unnecessary *here*: a
program cannot use io_uring to bypass anything, because it cannot create a ring.
The gap the notes describe is real and portability-relevant on a host that permits
io_uring, and I state it the same way in my own tool rather than closing it.

## A defect the notes warned about, which I had anyway

The notes say: "`setsockopt` is answered `0` for injected sockets. An `AF_UNIX`
socketpair rejects the IP-level option glibc's resolver sets, and the resolver
then aborts before sending."

I passed `setsockopt` through, and that broke DNS for every glibc program under
pod-netns. Same option, no interception vs intercepted:

```
bare                    setsockopt(IPPROTO_IP, IP_TOS, 0) -> 0 (ok)
under pod-netns         setsockopt(IPPROTO_IP, IP_TOS, 0) -> -1 EOPNOTSUPP
```

`EOPNOTSUPP` from the kernel because the fd is a socketpair, and glibc's resolver
aborts when its option fails. The symptom is a name-resolution error, which points
at DNS rather than at a proxy. Now answered `0` for a socket we handed out, with a
test that asserts it matches the bare control.

Worth saying plainly: the warning was in the notes and I hit it anyway, so a
correct written warning is not the same as a fix.

## Agreement on one point

The notes' "Remaining host limits" section is right, and so is mine:
`getsockname`/`getpeername` address rewriting needs `O_RDWR` on
`/proc/<pid>/mem`, this host denies it, and `PR_SET_DUMPABLE` does not change it.
Independently measured here:

```
open(/proc/<pid>/mem, O_RDONLY)  -> ok
open(/proc/<pid>/mem, O_WRONLY)  -> -1 Permission denied
open(/proc/<pid>/mem, O_RDWR)    -> -1 Permission denied
process_vm_writev                -> -1 Operation not permitted
ptrace(PTRACE_ATTACH)            -> -1 Operation not permitted
```

CapEff is 0, and the kernel gates the write path on `CAP_SYS_RESOURCE`. My
implementation passes the call through and tells the operator what it would have
said, rather than fabricating an address it cannot deliver. I had recorded that
this file was "readable and writable", which was wrong in the same way the `ADDFD`
claim was: the probe opened the file and never wrote through it.

## Two more traps, since they cost me the same kind of wrong turn

**`seccomp_notif` must be zeroed before every `NOTIF_RECV`.** The kernel rejects a
struct with any field set, and `EINVAL` is indistinguishable from a spent
listener. Reusing the struct across calls shows one good notification then
`EINVAL` forever, which reads as a hard ceiling. It is not: **64 of 64 served**
(`probe/multin.c`).

**BPF miss offsets must be 0, not `n-j+1`.** A miss has to fall through to the
next comparison. With the wrong value it skips the rest of the chain to
`RET ALLOW`, so only the first target is intercepted and everything else in the
list is dead code. Over a matrix of every syscall at every position, the old
builder notified **8 of 36** cells, a clean position-0 diagonal; the correct one
notifies **36 of 36** (`probe/offsetfix.c`). This is the one that had the longest
life: every fixture binds first, so the working path and the broken path were the
same path.

**A third one the notes do not mention, because it is not about a capability.** The
filter has to be installed into the *child*, from a pre-exec hook, and the
supervisor must not be filtered. A filter installed in the supervisor is in scope
for every thread the tool creates, so the supervisor's own `connect` to an upstream
raises a notification that the supervisor, being the thread blocked inside that
connect, cannot service. The tool deadlocks with the child frozen in its own
`connect` (`probe/selfdl.c` exits 124). Passing the notification through does not
help, because a blocked thread cannot reach its own listener. This is the one that
cost me the most time, and nothing in the notes warns about it.

## What I did not do

- No `doctor` subcommand. The cage facts are in the README, but a machine-readable
  capability probe is the right shape for this and I did not build it.
- No `sendto`/`sendmsg`/`sendmmsg` interception, so a program that writes with
  `sendto` rather than `write` gets the kernel's own behaviour on a socketpair.
- No DNS interception. UDP `send` is `EPERM` here so the fake-IP pool has nowhere
  to send the upstream query anyway.
- No chaining, no front door, no routing rules, no tailscale transport. The
  connector layer is a single upstream chosen once at startup.
- `io_uring` interception, which cannot be done by seccomp at all on a host that
  permits it.

## About the notes themselves

`tests/pod_netns_seccomp.rs` is cited three times, with a description of what each
test asserts. It is not in the repository. So is the seccomp backend: `grep` for
`USER_NOTIF`, `NOTIF_ADDFD` or `SECCOMP_IOCTL` across `src/` and `tests/` returns
nothing, and there is no `pod_netns` binary. `src/vnet/doctor.rs` exists and
probes `unshare`, `/dev/net/tun` and `ptrace_scope`, but no seccomp capability.

I am not claiming that is what was intended, only what is there now. My
measurements above are all from this host and reproducible with the probes in
`tools/pod-netns/probe/`.

One correction to my own work in the same spirit: the implementation notes were
right about `setsockopt` and I shipped the bug anyway, and my own code carried two
false measurement records that shaped real design decisions. Those are fixed, and
the record now names what each probe got wrong, so the next person does not
rediscover them the expensive way.