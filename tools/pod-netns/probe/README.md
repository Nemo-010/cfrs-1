# Probes

One standalone C file per measurement claimed in `../README.md`. Each builds with
`cc -O1 -o <name> <name>.c` and runs without arguments unless noted.

**Why these exist as files and not as paragraphs.** Four claims this crate made
about its own cage were wrong, and every one was wrong because a probe had a bug
rather than because the host disagreed. A reader who trusts a number with no way to
re-run it will trust the next wrong number too. Every file here can be run, and the
ones that were responsible for a wrong claim say so at the top.

Compiled binaries are not committed. Rebuilding is one command and the source is
the evidence.

| probe | claim it backs | what it shows |
| --- | --- | --- |
| `multin.c` | README §1 | `./multin q1`: every non-zero field of `seccomp_notif` gives EINVAL, all-zeros succeeds. `./multin q2 64 0`: 64 of 64 notifications served. |
| `offsetfix.c` | README §2 | `./offsetfix old`: 8 of 36 cells, a clean position-0 diagonal. `./offsetfix new`: 36 of 36. |
| `selfdl.c` | README §3 | `timeout 10 ./selfdl` exits 124: a process whose own `connect` notifies never returns from it. |
| `memrw.c` | README §4 | `/proc/<pid>/mem` is O_RDONLY only; `process_vm_writev` and `ptrace` both EPERM. |
| `sockopt.c` | README §5 | `./sockopt bare`: `IP_TOS` returns 0. `./sockopt sockpair`: the same option returns `EOPNOTSUPP`, which is what aborts a glibc resolver. `./sockopt faked`: prints the answer the supervisor gives. |
| `addfd_clean.c` | "Two open items" | ADDFD works in all four (flags, newfd_flags) combinations, including `newfd_flags=0`. |
| `verify_claims.c` | cross-check | checks three claims from cfrs issue #2 against this host |
| `udp_io.c` | "Scope, stated plainly" | UDP `send` is EPERM; `io_uring_setup` is EPERM |

## The probes that produced a wrong claim

Kept because a correction without its cause is one the next reader repeats.

**`verify_claims.c` is the direct descendant of the ADDFD mistake.** Its first
version issued four ADDFD calls against ONE notification. The first call succeeded
and consumed the notification, so the remaining three returned ENOENT, and that
output was recorded as "ADDFD is unavailable in this cage". `addfd_clean.c` uses
one notification per attempt and gets 4 of 4. The failing output is still in the
first probe's transcript, which is the point: a probe reporting a resource as
absent because its own earlier call consumed it is a probe bug wearing a
measurement's clothes.

**`multin.c` replaces four earlier `ceiling*.c` probes** that all reported a
one-notification limit. They declared `struct seccomp_notif nf` outside their loop
and called `memset` once, so the kernel's own output made the second RECV's input
non-zero, which is finding §1. Those probes were measuring their own struct reuse.