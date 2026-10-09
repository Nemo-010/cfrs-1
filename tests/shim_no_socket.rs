//! The shim must not break programs that never open a socket.
//!
//! `tests/shim_direct.rs` proves the virtual network works. It only ever runs
//! programs whose *first* action is `socket(2)`. These tests cover the other
//! population: ordinary programs that close a descriptor, duplicate one, or ask
//! for a socket name, before they ever open a socket.
//!
//! Every test here was written against a failure that was reproduced first.
//! The reference implementation of this shim had three defects that a
//! socket-first test cannot see, all in the same shape: state read or written
//! before the lazy resolver had run.
//!
//! | test | the defect it pins | how it failed |
//! | --- | --- | --- |
//! | [`closing_a_descriptor_before_any_socket_does_not_crash`] | `close` did not call `ensure_init`, so `r_close` was still NULL | `SIGSEGV` (exit 139) |
//! | [`getsockname_does_not_write_past_the_callers_buffer`] | `getsockname` zeroed a whole `sockaddr_storage` (128 bytes) into the caller's buffer | `stack smashing detected`, exit 134 |
//! | [`getsockname_supports_the_length_query_idiom`] | `getsockname(NULL, &len)` dereferenced the null pointer | `SIGSEGV` (exit 139) |
//! | [`a_short_buffer_truncates_instead_of_failing`] | a short buffer returned `EINVAL` where Linux truncates and reports the true length | `rc=-1` where the kernel returns `rc=0` |
//! | [`dup_before_socket_keeps_virtual_status`] | `dup*` read `cfg.max_fds` before the config was parsed | virtual status silently lost |
//!
//! Each test asserts on the exit status of a real process, so a regression is a
//! crash the test sees rather than a stack corruption that only shows up later.
//!
//! # Running these
//!
//! These compile and run C, so they report and return when there is no C
//! compiler, matching `shim_direct.rs`.

mod afinet_audit;

use std::process::{Command, Stdio};

use cfrs::vnet::shim;

/// Compile `source` and run it under `shim`, returning (exit status, stdout).
///
/// `LD_PRELOAD` is only set when `preload` is `Some`, so the same helper runs
/// the unshimmed control case with nothing else changed.
fn run(source: &str, preload: Option<&std::path::Path>) -> Option<(Option<i32>, String)> {
    let cc = shim::compiler().ok()?;
    let dir = tempfile::tempdir().ok()?;
    let path = dir.path().join("prog");
    let src_path = dir.path().join("prog.c");
    std::fs::write(&src_path, source).ok()?;
    let status = Command::new(&cc)
        .arg("-O2")
        .arg("-o")
        .arg(&path)
        .arg(&src_path)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    if !status.success() {
        return None;
    }
    let mut command = Command::new(&path);
    if let Some(shim) = preload {
        command.env("LD_PRELOAD", shim);
    }
    let out = command.output().ok()?;
    Some((
        out.status.code(),
        format!(
            "stdout={:?} stderr={:?}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    ))
}

/// Build the shim once per test, or skip.
///
/// The returned [`ShimGuard`] owns the directory. This matters: an earlier
/// version returned a bare path from a `tempfile::TempDir` that was dropped at
/// the end of the helper, so the `.so` was unlinked before the child process
/// ran and `LD_PRELOAD` silently failed to load. The loader prints a warning to
/// stderr and continues, so the child ran unshimmed and the test failed on the
/// kernel's `EACCES` rather than on the shim. Holding the directory for the
/// lifetime of the child is what makes the preload real.
struct ShimGuard {
    _dir: tempfile::TempDir,
    path: std::path::PathBuf,
}

fn shim_or_skip(test: &str) -> Option<ShimGuard> {
    if shim::compiler().is_err() {
        eprintln!("{test}: skipping, no C compiler");
        return None;
    }
    let dir = match tempfile::tempdir() {
        Ok(dir) => dir,
        Err(_) => {
            eprintln!("{test}: skipping, no writable scratch directory");
            return None;
        }
    };
    match shim::build(dir.path()) {
        Ok(built) => Some(ShimGuard { _dir: dir, path: built.path }),
        Err(e) => {
            eprintln!("{test}: skipping, the shim did not build: {e}");
            None
        }
    }
}

#[test]
fn closing_a_descriptor_before_any_socket_does_not_crash() {
    let test = "closing_a_descriptor_before_any_socket_does_not_crash";
    let Some(guard) = shim_or_skip(test) else {
        return;
    };
    let shim_path = &guard.path;
    let source = r#"
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
int main(void) {
    /* The ordinary order for a program that writes a file: open, close, and
       only then open a socket. */
    int f = open("/dev/null", O_RDONLY);
    if (f < 0) { perror("open"); return 2; }
    if (close(f) != 0) { perror("close"); return 3; }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    printf("fd=%d socket=%d\n", f, s);
    return 0;
}
"#;

    // The control: without the shim this must succeed. If it does not, the
    // host is unusual enough that the shimmed result proves nothing.
    let Some((Some(0), _)) = run(source, None) else {
        eprintln!("{test}: skipping, the unshimmed program did not exit 0");
        return;
    };

    let (code, out) = run(source, Some(shim_path)).expect("run under the shim");
    assert_eq!(
        code,
        Some(0),
        "{test}: the program must survive close(2) before socket(2); it exited {code:?} \
         (139 is SIGSEGV, 134 is abort) and printed {out:?}"
    );
    assert!(out.contains("socket="), "the program should have reached its socket call: {out:?}");
}

#[test]
fn getsockname_does_not_write_past_the_callers_buffer() {
    let test = "getsockname_does_not_write_past_the_callers_buffer";
    let Some(guard) = shim_or_skip(test) else {
        return;
    };
    let shim_path = &guard.path;
    // A 16-byte sockaddr_in followed by a canary. Any write past the 16 bytes
    // the caller declared is caught by the stack protector, and by the canary
    // if the compiler did not instrument it.
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
int main(void) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_port = htons(9);
    inet_pton(AF_INET, "10.66.0.2", &dst.sin_addr);
    /* An unbound datagram socket: the kernel auto-binds it on the first send,
       so getsockname has something to report without the program ever binding. */
    sendto(s, "x", 1, 0, (struct sockaddr *)&dst, sizeof dst);

    struct { struct sockaddr_in a; unsigned long canary; } probe;
    probe.canary = 0xA5A5A5A5A5A5A5A5UL;
    memset(&probe.a, 0, sizeof probe.a);
    socklen_t len = sizeof probe.a;
    getsockname(s, (struct sockaddr *)&probe.a, &len);
    printf("canary=%016lx\n", probe.canary);
    return probe.canary == 0xA5A5A5A5A5A5A5A5UL ? 0 : 1;
}
"#;
    let (code, out) = run(source, Some(shim_path)).expect("run under the shim");
    assert_eq!(
        code,
        Some(0),
        "{test}: getsockname wrote past the {}-byte buffer the caller declared \
         (exit {code:?}, out {out:?}); 134 is a stack-protector abort",
        std::mem::size_of::<libc::sockaddr_in>()
    );
}

#[test]
fn getsockname_supports_the_length_query_idiom() {
    let test = "getsockname_supports_the_length_query_idiom";
    let Some(guard) = shim_or_skip(test) else {
        return;
    };
    let shim_path = &guard.path;
    // POSIX permits getsockname(fd, NULL, &len) purely to ask the length, and
    // Linux answers rc=0 with the address's true length. A program sizing its
    // buffer this way must get the same answer from the shim.
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(int argc, char **argv) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(argc > 1 ? atoi(argv[1]) : 18181);
    inet_pton(AF_INET, "10.66.0.2", &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 2; }
    socklen_t len = 0;
    int rc = getsockname(s, NULL, &len);
    printf("rc=%d len=%u\n", rc, len);
    return rc == 0 ? 0 : 1;
}
"#;
    let (code, out) = run(source, Some(shim_path)).expect("run under the shim");
    assert_eq!(
        code,
        Some(0),
        "{test}: getsockname(fd, NULL, &len) must succeed and report the length, \
         got exit {code:?} out {out:?} (139 is SIGSEGV)"
    );
    assert!(
        out.contains("len=16"),
        "{test}: the reported length should be sizeof(struct sockaddr_in), got {out:?}"
    );
}

#[test]
fn a_short_buffer_truncates_instead_of_failing() {
    let test = "a_short_buffer_truncates_instead_of_failing";
    let Some(guard) = shim_or_skip(test) else {
        return;
    };
    let shim_path = &guard.path;
    // Linux copies min(*len, addr_len) and reports the address's true length in
    // *len, returning success. Returning EINVAL for a short buffer breaks every
    // caller that asks for a length by passing a small buffer.
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(18182);
    inet_pton(AF_INET, "10.66.0.2", &a.sin_addr);
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind"); return 2; }
    char small[8];
    socklen_t len = sizeof small;
    int rc = getsockname(s, (struct sockaddr *)small, &len);
    printf("rc=%d len=%u\n", rc, len);
    return rc == 0 ? 0 : 1;
}
"#;
    let (code, out) = run(source, Some(shim_path)).expect("run under the shim");
    assert_eq!(
        code,
        Some(0),
        "{test}: a short buffer must truncate and succeed, got exit {code:?} out {out:?}"
    );
    assert!(
        out.contains("len=16"),
        "{test}: the true address length must still be reported, got {out:?}"
    );
}

#[test]
fn dup_before_socket_keeps_virtual_status() {
    let test = "dup_before_socket_keeps_virtual_status";
    let Some(guard) = shim_or_skip(test) else {
        return;
    };
    let shim_path = &guard.path;
    // dup(2) copies the virtual status of the descriptor. If the shim reads its
    // fd-table capacity before the configuration has been parsed, the copy is
    // silently not tracked, and the bind below then reaches the kernel as
    // AF_INET and fails on a sealed host.
    let source = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
int main(void) {
    /* Close something first, so the fd table is exercised before any socket. */
    int f = open("/dev/null", O_RDONLY);
    if (f >= 0) close(f);
    int s = socket(AF_INET, SOCK_STREAM, 0);
    int d = dup(s);
    if (d < 0) { perror("dup"); return 2; }
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons(18183);
    inet_pton(AF_INET, "10.66.0.2", &a.sin_addr);
    if (bind(d, (struct sockaddr *)&a, sizeof a) < 0) { perror("bind on the dup"); return 1; }
    printf("dup bound ok\n");
    return 0;
}
"#;
    let source = format!("#include <fcntl.h>\n{source}");
    let (code, out) = run(&source, Some(shim_path)).expect("run under the shim");
    assert_eq!(
        code,
        Some(0),
        "{test}: a bind on a dup(2)'d socket must still be interposed, got exit \
         {code:?} out {out:?}; EACCES means the copy lost its virtual status"
    );
}

/// The kernel-side claim, kept next to the shim-side ones: the reason any of
/// the above is a meaningful test is that a real bind would fail here.
#[test]
fn the_control_bind_would_fail_without_the_shim() {
    let test = "the_control_bind_would_fail_without_the_shim";
    if shim::compiler().is_err() {
        eprintln!("{test}: skipping, no C compiler");
        return;
    }
    let cc = shim::compiler().expect("compiler");
    match afinet_audit::raw_bind_errno(&cc) {
        Ok(0) => eprintln!("{test}: skipping, this host allows bind(AF_INET)"),
        Ok(errno) => assert_eq!(errno, afinet_audit::EACCES),
        Err(afinet_audit::HelperError::NoCompiler) => {
            eprintln!("{test}: skipping, no C compiler")
        }
        Err(e) => panic!("{test}: {e}"),
    }
}