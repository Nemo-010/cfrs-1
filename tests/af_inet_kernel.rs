//! Independent evidence that the shim keeps `AF_INET` away from the kernel.
//!
//! `tests/shim_direct.rs` proves two programs exchange data over the virtual
//! network. It trusts the shim's own `CFRSNET_LOG` output for the claim that no
//! `AF_INET` syscall was issued. These tests measure that claim from below the
//! shim instead, and each one names what would falsify it.
//!
//! # Why the socket inode, and not `getsockname`
//!
//! The obvious instrument is `getsockname` on the bound fd, and it cannot be
//! used. The shim **interposes `getsockname`** and answers with the logical
//! address it recorded, so a probe built that way measures the shim's own
//! bookkeeping rather than the kernel, and passes by construction whatever the
//! kernel did. That was tried first here, and it answered `inet`, which is the
//! shim's record rather than the kernel's truth.
//!
//! The instrument is the socket inode instead. `/proc/self/fd/N` is a symlink to
//! `socket:[INODE]`, and the kernel lists each socket in its own protocol table:
//! field 7 of `/proc/net/unix` for `AF_UNIX`, field 10 of `/proc/net/tcp` for
//! `AF_INET`. The shim interposes neither `readlink` nor file reads, so which
//! table an inode turns up in is the kernel's own statement about that socket.
//!
//! # The chain of evidence, and what would break it
//!
//! 1. [`the_kernel_refuses_a_real_af_inet_bind`] is the control: a
//!    **shim-free** `bind(AF_INET, 127.0.0.1:0)` must return `EACCES`. If it
//!    does not, the host is not sealed, the shim's rewrite cannot be
//!    distinguished from a real bind, and every test here skips with a reason
//!    rather than asserting a conclusion it cannot support.
//! 2. [`a_bind_that_succeeds_under_the_shim_left_an_af_unix_fd`] runs the same
//!    program with the shim preloaded. The bind now succeeds and the kernel
//!    files the socket in `/proc/net/unix`. A bind that succeeded on a socket
//!    the kernel calls `AF_UNIX` cannot have been an `AF_INET` bind.
//! 3. [`the_socket_never_appears_in_the_kernel_tcp_table`] states the negative
//!    half on its own, so a change that puts the inode in both tables fails
//!    loudly instead of passing on the `unix` half alone.
//! 4. [`without_the_shim_the_same_bind_fails`] is the pairing that gives step 2
//!    its meaning: the same probe, the only difference being `LD_PRELOAD`.
//!
//! # On skipping
//!
//! A host with no C compiler cannot build the shim, so these tests skip with a
//! printed reason. A *compile failure of our own helper source* is not a
//! property of the host and is reported as a failure instead: a broken
//! instrument must never produce a green run. That distinction is what
//! `HelperError` exists for.
//!
//! Both properties were checked by sabotage rather than asserted. Pointing the
//! probe at a table that does not exist turns a passing run into four
//! failures, which is the check that first caught an earlier version of this
//! file quietly skipping on its own breakage.

mod afinet_audit;

use afinet_audit::HelperError;
use cfrs::vnet::shim;

/// The compiler, or skip with a printed reason.
fn compiler_or_skip(test: &str) -> Option<String> {
    match shim::compiler() {
        Ok(cc) => Some(cc),
        Err(_) => {
            eprintln!("{test}: skipping, no C compiler");
            None
        }
    }
}

/// The sealed-host errno for a refused `AF_INET` bind, or skip when the host is
/// not sealed (in which case the rest of this file proves nothing).
fn sealed_or_skip(test: &str, cc: &str) -> Option<i32> {
    match afinet_audit::raw_bind_errno(cc) {
        Ok(0) => {
            eprintln!(
                "{test}: skipping, this host allows bind(AF_INET), so the shim's \
                 rewrite cannot be told apart from a real bind"
            );
            None
        }
        Ok(errno) => Some(errno),
        Err(HelperError::NoCompiler) => {
            eprintln!("{test}: skipping, no C compiler");
            None
        }
        Err(e) => panic!("{test}: the measurement helper failed: {e}"),
    }
}

#[test]
fn the_kernel_refuses_a_real_af_inet_bind() {
    let Some(cc) = compiler_or_skip("the_kernel_refuses_a_real_af_inet_bind") else {
        return;
    };
    let Some(errno) = sealed_or_skip("the_kernel_refuses_a_real_af_inet_bind", &cc) else {
        return;
    };
    assert_eq!(
        errno,
        afinet_audit::EACCES,
        "expected the kernel to refuse bind(AF_INET, 127.0.0.1:0) with EACCES, got {errno}"
    );
}

#[test]
fn a_bind_that_succeeds_under_the_shim_left_an_af_unix_fd() {
    let test = "a_bind_that_succeeds_under_the_shim_left_an_af_unix_fd";
    let Some(cc) = compiler_or_skip(test) else {
        return;
    };
    if sealed_or_skip(test, &cc).is_none() {
        return;
    }

    let dir = tempfile::tempdir().expect("scratch dir");
    let shim = shim::build(dir.path()).expect("build the shim");

    let seen = afinet_audit::bind_then_locate_inode(&cc, &shim.path, "10.66.0.2", 18091)
        .unwrap_or_else(|e| panic!("{test}: {e}"));
    assert_eq!(
        seen, "unix",
        "a program that bound AF_INET 10.66.0.2:18091 successfully should have been \
         given an AF_UNIX fd; the kernel lists its socket inode as {seen:?}"
    );
}

#[test]
fn the_socket_never_appears_in_the_kernel_tcp_table() {
    let test = "the_socket_never_appears_in_the_kernel_tcp_table";
    let Some(cc) = compiler_or_skip(test) else {
        return;
    };
    if sealed_or_skip(test, &cc).is_none() {
        return;
    }

    let dir = tempfile::tempdir().expect("scratch dir");
    let shim = shim::build(dir.path()).expect("build the shim");

    let seen = afinet_audit::bind_then_locate_inode(&cc, &shim.path, "10.66.0.2", 18092)
        .unwrap_or_else(|e| panic!("{test}: {e}"));
    assert_ne!(
        seen, "inet",
        "the kernel filed the fd under /proc/net/tcp, so an AF_INET bind reached it"
    );
}

#[test]
fn without_the_shim_the_same_bind_fails() {
    let test = "without_the_shim_the_same_bind_fails";
    let Some(cc) = compiler_or_skip(test) else {
        return;
    };
    if sealed_or_skip(test, &cc).is_none() {
        return;
    }

    // A path that names no shim. LD_PRELOAD pointing at a missing file is
    // ignored by the loader, so this run has no interposition at all, which is
    // the control for the test above.
    let seen = afinet_audit::bind_then_locate_inode(
        &cc,
        std::path::Path::new("/nonexistent/libcfrsnet.so"),
        "10.66.0.2",
        18093,
    )
    .unwrap_or_else(|e| panic!("{test}: {e}"));
    assert_eq!(
        seen, "bind-failed",
        "with no shim loaded the bind must reach the kernel and fail; the probe said {seen:?}"
    );
}