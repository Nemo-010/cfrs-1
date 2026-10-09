//! C helpers shared by the `LD_PRELOAD` shim's integration tests.
//!
//! The document's §9.3 asks for an independent confirmation that no `AF_INET`
//! syscall reaches the kernel, rather than trusting the shim's own log. The
//! instrument these helpers use is the **socket inode**: `/proc/self/fd/N` is a
//! symlink to `socket:[INODE]`, and the kernel lists each socket under its own
//! protocol table, `/proc/net/unix` for `AF_UNIX` and `/proc/net/tcp` for
//! `AF_INET`. The shim interposes neither `readlink` nor file reads, so the
//! table a socket turns up in is the kernel's own statement about it.
//!
//! `getsockname` would be the obvious alternative and it cannot be used here:
//! the shim interposes it and answers with the logical address it recorded, so
//! a probe built on it measures the shim's bookkeeping rather than the kernel.
//!
//! These are integration helpers: they compile C and run it. Everything returns
//! `None` rather than failing when a compiler is missing or a program cannot
//! run, so the suite stays green on a host that cannot build the shim.

// These helpers are compiled into more than one test binary: `raw_bind_errno`
// and `EACCES` are used by both `af_inet_kernel.rs` and `shim_no_socket.rs`,
// while `bind_then_locate_inode` and `INODE_PROGRAM` belong to
// `af_inet_kernel.rs` alone. A binary that does not use the second pair sees
// them as dead, which is an artefact of sharing a module rather than of unused
// code, so the lint is silenced here with the reason rather than by deleting
// something another test needs.
#![allow(dead_code)]

use std::process::Command;

/// `EACCES`, the errno a sealed host returns for a refused `AF_INET` bind.
pub const EACCES: i32 = 13;

/// C helpers, without the leading `extern "C"`, that a test prepends to a
/// program before compiling it.
pub const HELPERS: &str = r#"
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

/* The errno bind(AF_INET, 127.0.0.1:0) returns, or 0 when it succeeds.
   Run without the shim preloaded: that is the kernel's own answer. */
static int raw_bind_errno(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return errno;
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = 0;
    a.sin_addr.s_addr = htonl(0x7f000001u); /* 127.0.0.1 */
    errno = 0;
    int r = bind(s, (struct sockaddr *)&a, sizeof a);
    int saved = (r == 0) ? 0 : errno;
    close(s);
    return saved;
}

/* Bind AF_INET <addr>:<port>, then report which kernel table holds the fd's
   socket inode: "unix", "inet", "unknown", or "bind-failed".

   The inode is read from /proc/self/fd/N, which is the kernel's symlink for
   that descriptor, and is then looked up in /proc/net/unix and /proc/net/tcp.
   Neither read is interposed, so the answer describes the kernel's view and not
   anything the shim recorded. */
static const char *bind_then_locate_inode(const char *addr, int port) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    if (s < 0) return "socket-failed";
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, addr, &a.sin_addr) != 1) { close(s); return "bad-address"; }
    if (bind(s, (struct sockaddr *)&a, sizeof a) < 0) { close(s); return "bind-failed"; }

    char link[64];
    snprintf(link, sizeof link, "/proc/self/fd/%d", s);
    char target[128];
    ssize_t n = readlink(link, target, sizeof target - 1);
    if (n < 0) { close(s); return "readlink-failed"; }
    target[n] = '\0';

    /* "socket:[12345]" -> "12345" */
    const char *open = strchr(target, '[');
    const char *shut = strchr(target, ']');
    if (!open || !shut || shut <= open + 1) { close(s); return "unreadable-inode"; }
    char inode[64];
    size_t len = (size_t)(shut - open - 1);
    if (len >= sizeof inode) { close(s); return "unreadable-inode"; }
    memcpy(inode, open + 1, len);
    inode[len] = '\0';

    /* The inode is the 7th field of /proc/net/unix ("Num RefCount Protocol
       Flags Type St Inode Path") and the 10th of /proc/net/tcp ("sl
       local_address rem_address st tx_queue:rx_queue tr tm->when retrnsmt
       uid timeout inode"). Neither is the last field when the socket is named,
       so the fields are counted rather than guessed from the line's end. */
    const char *verdict = "unknown";
    const char *tables[2];
    tables[0] = "/proc/net/unix";
    tables[1] = "/proc/net/tcp";
    const char *names[2];
    names[0] = "unix";
    names[1] = "inet";
    /* 1-based field index of the inode in each table. */
    const int inode_field[2] = { 7, 10 }; /* /proc/net/unix, /proc/net/tcp */

    for (int t = 0; t < 2 && strcmp(verdict, "unknown") == 0; t++) {
        FILE *f = fopen(tables[t], "r");
        if (!f) continue;
        char line[1024];
        if (!fgets(line, sizeof line, f)) { fclose(f); continue; } /* header */
        while (fgets(line, sizeof line, f)) {
            int field = 1;
            char *cursor = line;
            while (*cursor && field < inode_field[t]) {
                while (*cursor == ' ' || *cursor == '\t') cursor++;
                while (*cursor && *cursor != ' ' && *cursor != '\t') cursor++;
                field++;
            }
            while (*cursor == ' ' || *cursor == '\t') cursor++;
            char *stop = cursor;
            while (*stop && *stop != ' ' && *stop != '\t' && *stop != '\n') stop++;
            *stop = '\0';
            if (strcmp(cursor, inode) == 0) { verdict = names[t]; break; }
        }
        fclose(f);
    }
    close(s);
    return verdict;
}
"#;

/// A test program that prints `raw_bind_errno()` and exits.
pub const RAW_BIND_PROGRAM: &str = r#"
int main(void) { printf("%d\n", raw_bind_errno()); return 0; }
"#;

/// A test program that binds `AF_INET <argv[1]>:<argv[2]>` and prints which
/// kernel table holds the resulting socket's inode.
pub const INODE_PROGRAM: &str = r#"
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    printf("%s\n", bind_then_locate_inode(argv[1], atoi(argv[2])));
    return 0;
}
"#;

/// Why a helper program could not be produced or run.
#[derive(Debug, PartialEq, Eq)]
pub enum HelperError {
    /// No C compiler on this host. The caller skips: the shim cannot be built
    /// here at all, so there is nothing to claim.
    NoCompiler,
    /// A compiler ran but rejected our own source. That is a defect in this
    /// file, not a property of the host, and it must never be a green run.
    CompileFailed(String),
    /// The helper built but could not be executed.
    RunFailed(String),
}

impl std::fmt::Display for HelperError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCompiler => write!(f, "no C compiler"),
            Self::CompileFailed(m) => write!(f, "helper source did not compile: {m}"),
            Self::RunFailed(m) => write!(f, "helper could not run: {m}"),
        }
    }
}

impl std::error::Error for HelperError {}

/// Compile `source` (with [`HELPERS`] prepended) into `dir/name`.
///
/// A missing compiler is [`HelperError::NoCompiler`] so the caller can skip;
/// a compile failure of our own source is [`HelperError::CompileFailed`] so it
/// surfaces as a failure.
pub fn build_helper_program(
    dir: &std::path::Path,
    name: &str,
    source: &str,
    compiler: &str,
) -> Result<std::path::PathBuf, HelperError> {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, format!("{HELPERS}\n{source}"))
        .map_err(|e| HelperError::CompileFailed(format!("writing {name}.c: {e}")))?;
    let output = dir.join(name);
    let run = Command::new(compiler)
        .arg("-O2")
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .output()
        .map_err(|_| HelperError::NoCompiler)?;
    if !run.status.success() {
        return Err(HelperError::CompileFailed(format!(
            "compiling {name}.c failed: {}",
            String::from_utf8_lossy(&run.stderr).trim()
        )));
    }
    Ok(output)
}

/// The errno a **shim-free** `bind(AF_INET, 127.0.0.1:0)` returns on this host.
pub fn raw_bind_errno(compiler: &str) -> Result<i32, HelperError> {
    let dir = tempfile::tempdir().map_err(|e| HelperError::RunFailed(e.to_string()))?;
    let program = build_helper_program(dir.path(), "rawbind", RAW_BIND_PROGRAM, compiler)?;
    let out = Command::new(&program)
        .output()
        .map_err(|e| HelperError::RunFailed(e.to_string()))?;
    String::from_utf8_lossy(&out.stdout)
        .trim()
        .parse()
        .map_err(|_| HelperError::RunFailed(format!("rawbind printed {:?}", out.stdout)))
}

/// Which kernel table holds the socket inode for a program that bound
/// `AF_INET addr:port`, with `shim` preloaded. Returns one of `unix`, `inet`,
/// `unknown`, or a failure line.
pub fn bind_then_locate_inode(
    compiler: &str,
    shim: &std::path::Path,
    addr: &str,
    port: u16,
) -> Result<String, HelperError> {
    let dir = tempfile::tempdir().map_err(|e| HelperError::RunFailed(e.to_string()))?;
    let program = build_helper_program(dir.path(), "inode", INODE_PROGRAM, compiler)?;
    let out = Command::new(&program)
        .env("LD_PRELOAD", shim)
        .args([addr, &port.to_string()])
        .output()
        .map_err(|e| HelperError::RunFailed(e.to_string()))?;
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}