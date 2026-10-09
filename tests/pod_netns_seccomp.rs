//! End-to-end test for `pod-netns`'s seccomp backend.
//!
//! A SOCKS5 proxy listens on a unix socket (the only bind a sealed host
//! permits). A compiled C program calls `socket(AF_INET)`/`connect(AF_INET)`
//! normally; the filter stops both and the supervisor hands it a socketpair
//! and dials the proxy. No `LD_PRELOAD` is involved, so a **static** build is
//! exercised too — that is the whole point of the backend.
//!
//! If the host does not offer `SECCOMP_RET_USER_NOTIF` the test reports that
//! and passes, as the other shim tests do when no compiler is present.

use std::io::{Read, Write};
use std::os::unix::net::UnixListener;
use std::path::PathBuf;
use std::process::Command;
use std::sync::mpsc;

use cfrs::vnet::shim;

fn have_compiler() -> bool {
    shim::compiler().is_ok()
}

fn build_program(dir: &std::path::Path, name: &str, source: &str, static_link: bool) -> PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = shim::compiler().unwrap();
    let mut cmd = Command::new(cc);
    cmd.arg("-O2");
    if static_link {
        cmd.arg("-static");
    }
    let status = cmd
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

/// A minimal SOCKS5 proxy on a unix socket: no auth, CONNECT only, then a
/// greeting and an echo.
fn socks5_echo(listener: UnixListener, targets: mpsc::Sender<String>) {
    for conn in listener.incoming() {
        let mut c = match conn {
            Ok(c) => c,
            Err(_) => break,
        };
        let _ = (|| -> std::io::Result<()> {
            let mut hdr = [0u8; 2];
            c.read_exact(&mut hdr)?;
            let mut methods = vec![0u8; hdr[1] as usize];
            c.read_exact(&mut methods)?;
            c.write_all(&[5, 0])?;
            let mut req = [0u8; 4];
            c.read_exact(&mut req)?;
            let host = match req[3] {
                1 => {
                    let mut a = [0u8; 4];
                    c.read_exact(&mut a)?;
                    std::net::Ipv4Addr::from(a).to_string()
                }
                3 => {
                    let mut l = [0u8; 1];
                    c.read_exact(&mut l)?;
                    let mut h = vec![0u8; l[0] as usize];
                    c.read_exact(&mut h)?;
                    String::from_utf8_lossy(&h).to_string()
                }
                4 => {
                    let mut a = [0u8; 16];
                    c.read_exact(&mut a)?;
                    std::net::Ipv6Addr::from(a).to_string()
                }
                _ => return Ok(()),
            };
            let mut p = [0u8; 2];
            c.read_exact(&mut p)?;
            let port = u16::from_be_bytes(p);
            let _ = targets.send(format!("{host}:{port}"));
            c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
            c.write_all(b"HELLO-FROM-TARGET\n")?;
            let mut buf = [0u8; 4096];
            loop {
                let n = c.read(&mut buf)?;
                if n == 0 {
                    break;
                }
                c.write_all(&buf[..n])?;
            }
            Ok(())
        })();
    }
}

fn seccomp_available() -> bool {
    let out = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
        .arg("doctor")
        .output()
        .expect("run pod-netns doctor");
    String::from_utf8_lossy(&out.stdout).contains("SECCOMP_RET_USER_NOTIF    ok")
}

const CLIENT: &str = r#"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
int main(void) {
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a; memset(&a, 0, sizeof a);
    a.sin_family = AF_INET; a.sin_port = htons(80);
    inet_pton(AF_INET, "93.184.216.34", &a.sin_addr);
    if (connect(s, (struct sockaddr *)&a, sizeof a) < 0) { perror("connect"); return 1; }
    write(s, "PING\n", 5);
    char b[64] = {0};
    int n = read(s, b, sizeof b - 1);
    printf("READ:%d:%s", n, b);
    return 0;
}
"#;

#[test]
fn seccomp_backend_proxies_a_static_and_a_dynamic_binary() {
    if !have_compiler() {
        eprintln!("no C compiler; skipping");
        return;
    }
    if !seccomp_available() {
        eprintln!("SECCOMP_RET_USER_NOTIF not available; skipping");
        return;
    }

    let dir = std::env::temp_dir().join(format!("pod-netns-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let sock = dir.join("socks.sock");
    let listener = UnixListener::bind(&sock).unwrap();
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || socks5_echo(listener, tx));

    let dynamic = build_program(&dir, "client-dynamic", CLIENT, false);
    let statically = build_program(&dir, "client-static", CLIENT, true);

    for program in [&dynamic, &statically] {
        let output = Command::new(env!("CARGO_BIN_EXE_pod-netns"))
            .args(["--backend", "seccomp", "-x"])
            .arg(format!("unix:{}", sock.display()))
            .arg("--")
            .arg(program)
            .output()
            .expect("run pod-netns");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("READ:18:HELLO-FROM-TARGET"),
            "{} did not reach the proxy: stdout={stdout:?} stderr={:?}",
            program.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // The proxy must have seen the address the client asked for.
    let first = rx.recv().unwrap();
    assert_eq!(first, "93.184.216.34:80");

    let _ = std::fs::remove_dir_all(&dir);
}
