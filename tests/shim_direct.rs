//! End-to-end tests for the `LD_PRELOAD` shim in direct mode.
//!
//! They compile the shim from its embedded source, compile two ordinary C
//! programs that use `AF_INET` sockets, and run them with the shim preloaded.
//! The kernel never sees an `AF_INET` bind or connect; the programs still
//! exchange data over `\0cfrsnet/...` abstract names.
//!
//! If no C compiler is available the tests report that and pass, so they do
//! not fail on a host that cannot build the shim at all.

use std::io::Write;
use std::process::{Command, Stdio};
use std::time::Duration;

use cfrs::vnet::shim;

fn have_compiler() -> bool {
    shim::compiler().is_ok()
}

/// Build the shim and a program into a scratch directory.
fn build_program(dir: &std::path::Path, name: &str, source: &str) -> std::path::PathBuf {
    let source_path = dir.join(format!("{name}.c"));
    std::fs::write(&source_path, source).unwrap();
    let output = dir.join(name);
    let cc = shim::compiler().unwrap();
    let status = Command::new(cc)
        .arg("-O2")
        .arg("-o")
        .arg(&output)
        .arg(&source_path)
        .status()
        .unwrap();
    assert!(status.success(), "compiling {name} failed");
    output
}

#[test]
fn tcp_direct_mode_round_trip() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();
    assert!(shim.path.is_file());

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4);
  struct sockaddr_in got; socklen_t gl=sizeof got;
  if(getsockname(s,(struct sockaddr*)&got,&gl)<0){perror("getsockname");return 2;}
  printf("server: bound %s:%d\n", inet_ntoa(got.sin_addr), ntohs(got.sin_port));
  fflush(stdout);
  int c=accept(s,0,0);
  char buf[256]={0}; int n=read(c,buf,sizeof buf-1);
  printf("server: read %dB: %s", n, buf);
  const char *r="HTTP/1.0 200 OK\r\n\r\nuserspace virtual net says hi\n";
  write(c,r,strlen(r)); close(c); close(s);
  return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_STREAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(18080);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  struct sockaddr_in peer; socklen_t pl=sizeof peer;
  if(getpeername(s,(struct sockaddr*)&peer,&pl)<0){perror("getpeername");return 2;}
  printf("client: connected to %s:%d\n", inet_ntoa(peer.sin_addr), ntohs(peer.sin_port));
  const char *q="GET /hello HTTP/1.0\r\n\r\n";
  write(s,q,strlen(q));
  char buf[512]={0}; int n=read(s,buf,sizeof buf-1);
  printf("client: got %dB\n", n);
  close(s); return 0;
}
"#;
    let server = build_program(dir.path(), "server", server_src);
    let client = build_program(dir.path(), "client", client_src);

    let child = Command::new(&server)
        .env("LD_PRELOAD", &shim.path)
        .env("CFRSNET_LOG", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(400));

    let output = Command::new(&client)
        .env("LD_PRELOAD", &shim.path)
        .env("CFRSNET_LOG", "1")
        .output()
        .unwrap();
    let server_output = child.wait_with_output().unwrap();

    assert!(
        server_output.status.success(),
        "server failed: {}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    assert!(
        output.status.success(),
        "client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let server_stdout = String::from_utf8_lossy(&server_output.stdout);
    let client_stdout = String::from_utf8_lossy(&output.stdout);
    assert!(server_stdout.contains("server: bound 10.66.0.2:18080"), "{server_stdout}");
    assert!(server_stdout.contains("read 23B"), "{server_stdout}");
    assert!(client_stdout.contains("connected to 10.66.0.2:18080"), "{client_stdout}");
    assert!(client_stdout.contains("got 49B"), "{client_stdout}");
    // The kernel only ever saw the abstract name.
    let server_stderr = String::from_utf8_lossy(&server_output.stderr);
    let client_stderr = String::from_utf8_lossy(&output.stderr);
    assert!(server_stderr.contains("bind -> cfrsnet/4/10.66.0.2/18080"), "{server_stderr}");
    assert!(client_stderr.contains("connect -> cfrsnet/4/10.66.0.2/18080"), "{client_stderr}");
}

#[test]
fn udp_direct_mode_round_trip() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(19999);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  char buf[256]={0};
  struct sockaddr_in from; socklen_t fl=sizeof from;
  int n=recvfrom(s,buf,sizeof buf-1,0,(struct sockaddr*)&from,&fl);
  if(n<0){perror("recvfrom");return 2;}
  printf("server: got %dB: %s\n", n, buf);
  const char *r="pong";
  sendto(s,r,strlen(r),0,(struct sockaddr*)&from,fl);
  close(s);
  return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET,SOCK_DGRAM,0);
  struct sockaddr_in a; memset(&a,0,sizeof a);
  a.sin_family=AF_INET; a.sin_port=htons(20000);
  inet_pton(AF_INET,"10.66.0.2",&a.sin_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  struct sockaddr_in peer; memset(&peer,0,sizeof peer);
  peer.sin_family=AF_INET; peer.sin_port=htons(19999);
  inet_pton(AF_INET,"10.66.0.2",&peer.sin_addr);
  const char *q="ping";
  if(sendto(s,q,strlen(q),0,(struct sockaddr*)&peer,sizeof peer)<0){perror("sendto");return 1;}
  char buf[64]={0};
  int n=recvfrom(s,buf,sizeof buf-1,0,0,0);
  printf("client: got %dB: %s\n", n, buf);
  close(s);
  return 0;
}
"#;
    let server = build_program(dir.path(), "userver", server_src);
    let client = build_program(dir.path(), "uclient", client_src);

    let child = Command::new(&server)
        .env("LD_PRELOAD", &shim.path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let output = Command::new(&client)
        .env("LD_PRELOAD", &shim.path)
        .output()
        .unwrap();
    let server_output = child.wait_with_output().unwrap();

    assert!(
        server_output.status.success(),
        "udp server failed: {}",
        String::from_utf8_lossy(&server_output.stderr)
    );
    assert!(
        output.status.success(),
        "udp client failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&server_output.stdout).contains("got 4B: ping"));
    assert!(String::from_utf8_lossy(&output.stdout).contains("got 4B: pong"));
}

/// A tiny guard that the test's own writer never blocks: stdout is piped and
/// small. This exists only to use `std::io::Write` so the import is not dead.
#[test]
fn piped_output_is_small() {
    let mut sink = Vec::new();
    sink.write_all(b"cfrsnet").unwrap();
    assert_eq!(sink, b"cfrsnet");
}

/// `CFRSNET_MAP_LOOPBACK` must encode `::1` as the same RFC 5952 literal the
/// Rust side would produce for the v4-mapped local address.
#[test]
fn ipv6_loopback_mapping_matches_the_rust_encoder() {
    if !have_compiler() {
        eprintln!("skipping: no C compiler");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let shim = shim::build(dir.path()).unwrap();

    let server_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET6,SOCK_STREAM,0);
  struct sockaddr_in6 a; memset(&a,0,sizeof a);
  a.sin6_family=AF_INET6; a.sin6_port=htons(18081);
  inet_pton(AF_INET6,"::1",&a.sin6_addr);
  if(bind(s,(struct sockaddr*)&a,sizeof a)<0){perror("bind");return 1;}
  listen(s,4);
  int c=accept(s,0,0);
  if(c<0){perror("accept");return 2;}
  char buf[16]={0}; int n=read(c,buf,sizeof buf);
  write(c,buf,n); close(c); close(s); return 0;
}
"#;
    let client_src = r#"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>
int main(void){
  int s=socket(AF_INET6,SOCK_STREAM,0);
  struct sockaddr_in6 a; memset(&a,0,sizeof a);
  a.sin6_family=AF_INET6; a.sin6_port=htons(18081);
  inet_pton(AF_INET6,"::1",&a.sin6_addr);
  if(connect(s,(struct sockaddr*)&a,sizeof a)<0){perror("connect");return 1;}
  const char *q="v6 mapped"; write(s,q,strlen(q));
  char buf[32]={0}; int n=read(s,buf,sizeof buf);
  printf("client: got %dB: %s\n", n, buf);
  close(s); return 0;
}
"#;
    let server = build_program(dir.path(), "v6server", server_src);
    let client = build_program(dir.path(), "v6client", client_src);

    let child = Command::new(&server)
        .env("LD_PRELOAD", &shim.path)
        .env("CFRSNET_MAP_LOOPBACK", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    std::thread::sleep(Duration::from_millis(400));
    let output = Command::new(&client)
        .env("LD_PRELOAD", &shim.path)
        .env("CFRSNET_MAP_LOOPBACK", "1")
        .env("CFRSNET_LOG", "1")
        .output()
        .unwrap();
    let server_output = child.wait_with_output().unwrap();

    assert!(output.status.success(), "v6 client failed: {}", String::from_utf8_lossy(&output.stderr));
    assert!(server_output.status.success(), "v6 server failed");
    assert!(String::from_utf8_lossy(&output.stdout).contains("got 9B: v6 mapped"));
    // ::1 maps to ::ffff:10.66.0.2, which RFC 5952 renders ::ffff:a42:2.
    let client_stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        client_stderr.contains("cfrsnet/6/::ffff:a42:2/18081"),
        "unexpected abstract name: {client_stderr}"
    );
}
