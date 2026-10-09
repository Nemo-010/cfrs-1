//! A test origin that serves over a unix domain socket.
//!
//! This is not part of the cfrs library. It is a deliberately trivial HTTP
//! origin used to prove that `cfrs serve` really splices a visitor's SSH
//! channel to a unix-socket origin and carries bytes both ways. Every response
//! carries a fresh marker so a proof can distinguish a real traversal from a
//! cached or echoed body.
//!
//! Run: `cf-origin --socket /tmp/app.sock`
//! Then: `curl --unix-socket /tmp/app.sock http://localhost/`

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixListener;

fn main() {
    // Accept either `--socket PATH` or a bare `PATH`, so a quick manual run
    // does not silently create a socket literally named "--socket".
    let args: Vec<String> = std::env::args().skip(1).collect();
    let socket_path = match args.as_slice() {
        [flag, path] if flag == "--socket" => path.clone(),
        [path] if !path.starts_with("--") => path.clone(),
        [flag, ..] if flag == "--socket" => {
            eprintln!("cf-origin: --socket needs a path");
            std::process::exit(2);
        }
        _ => "/tmp/cfrs-origin.sock".to_string(),
    };

    // A leftover socket from a previous run would make bind fail with
    // "Address already in use"; a live one is not ours to remove.
    if std::path::Path::new(&socket_path).exists() {
        if let Ok(s) = UnixListener::bind(&socket_path) {
            drop(s);
        }
        std::fs::remove_file(&socket_path).expect("remove stale socket");
    }

    let listener = UnixListener::bind(&socket_path).expect("bind origin socket");
    eprintln!("cf-origin listening on {socket_path}");

    let mut counter: u64 = 0;
    for stream in listener.incoming() {
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cf-origin accept error: {e}");
                continue;
            }
        };
        counter += 1;
        let id = counter;

        let mut reader = BufReader::new(&stream);
        let mut request_line = String::new();
        if reader.read_line(&mut request_line).is_err() {
            continue;
        }
        // Drain headers so the client sees a clean exchange.
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(_) if line.trim().is_empty() => break,
                Ok(_) => {}
                Err(_) => break,
            }
        }

        let path = request_line.split_whitespace().nth(1).unwrap_or("/");
        let body = format!(
            "cf-origin OK\nmarker={id}\npath={path}\nagent=cf-origin-unix-socket\n"
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(response.as_bytes());
        let _ = stream.flush();
    }
}