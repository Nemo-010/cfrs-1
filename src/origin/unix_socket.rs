//! Unix-domain-socket origins.
//!
//! Split out from `tcp.rs` so the reason this origin exists stays legible: in
//! a sandbox where `bind()` on TCP returns `EACCES` and `connect()` to
//! loopback returns `EPERM`, a unix socket is the only kind of origin that can
//! both be created and reached.

use std::path::PathBuf;
use std::time::Duration;

pub use super::tcp::UnixOrigin;

/// Convenience: connect to a unix socket origin by path.
pub async fn connect(path: &std::path::Path, timeout: Duration) -> Result<(), String> {
    UnixOrigin::new(path.to_path_buf())
        .connect(timeout)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Whether a path looks like a usable unix socket right now.
pub fn is_live(path: &std::path::Path) -> bool {
    path.exists() && std::fs::metadata(path).map(|m| {
        use std::os::unix::fs::FileTypeExt;
        m.file_type().is_socket()
    }).unwrap_or(false)
}

/// The `PathBuf` a service string should produce for `unix:`.
pub fn path_from_service(rest: &str) -> Result<PathBuf, String> {
    if rest.is_empty() {
        return Err("unix: needs a socket path".to_string());
    }
    Ok(PathBuf::from(rest))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_paths_must_be_present() {
        assert!(path_from_service("").is_err());
        assert_eq!(
            path_from_service("/tmp/x.sock").unwrap(),
            PathBuf::from("/tmp/x.sock")
        );
    }

    #[tokio::test]
    async fn a_regular_file_is_not_a_socket() {
        let p = std::env::temp_dir().join(format!("cfrs-notasocket-{}", std::process::id()));
        std::fs::write(&p, b"x").expect("write");
        assert!(!is_live(&p), "a regular file must not pass is_live");
        let _ = std::fs::remove_file(&p);
    }

    #[test]
    fn a_bound_socket_is_live() {
        let p = std::env::temp_dir().join(format!("cfrs-issocket-{}", std::process::id()));
        let _ = std::fs::remove_file(&p);
        let l = std::os::unix::net::UnixListener::bind(&p).expect("bind");
        assert!(is_live(&p), "a bound unix socket must pass is_live");
        drop(l);
        let _ = std::fs::remove_file(&p);
    }
}