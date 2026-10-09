//! cfrs command line interface.

use std::process::ExitCode;

use cfrs::quicktunnel::{self, AuthMode};
use cfrs::relay::{self, RelayConfig};

const USAGE: &str = "\
cfrs - Cloudflare quick-tunnel client in Rust, for constrained sandboxes

USAGE:
    cfrs provision [OPTIONS]        Request an anonymous quick tunnel
    cfrs serve --unix-socket PATH   Expose a unix-socket origin on the public web
    cfrs doctor                    Report what this machine can reach

GLOBAL OPTIONS:
    -h, --help        Show this help
    -V, --version     Show the version

provision OPTIONS:
        --otp                       Require a one-time PIN from visitors
        --quick-service URL         Provisioning endpoint
                                   [default: https://api.trycloudflare.com]
        --proxy HOST:PORT           HTTP CONNECT proxy (default: $HTTPS_PROXY if set)
        --timeout SECONDS           Request timeout [default: 15]

serve OPTIONS:
        --unix-socket PATH          Origin unix socket [default: /tmp/cfrs-origin.sock]
        --relay HOST:PORT           SSH relay [default: free.pinggy.io:443]
        --proxy HOST:PORT           HTTP CONNECT proxy (default: $HTTPS_PROXY if set)
        --user NAME                 SSH user [default: cfrs]

EXAMPLES:
    cfrs provision
    cfrs serve --unix-socket /tmp/app.sock
    cfrs serve --unix-socket /tmp/app.sock --proxy 169.254.169.1:44561
";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    match args.first().map(String::as_str) {
        None | Some("-h") | Some("--help") | Some("help") => {
            print!("{USAGE}");
            ExitCode::SUCCESS
        }
        Some("-V") | Some("--version") | Some("version") => {
            println!("cfrs {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("provision") => match cmd_provision(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cfrs: {e}");
                ExitCode::FAILURE
            }
        },
        Some("serve") => match cmd_serve(&args[1..]) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("cfrs: {e}");
                ExitCode::FAILURE
            }
        },
        Some("doctor") => match cmd_doctor(&args[1..]) {
            Ok(code) => code,
            Err(e) => {
                eprintln!("cfrs: {e}");
                ExitCode::FAILURE
            }
        },
        Some(other) => {
            eprintln!("cfrs: unknown command {other:?}\n");
            eprint!("{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Minimal flag parser: every flag is `--name value`, `--name=value`, or a
/// bare `--name` when the next token is itself a flag.
struct Flags {
    values: Vec<(String, Option<String>)>,
}

impl Flags {
    fn parse(args: &[String]) -> Result<Flags, String> {
        let mut values = Vec::new();
        let mut i = 0;
        while i < args.len() {
            let arg = &args[i];
            let Some(name) = arg.strip_prefix("--") else {
                return Err(format!("unexpected argument {arg:?}"));
            };
            if let Some((name, inline)) = name.split_once('=') {
                values.push((name.to_string(), Some(inline.to_string())));
                i += 1;
                continue;
            }
            match args.get(i + 1) {
                Some(v) if !v.starts_with("--") => {
                    values.push((name.to_string(), Some(v.clone())));
                    i += 2;
                }
                _ => {
                    values.push((name.to_string(), None));
                    i += 1;
                }
            }
        }
        Ok(Flags { values })
    }

    fn present(&self, name: &str) -> bool {
        self.values.iter().any(|(n, _)| n == name)
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|(n, _)| n == name)
            .and_then(|(_, v)| v.as_deref())
    }

    /// Reject any flag this command does not define, so a typo fails loudly
    /// instead of silently doing nothing.
    fn reject_unknown(&self, allowed: &[&str]) -> Result<(), String> {
        for (name, _) in &self.values {
            if !allowed.contains(&name.as_str()) {
                let mut sorted = allowed.to_vec();
                sorted.sort_unstable();
                return Err(format!(
                    "unknown option --{name}; this command accepts: {}",
                    sorted
                        .iter()
                        .map(|s| format!("--{s}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                ));
            }
        }
        Ok(())
    }
}

fn cmd_provision(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["otp", "quick-service", "proxy", "timeout"])?;

    let endpoint = flags
        .get("quick-service")
        .unwrap_or(quicktunnel::DEFAULT_QUICK_SERVICE);
    let timeout: u64 = flags
        .get("timeout")
        .unwrap_or("15")
        .parse()
        .map_err(|_| "invalid --timeout: expected a whole number of seconds".to_string())?;

    let proxy = resolve_proxy(flags.get("proxy"));

    let auth_mode = if flags.present("otp") {
        AuthMode::Otp
    } else {
        AuthMode::Public
    };

    let via = proxy.as_deref().unwrap_or("a direct connection");
    eprintln!("cfrs: requesting a quick tunnel from {endpoint} via {via} (no credentials)");
    let tunnel = quicktunnel::request_quick_tunnel(endpoint, auth_mode, timeout, proxy.as_deref())
        .map_err(|e| e.to_string())?;

    // Validate the secret eagerly: a tunnel whose secret will not decode is
    // useless at the edge, and finding that out now beats finding it out later.
    let secret = tunnel.secret_bytes()?;

    println!("url:     {}", tunnel.url());
    println!("id:      {}", tunnel.id);
    println!("account: {}", tunnel.account_tag);
    println!(
        "secret:  {} bytes decoded from {} base64 chars",
        secret.len(),
        tunnel.secret.len()
    );
    if auth_mode == AuthMode::Otp {
        println!("auth:    otp (visitors must pass a one-time PIN)");
    }
    Ok(())
}

fn cmd_serve(args: &[String]) -> Result<(), String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["unix-socket", "relay", "proxy", "user"])?;

    let unix_socket = flags
        .get("unix-socket")
        .unwrap_or("/tmp/cfrs-origin.sock")
        .to_string();

    // Fail before dialling anything if the origin is not there: a tunnel that
    // accepts visitors and then 502s is worse than a clear refusal.
    if !std::path::Path::new(&unix_socket).exists() {
        return Err(format!(
            "origin socket {unix_socket} does not exist; start the origin server first"
        ));
    }

    let proxy = resolve_proxy(flags.get("proxy"));

    let config = RelayConfig {
        address: flags
            .get("relay")
            .unwrap_or(relay::DEFAULT_RELAY)
            .to_string(),
        proxy,
        username: flags.get("user").unwrap_or("cfrs").to_string(),
        unix_socket: std::path::PathBuf::from(&unix_socket),
        connect_timeout: std::time::Duration::from_secs(15),
    };

    if config.proxy.is_some() {
        eprintln!("cfrs: egress via HTTP CONNECT proxy");
    } else {
        eprintln!(
            "cfrs: no proxy configured, connecting directly (this fails in most sandboxes)"
        );
    }

    let runtime = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let (handle, session) = relay::run(config).await.map_err(|e| e.to_string())?;
        println!("url: {}", handle.url);
        println!("port: {}", handle.remote_port);
        eprintln!(
            "cfrs: serving {} on {}; press ctrl-c to stop",
            unix_socket, handle.url
        );

        // Hold the session open: dropping it closes the forward.
        let _ = session.await;
        Ok(())
    })
}

/// `http://host:port` and `host:port` mean the same thing to a CONNECT proxy.
fn strip_scheme(value: String) -> String {
    for scheme in ["http://", "https://"] {
        if let Some(rest) = value.strip_prefix(scheme) {
            return rest.to_string();
        }
    }
    value
}

/// Resolve the proxy from an explicit flag, then the environment.
fn resolve_proxy(explicit: Option<&str>) -> Option<String> {
    match explicit {
        Some(p) => Some(strip_scheme(p.to_string())),
        None => std::env::var("HTTPS_PROXY")
            .ok()
            .or_else(|| std::env::var("https_proxy").ok())
            .map(strip_scheme),
    }
}

fn cmd_doctor(args: &[String]) -> Result<ExitCode, String> {
    let flags = Flags::parse(args)?;
    flags.reject_unknown(&["proxy"])?;

    let proxy = resolve_proxy(flags.get("proxy"));

    let mut ok = true;
    println!("cfrs doctor");

    // 1. Can we bind a unix socket? The origin has to be reachable somehow.
    let probe = std::env::temp_dir().join(format!("cfrs-doctor-{}.sock", std::process::id()));
    match std::os::unix::net::UnixListener::bind(&probe) {
        Ok(_) => {
            println!("  unix socket bind      OK   ({})", probe.display());
            let _ = std::fs::remove_file(&probe);
        }
        Err(e) => {
            println!("  unix socket bind      FAIL {e}");
            ok = false;
        }
    }

    // 2. Can we bind a TCP listener? Almost always no in a sandbox.
    match std::net::TcpListener::bind("127.0.0.1:0") {
        Ok(_) => println!("  tcp listener bind     OK"),
        Err(e) => println!("  tcp listener bind     FAIL {e}  (expected in a sandbox)"),
    }

    // 3. Is the Cloudflare provisioning API reachable? This is the part that
    //    works under a restrictive egress policy.
    match quicktunnel::request_quick_tunnel(
        quicktunnel::DEFAULT_QUICK_SERVICE,
        AuthMode::Public,
        10,
        proxy.as_deref(),
    ) {
        Ok(t) => {
            println!("  quick tunnel API      OK   {}", t.hostname);
            println!("  tunnel edge :7844     not attempted (see README)");
        }
        Err(e) => {
            println!("  quick tunnel API      FAIL {e}");
            ok = false;
        }
    }

    match &proxy {
        Some(p) => println!("  egress proxy          {p}"),
        None => {
            println!("  egress proxy          none configured");
            ok = false;
        }
    }

    if ok {
        println!("\nready");
        Ok(ExitCode::SUCCESS)
    } else {
        println!("\nnot ready");
        Ok(ExitCode::FAILURE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owned(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn flags_take_the_next_token_as_a_value() {
        let f = Flags::parse(&owned(&["--unix-socket", "/tmp/a.sock", "--relay", "h:443"]))
            .expect("parse");
        assert_eq!(f.get("unix-socket"), Some("/tmp/a.sock"));
        assert_eq!(f.get("relay"), Some("h:443"));
    }

    #[test]
    fn a_bare_flag_is_boolean() {
        let f = Flags::parse(&owned(&["--otp"])).expect("parse");
        assert!(f.present("otp"));
        assert!(!f.present("timeout"));
    }

    #[test]
    fn inline_values_are_supported() {
        let f = Flags::parse(&["--timeout=30".to_string()]).expect("parse");
        assert_eq!(f.get("timeout"), Some("30"));
    }

    #[test]
    fn unknown_options_are_rejected_by_name() {
        let f = Flags::parse(&["--url-onlyy".to_string()]).expect("parse");
        let err = f.reject_unknown(&["unix-socket", "url-only"]).unwrap_err();
        assert!(err.contains("url-onlyy"), "error should name the typo: {err}");
        assert!(err.contains("--unix-socket"), "error should list valid flags: {err}");
    }

    #[test]
    fn a_bare_flag_before_another_flag_does_not_swallow_it() {
        let f = Flags::parse(&owned(&["--otp", "--timeout", "5"])).expect("parse");
        assert!(f.present("otp"), "otp should be a bare flag");
        assert_eq!(f.get("timeout"), Some("5"), "timeout should keep its value");
    }

    #[test]
    fn positional_arguments_are_rejected() {
        assert!(Flags::parse(&owned(&["oops"])).is_err());
    }

    #[test]
    fn strip_scheme_removes_a_proxy_prefix() {
        assert_eq!(strip_scheme("http://1.2.3.4:8080".into()), "1.2.3.4:8080");
        assert_eq!(strip_scheme("1.2.3.4:8080".into()), "1.2.3.4:8080");
        assert_eq!(strip_scheme("https://1.2.3.4:8443".into()), "1.2.3.4:8443");
    }

    #[test]
    fn serve_rejects_a_missing_origin_socket() {
        let missing = "/tmp/cfrs-does-not-exist-12345.sock";
        let err = cmd_serve(&[format!("--unix-socket={missing}")]).unwrap_err();
        assert!(err.contains("does not exist"), "unexpected error: {err}");
    }

    #[test]
    fn provision_rejects_an_unknown_flag_before_touching_the_network() {
        let err = cmd_provision(&["--quick-servicex=https://x".to_string()]).unwrap_err();
        assert!(err.contains("unknown option"), "unexpected error: {err}");
    }
}