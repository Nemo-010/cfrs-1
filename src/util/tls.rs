//! TLS configuration helpers shared by origins and the Cloudflare edge.

use std::path::Path;
use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};

/// Build a client TLS config.
///
/// `insecure` disables verification entirely and is intended for origins with
/// self-signed certificates. `ca_file` adds a private root instead, which is the
/// safer option when one is available.
/// `server_name` is accepted so callers can be explicit about which name the
/// certificate must cover; rustls reads it from the connector call site.
pub fn client_config(
    _server_name: &str,
    insecure: bool,
    ca_file: Option<&Path>,
) -> Result<Arc<ClientConfig>, String> {
    let builder = ClientConfig::builder();

    if insecure {
        return Ok(Arc::new(
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        ));
    }

    let mut roots = RootCertStore::empty();
    if let Some(path) = ca_file {
        let pem = std::fs::read(path).map_err(|e| format!("reading ca file {path:?}: {e}"))?;
        let mut cursor = std::io::Cursor::new(pem);
        for cert in rustls_pemfile::certs(&mut cursor) {
            let cert = cert.map_err(|e| format!("parsing ca file {path:?}: {e}"))?;
            roots
                .add(cert)
                .map_err(|e| format!("adding ca cert from {path:?}: {e}"))?;
        }
        if roots.is_empty() {
            return Err(format!("no certificates found in {path:?}"));
        }
    }

    Ok(Arc::new(
        builder.with_root_certificates(roots).with_no_client_auth(),
    ))
}

/// A verifier that accepts anything.
///
/// Only reachable through [`client_config`] with `insecure: true`, which is the
/// same contract cloudflared's `noTLSVerify` has. It is here rather than in a
/// dependency because rustls 0.23 requires the verifier to be written out.
#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insecure_mode_builds_a_config() {
        let cfg = client_config("example.com", true, None).expect("insecure config");
        assert_eq!(cfg.alpn_protocols, Vec::<Vec<u8>>::new());
    }

    #[test]
    fn a_missing_ca_file_is_reported_not_ignored() {
        let err = client_config("example.com", false, Some(Path::new("/tmp/cfrs-no-such-ca.pem")))
            .expect_err("missing ca must fail");
        assert!(err.contains("reading ca file"), "unexpected error: {err}");
    }

    #[test]
    fn the_insecure_verifier_accepts_any_certificate() {
        let v = NoVerify;
        assert!(v
            .verify_server_cert(
                &rustls::pki_types::CertificateDer::from(vec![0u8]),
                &[],
                &rustls::pki_types::ServerName::try_from("example.com").unwrap(),
                &[],
                rustls::pki_types::UnixTime::since_unix_epoch(std::time::Duration::from_secs(0)),
            )
            .is_ok());
        assert!(!v.supported_verify_schemes().is_empty());
    }
}