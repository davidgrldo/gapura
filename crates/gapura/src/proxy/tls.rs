//! TLS server side: pick the certificate for the SNI of each handshake from the current runtime.

use std::sync::Arc;

use async_trait::async_trait;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::ssl::NameType;

use crate::store::Store;
use crate::telemetry::METRICS;

/// One resolver per HTTPS listen address; the port selects among listeners in the Config.
pub struct SniResolver {
    pub store: Arc<Store>,
    pub port: u16,
}

/// SNI as sent by the client, normalized the same way as the request host.
pub fn normalize_sni(sni: &str) -> String {
    sni.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[async_trait]
impl TlsAccept for SniResolver {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let rt = self.store.load_full();
        let sni = ssl.servername(NameType::HOST_NAME).map(normalize_sni);
        let port_label = self.port.to_string();
        let Some(bundle) = rt.config.tls_for(self.port, sni.as_deref()) else {
            METRICS
                .tls_sni_misses_total
                .with_label_values(&[&port_label])
                .inc();
            tracing::debug!(port = self.port, sni = ?sni, "no TLS listener for this SNI");
            return;
        };
        let Some(cert) = rt.cert(&bundle.secret) else {
            METRICS
                .tls_sni_misses_total
                .with_label_values(&[&port_label])
                .inc();
            tracing::warn!(secret = %bundle.secret, "certificate selected but not parsed");
            return;
        };
        if let Err(e) = ext::ssl_use_certificate(ssl, &cert.leaf) {
            tracing::error!(secret = %bundle.secret, error = %e, "ssl_use_certificate failed");
            return;
        }
        if let Err(e) = ext::ssl_use_private_key(ssl, &cert.key) {
            tracing::error!(secret = %bundle.secret, error = %e, "ssl_use_private_key failed");
            return;
        }
        for intermediate in &cert.chain {
            if let Err(e) = ext::ssl_add_chain_cert(ssl, intermediate) {
                tracing::warn!(secret = %bundle.secret, error = %e, "ssl_add_chain_cert failed");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sni_is_normalized() {
        assert_eq!(normalize_sni("API.Example.com."), "api.example.com");
        assert_eq!(normalize_sni(" a.b "), "a.b");
    }
}
