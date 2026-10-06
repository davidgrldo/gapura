//! TLS to Postgres, on the rustls the rest of the workspace already uses.
//!
//! tokio-postgres takes its TLS through three small traits rather than a feature flag, and the
//! adapters published for rustls bring their own certificate parsing for channel binding. This is
//! the part of them the store needs: a verified handshake. Channel binding is not offered, so
//! SCRAM authenticates as SCRAM-SHA-256 rather than SCRAM-SHA-256-PLUS; the verified certificate
//! already pins the server, which is what binding would add.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{anyhow, Result};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, InvalidDnsNameError, ServerName};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_postgres::tls::{ChannelBinding, MakeTlsConnect, TlsConnect, TlsStream};

#[derive(Clone)]
pub struct MakeRustls(tokio_rustls::TlsConnector);

impl MakeRustls {
    /// Trusts Mozilla's root store, plus every certificate in `extra_ca`. Managed Postgres
    /// services such as RDS and Cloud SQL sign with a CA of their own, which is not in the former.
    pub fn new(extra_ca: Option<&[u8]>) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = extra_ca {
            let mut added = 0;
            for cert in CertificateDer::pem_slice_iter(pem) {
                let cert = cert.map_err(|e| anyhow!("reading the database CA file: {e:?}"))?;
                roots.add(cert)?;
                added += 1;
            }
            // An empty or non-PEM file would otherwise leave only the public roots, and the
            // failure would surface as a handshake error naming the server instead of the file.
            anyhow::ensure!(added > 0, "the database CA file holds no PEM certificate");
        }
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self(tokio_rustls::TlsConnector::from(Arc::new(config))))
    }
}

impl<S> MakeTlsConnect<S> for MakeRustls
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = Stream<S>;
    type TlsConnect = Connect;
    type Error = InvalidDnsNameError;

    fn make_tls_connect(&mut self, host: &str) -> Result<Connect, InvalidDnsNameError> {
        Ok(Connect {
            connector: self.0.clone(),
            // A host name or an IP address; rustls checks it against the certificate either way.
            name: ServerName::try_from(host.to_string())?,
        })
    }
}

pub struct Connect {
    connector: tokio_rustls::TlsConnector,
    name: ServerName<'static>,
}

impl<S> TlsConnect<S> for Connect
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    type Stream = Stream<S>;
    type Error = io::Error;
    type Future = Pin<Box<dyn Future<Output = io::Result<Stream<S>>> + Send>>;

    fn connect(self, stream: S) -> Self::Future {
        Box::pin(async move { Ok(Stream(self.connector.connect(self.name, stream).await?)) })
    }
}

pub struct Stream<S>(tokio_rustls::client::TlsStream<S>);

impl<S: AsyncRead + AsyncWrite + Unpin> TlsStream for Stream<S> {
    fn channel_binding(&self) -> ChannelBinding {
        ChannelBinding::none()
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for Stream<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for Stream<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ca_file_without_a_certificate_is_refused() {
        assert!(MakeRustls::new(Some(b"not a certificate")).is_err());
        assert!(MakeRustls::new(None).is_ok());
    }

    #[test]
    fn a_ca_file_with_a_certificate_is_read() {
        let cert = rcgen::generate_simple_self_signed(vec!["db.internal".into()]).unwrap();
        assert!(MakeRustls::new(Some(cert.cert.pem().as_bytes())).is_ok());
    }
}
