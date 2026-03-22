use std::net::{IpAddr, SocketAddr};
use std::net::IpAddr as StdIpAddr;
use std::sync::{Arc, Mutex};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration};
use tokio_rustls::TlsConnector;
use rustls::ClientConfig;
use rustls::SignatureScheme;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier, HandshakeSignatureValid};
use rustls::pki_types::{ServerName, CertificateDer, UnixTime};
use rustls::pki_types::IpAddr as PkiIpAddr;
use x509_parser::prelude::*;

pub struct TlsInfo {
    pub version: String,
    pub cn: Option<String>,
    pub sans: Vec<String>,
    pub issuer: Option<String>,
    pub expiry: Option<String>,
    pub expired: bool,
}

pub struct HttpInfo {
    pub status: u16,
    pub server: Option<String>,
    pub title: Option<String>,
}

pub struct ProbeResult {
    pub tls: Option<TlsInfo>,
    pub http: Option<HttpInfo>,
}

#[derive(Debug)]
struct CaptureVerifier {
    cert: Arc<Mutex<Option<Vec<u8>>>>,
}

impl ServerCertVerifier for CaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        *self.cert.lock().unwrap() = Some(end_entity.as_ref().to_vec());
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
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

fn make_server_name(ip: StdIpAddr) -> ServerName<'static> {
    match ip {
        StdIpAddr::V4(a) => ServerName::IpAddress(PkiIpAddr::V4(a.into())),
        StdIpAddr::V6(a) => ServerName::IpAddress(PkiIpAddr::V6(a.into())),
    }
}

fn make_connector() -> (TlsConnector, Arc<Mutex<Option<Vec<u8>>>>) {
    let cert_arc: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));
    let verifier = Arc::new(CaptureVerifier { cert: cert_arc.clone() });
    let config = ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    (TlsConnector::from(Arc::new(config)), cert_arc)
}

async fn do_http<S: AsyncReadExt + AsyncWriteExt + Unpin>(stream: &mut S, ip: StdIpAddr) -> Option<HttpInfo> {
    let req = format!("GET / HTTP/1.0\r\nHost: {}\r\nUser-Agent: synapse\r\nConnection: close\r\n\r\n", ip);
    stream.write_all(req.as_bytes()).await.ok()?;

    let mut buf = Vec::with_capacity(8192);
    let mut tmp = [0u8; 4096];
    loop {
        match stream.read(&mut tmp).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                buf.extend_from_slice(&tmp[..n]);
                if buf.len() >= 8192 {
                    break;
                }
            }
        }
    }
    parse_http(&buf)
}

async fn tls_and_http(ip: StdIpAddr, port: u16) -> Option<ProbeResult> {
    let (connector, cert_arc) = make_connector();
    let addr = SocketAddr::new(ip, port);
    let tcp = TcpStream::connect(addr).await.ok()?;
    let mut stream = connector.connect(make_server_name(ip), tcp).await.ok()?;

    let version = match stream.get_ref().1.protocol_version() {
        Some(rustls::ProtocolVersion::TLSv1_3) => "TLS 1.3",
        Some(rustls::ProtocolVersion::TLSv1_2) => "TLS 1.2",
        _ => "TLS",
    }.to_string();

    let der = cert_arc.lock().unwrap().clone();
    let mut tls = der.as_deref().and_then(parse_cert).unwrap_or_else(|| TlsInfo {
        version: String::new(),
        cn: None,
        sans: vec![],
        issuer: None,
        expiry: None,
        expired: false,
    });
    tls.version = version;

    let http = do_http(&mut stream, ip).await;
    Some(ProbeResult { tls: Some(tls), http })
}

async fn plain_http(ip: StdIpAddr, port: u16) -> Option<HttpInfo> {
    let mut stream = TcpStream::connect(SocketAddr::new(ip, port)).await.ok()?;
    do_http(&mut stream, ip).await
}

pub async fn probe_port(ip: IpAddr, port: u16, timeout_ms: u64) -> ProbeResult {
    let dur = Duration::from_millis(timeout_ms * 3);
    if let Ok(Some(r)) = timeout(dur, tls_and_http(ip, port)).await {
        return r;
    }
    let http = timeout(dur, plain_http(ip, port)).await.ok().flatten();
    ProbeResult { tls: None, http }
}

fn parse_cert(der: &[u8]) -> Option<TlsInfo> {
    let (_, cert) = X509Certificate::from_der(der).ok()?;

    let cn = cert.subject()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(String::from);

    let sans: Vec<String> = cert.subject_alternative_name()
        .ok()
        .flatten()
        .map(|ext| ext.value.general_names.iter()
            .filter_map(|gn| match gn {
                GeneralName::DNSName(n) => Some(n.to_string()),
                GeneralName::IPAddress(b) if b.len() == 4 => {
                    Some(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
                }
                _ => None,
            })
            .collect())
        .unwrap_or_default();

    let issuer = cert.issuer()
        .iter_common_name()
        .next()
        .and_then(|a| a.as_str().ok())
        .map(String::from);

    let not_after = cert.validity().not_after.timestamp();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64;

    Some(TlsInfo {
        version: String::new(),
        cn,
        sans,
        issuer,
        expiry: Some(ts_to_date(not_after)),
        expired: not_after < now,
    })
}

fn ts_to_date(ts: i64) -> String {
    let z = ts / 86400 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = if m <= 2 { y + 1 } else { y };
    format!("{:04}-{:02}-{:02}", year, m, d)
}

fn parse_http(data: &[u8]) -> Option<HttpInfo> {
    let text = std::str::from_utf8(data).unwrap_or("");
    let status: u16 = text.lines().next()?.split_whitespace().nth(1)?.parse().ok()?;

    let server = text.lines()
        .find(|l| l.to_ascii_lowercase().starts_with("server:"))
        .map(|l| l[7..].trim().to_string());

    let title = extract_title(text);
    Some(HttpInfo { status, server, title })
}

fn extract_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = start + lower[start..].find("</title>")?;
    let s = html[start..end].trim().to_string();
    if s.is_empty() { None } else { Some(s) }
}
