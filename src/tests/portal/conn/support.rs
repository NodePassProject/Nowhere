// Copyright (C) 2026 NodePassProject <https://github.com/NodePassProject>
// SPDX-License-Identifier: GPL-3.0-only

//! Shared portal connection test helpers.

use std::net::SocketAddr;
use std::sync::Arc;

use quinn::Connection;
use quinn::crypto::rustls::QuicClientConfig;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use url::Url;

use crate::common::{LogLevel, Logger};
use crate::portal::{Portal, UdpFlowLimits};
use crate::protocol::{AuthFrame, AuthTransport, SessionId, Target, encode_auth_frame};

use super::super::*;

#[derive(Debug)]
struct AcceptAnyServerCertificate;

impl ServerCertVerifier for AcceptAnyServerCertificate {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _certificate: &CertificateDer<'_>,
        _signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

pub(super) async fn connect_test_tls(
    listen_addr: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    connect_test_tls_with_alpns(listen_addr, vec![b"nw2".to_vec()])
        .await
        .unwrap()
}

pub(super) async fn connect_test_tls_with_alpns(
    listen_addr: SocketAddr,
    alpns: Vec<Vec<u8>>,
) -> std::io::Result<tokio_rustls::client::TlsStream<TcpStream>> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate))
        .with_no_client_auth();
    client_config.alpn_protocols = alpns;
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = TcpStream::connect(listen_addr).await?;
    connector
        .connect(
            ServerName::try_from("localhost").unwrap().to_owned(),
            stream,
        )
        .await
}

pub(super) fn tls_auth_frame(
    portal: &Portal,
    stream: &tokio_rustls::client::TlsStream<TcpStream>,
    session_id: SessionId,
) -> AuthFrame {
    let mut exporter = [0u8; 32];
    stream
        .get_ref()
        .1
        .export_keying_material(&mut exporter, b"EXPORTER-Nowhere-Auth", Some(&[]))
        .unwrap();
    encode_auth_frame(
        portal.inner.credentials.auth_key,
        AuthTransport::TlsTcp,
        &exporter,
        session_id,
    )
}

pub(super) fn quic_auth_frame(
    portal: &Portal,
    connection: &Connection,
    session_id: SessionId,
) -> AuthFrame {
    let mut exporter = [0u8; 32];
    connection
        .export_keying_material(&mut exporter, b"EXPORTER-Nowhere-Auth", b"")
        .unwrap();
    encode_auth_frame(
        portal.inner.credentials.auth_key,
        AuthTransport::Quic,
        &exporter,
        session_id,
    )
}

pub(super) fn test_target(value: &str) -> Target {
    value.parse().unwrap()
}

pub(super) async fn connect_test_quic() -> (
    Portal,
    quinn::Endpoint,
    quinn::Endpoint,
    Connection,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    connect_test_quic_with_url("portal://secret@127.0.0.1:0?log=none&net=udp").await
}

pub(super) async fn connect_test_quic_with_url(
    url: &str,
) -> (
    Portal,
    quinn::Endpoint,
    quinn::Endpoint,
    Connection,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    connect_test_quic_with_url_and_limits(url, None).await
}

pub(super) async fn connect_test_quic_with_url_and_limits(
    url: &str,
    limits: Option<UdpFlowLimits>,
) -> (
    Portal,
    quinn::Endpoint,
    quinn::Endpoint,
    Connection,
    CancellationToken,
    tokio::task::JoinHandle<()>,
) {
    let mut parsed_url = Url::parse(url).unwrap();
    if parsed_url.port() == Some(0) {
        let host = parsed_url.host_str().unwrap_or("127.0.0.1");
        let reservation = std::net::UdpSocket::bind((host, 0)).unwrap();
        let port = reservation.local_addr().unwrap().port();
        parsed_url.set_port(Some(port)).unwrap();
        drop(reservation);
    }
    let mut portal = Portal::new(parsed_url, Logger::new(LogLevel::None, false)).unwrap();
    if let Some(limits) = limits {
        let inner = Arc::get_mut(&mut portal.inner).unwrap();
        inner.udp_flow_limits = limits;
        inner.pairing = Arc::new(crate::portal::pairing::PairingRegistry::new(
            inner.runtime.max_tcp_flows as usize,
            limits.max_flows,
            inner.runtime.max_pending_pairs,
            inner.runtime.flow_pair_timeout,
        ));
    }
    let server_endpoint = portal.listen_endpoints().unwrap().pop().unwrap();
    let listen_addr = server_endpoint.local_addr().unwrap();
    let shutdown = CancellationToken::new();
    let server_shutdown = shutdown.clone();
    let server_portal = portal.inner.clone();
    let server_endpoint_for_task = server_endpoint.clone();
    let server_task = tokio::spawn(async move {
        crate::portal::listener::accept_endpoint_loop(
            server_portal,
            server_endpoint_for_task,
            server_shutdown.clone(),
            server_shutdown,
        )
        .await;
    });

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate))
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"nw2".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(rustls_config).unwrap();
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    client_endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    let connection = client_endpoint
        .connect(listen_addr, "localhost")
        .unwrap()
        .await
        .unwrap();

    (
        portal,
        server_endpoint,
        client_endpoint,
        connection,
        shutdown,
        server_task,
    )
}

pub(super) async fn connect_test_quic_to(listen_addr: SocketAddr) -> (quinn::Endpoint, Connection) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut rustls_config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCertificate))
        .with_no_client_auth();
    rustls_config.alpn_protocols = vec![b"nw2".to_vec()];
    let quic_crypto = QuicClientConfig::try_from(rustls_config).unwrap();
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(quic_crypto)));
    let connection = endpoint
        .connect(listen_addr, "localhost")
        .unwrap()
        .await
        .unwrap();
    (endpoint, connection)
}

#[derive(Clone, Copy)]
pub(super) enum TestSocksAuth<'a> {
    None,
    Password(&'a str, &'a str),
}

pub(super) async fn spawn_test_socks5_tcp(
    auth: TestSocksAuth<'static>,
    expected_target: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        accept_test_socks_auth(&mut control, auth).await;
        let (command, target, _) = read_test_socks_command(&mut control).await;
        assert_eq!(command, 1);
        assert_eq!(target, expected_target);
        write_test_socks_reply(&mut control, SocketAddr::from(([127, 0, 0, 1], 50000))).await;
        let mut payload = [0u8; 4];
        control.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ping");
        control.write_all(b"pong").await.unwrap();
    });
    (endpoint, task)
}

pub(super) async fn spawn_test_socks5_udp(
    auth: TestSocksAuth<'static>,
    expected_target: &'static str,
) -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut control, _) = listener.accept().await.unwrap();
        accept_test_socks_auth(&mut control, auth).await;
        let (command, _, _) = read_test_socks_command(&mut control).await;
        assert_eq!(command, 3);
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        write_test_socks_reply(&mut control, relay.local_addr().unwrap()).await;

        let mut packet = [0u8; 1024];
        let (size, peer) = relay.recv_from(&mut packet).await.unwrap();
        let (target, _, header_len) = decode_test_socks_address(&packet, 3);
        assert_eq!(target, expected_target);
        assert_eq!(&packet[header_len..size], b"ping");
        let mut response = packet[..header_len].to_vec();
        response.extend_from_slice(b"pong");
        relay.send_to(&response, peer).await.unwrap();

        let mut eof = [0u8; 1];
        let _ = control.read(&mut eof).await;
    });
    (endpoint, task)
}

async fn accept_test_socks_auth(stream: &mut TcpStream, auth: TestSocksAuth<'_>) {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 5);
    assert_eq!(header[1], 1);
    let mut method = [0u8; 1];
    stream.read_exact(&mut method).await.unwrap();
    let expected_method = match auth {
        TestSocksAuth::None => 0,
        TestSocksAuth::Password(_, _) => 2,
    };
    assert_eq!(method[0], expected_method);
    stream.write_all(&[5, expected_method]).await.unwrap();

    if let TestSocksAuth::Password(expected_user, expected_password) = auth {
        let version = stream.read_u8().await.unwrap();
        let user_len = stream.read_u8().await.unwrap() as usize;
        let mut user = vec![0u8; user_len];
        stream.read_exact(&mut user).await.unwrap();
        let password_len = stream.read_u8().await.unwrap() as usize;
        let mut password = vec![0u8; password_len];
        stream.read_exact(&mut password).await.unwrap();
        assert_eq!(version, 1);
        assert_eq!(user, expected_user.as_bytes());
        assert_eq!(password, expected_password.as_bytes());
        stream.write_all(&[1, 0]).await.unwrap();
    }
}

async fn read_test_socks_command(stream: &mut TcpStream) -> (u8, String, u16) {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.unwrap();
    assert_eq!(header[0], 5);
    assert_eq!(header[2], 0);
    let (host, port, _) = read_test_socks_address(stream, header[3]).await;
    (header[1], host, port)
}

async fn read_test_socks_address(stream: &mut TcpStream, address_type: u8) -> (String, u16, usize) {
    match address_type {
        1 => {
            let mut value = [0u8; 6];
            stream.read_exact(&mut value).await.unwrap();
            (
                format!("{}.{}.{}.{}", value[0], value[1], value[2], value[3]),
                u16::from_be_bytes([value[4], value[5]]),
                10,
            )
        }
        3 => {
            let length = stream.read_u8().await.unwrap() as usize;
            let mut host = vec![0u8; length];
            stream.read_exact(&mut host).await.unwrap();
            let port = stream.read_u16().await.unwrap();
            (String::from_utf8(host).unwrap(), port, 7 + length)
        }
        4 => {
            let mut value = [0u8; 18];
            stream.read_exact(&mut value).await.unwrap();
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&value[..16]);
            (
                std::net::Ipv6Addr::from(ip).to_string(),
                u16::from_be_bytes([value[16], value[17]]),
                22,
            )
        }
        other => panic!("unexpected address type: {other}"),
    }
}

fn decode_test_socks_address(packet: &[u8], offset: usize) -> (String, u16, usize) {
    let address_type = packet[offset];
    let mut cursor = offset + 1;
    let (host, port) = match address_type {
        1 => {
            let host = format!(
                "{}.{}.{}.{}",
                packet[cursor],
                packet[cursor + 1],
                packet[cursor + 2],
                packet[cursor + 3]
            );
            cursor += 4;
            let port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
            cursor += 2;
            (host, port)
        }
        3 => {
            let length = packet[cursor] as usize;
            cursor += 1;
            let host = String::from_utf8(packet[cursor..cursor + length].to_vec()).unwrap();
            cursor += length;
            let port = u16::from_be_bytes([packet[cursor], packet[cursor + 1]]);
            cursor += 2;
            (host, port)
        }
        other => panic!("unexpected address type: {other}"),
    };
    (host, port, cursor)
}

async fn write_test_socks_reply(stream: &mut TcpStream, address: SocketAddr) {
    let mut response = vec![5, 0, 0];
    match address {
        SocketAddr::V4(address) => {
            response.push(1);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            response.push(4);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    stream.write_all(&response).await.unwrap();
}

pub(super) async fn stop_test_quic(
    server_endpoint: quinn::Endpoint,
    client_endpoint: quinn::Endpoint,
    shutdown: CancellationToken,
    server_task: tokio::task::JoinHandle<()>,
) {
    shutdown.cancel();
    server_endpoint.close(VarInt::from_u32(0), b"");
    client_endpoint.close(VarInt::from_u32(0), b"");
    server_task.await.unwrap();
}
