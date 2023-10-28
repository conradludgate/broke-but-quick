// yoke does this
#![allow(clippy::forget_non_drop)]
use std::{net::SocketAddr, ops::Deref, sync::Arc};

use bincode::Options;
use quinn::{Endpoint, SendStream};
use quinn_proto::ClientConfig;
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yoke::{Yoke, Yokeable};

pub mod tls {
    use rustls::{
        server::AllowAnyAuthenticatedClient, version::TLS13, Certificate, ClientConfig, PrivateKey,
        RootCertStore, ServerConfig,
    };

    fn ca_store(
        ca_certs: impl IntoIterator<Item = Certificate>,
    ) -> Result<RootCertStore, rustls::Error> {
        let mut ca_store = RootCertStore::empty();
        for cert in ca_certs {
            ca_store.add(&cert)?;
        }
        Ok(ca_store)
    }

    pub fn client(
        private_key: PrivateKey,
        client_certs: impl IntoIterator<Item = Certificate>,
        ca_certs: impl IntoIterator<Item = Certificate>,
    ) -> Result<ClientConfig, rustls::Error> {
        let mut config = rustls::ClientConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_root_certificates(ca_store(ca_certs)?)
            .with_client_auth_cert(client_certs.into_iter().collect(), private_key)?;

        config.alpn_protocols = vec![b"bbq".to_vec()];
        Ok(config)
    }

    pub fn server(
        private_key: PrivateKey,
        server_certs: impl IntoIterator<Item = Certificate>,
        ca_certs: impl IntoIterator<Item = Certificate>,
    ) -> Result<ServerConfig, rustls::Error> {
        let mut config = rustls::ServerConfig::builder()
            .with_safe_default_cipher_suites()
            .with_safe_default_kx_groups()
            .with_protocol_versions(&[&TLS13])
            .unwrap()
            .with_client_cert_verifier(
                AllowAnyAuthenticatedClient::new(ca_store(ca_certs)?).boxed(),
            )
            .with_single_cert(server_certs.into_iter().collect(), private_key)?;

        config.alpn_protocols = vec![b"bbq".to_vec()];
        Ok(config)
    }
}

pub struct Connection {
    inner: quinn::Connection,
}

#[derive(Serialize, Deserialize, Yokeable)]
pub enum OpenMessage<'a> {
    #[serde(borrow)]
    Publish(Publish<'a>),
    #[serde(borrow)]
    Consume(Consume<'a>),
}

#[derive(Serialize, Deserialize, Yokeable)]
pub struct Publish<'a> {
    pub exchange: &'a str,
    pub routing_key: &'a str,
    pub message: &'a [u8],
}

#[derive(Serialize, Deserialize, Yokeable)]
pub struct Consume<'a> {
    pub queue: &'a str,
}

pub const PUBLISH: [u8; 4] = *b"SEND";
pub const CONSUME: [u8; 4] = *b"RECV";

pub fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_little_endian()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_no_limit()
}

pub async fn write_message(
    t: &(impl Serialize + ?Sized),
    w: &mut (impl AsyncWrite + Unpin),
) -> Result<(), Box<dyn std::error::Error>> {
    let message = options().serialize(t)?;
    w.write_all(&(message.len() as u64).to_le_bytes()).await?;
    w.write_all(&message).await?;
    Ok(())
}

/// writes a message of a fixed known size into the buffer
///
/// # Panics:
/// Panics if the size of the buffer is wrong (eg, not fixed)
pub async fn write_message_fixed(
    t: &(impl Serialize + ?Sized),
    w: &mut (impl AsyncWrite + Unpin),
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    let len = options().serialized_size(t)?;
    debug_assert_eq!(buf.len(), len as usize, "buffer len did not match");
    options().serialize_into(&mut *buf, t)?;
    w.write_all(buf).await?;
    Ok(())
}

pub async fn read_message<T>(
    r: &mut (impl AsyncRead + Unpin),
) -> Result<Yoke<T, Vec<u8>>, Box<dyn std::error::Error>>
where
    T: for<'a> Yokeable<'a>,
    for<'de> <T as yoke::Yokeable<'de>>::Output: Deserialize<'de>,
{
    let mut payload_len = [0; 8];
    r.read_exact(&mut payload_len).await?;
    let payload_len = dbg!(u64::from_le_bytes(payload_len));

    let mut payload = vec![0; payload_len as usize];
    r.read_exact(&mut payload).await?;

    Ok(Yoke::try_attach_to_cart(payload, |bytes| {
        options().deserialize(bytes)
    })?)
}

pub async fn read_message_fixed<'de, T: Deserialize<'de>>(
    r: &mut (impl AsyncRead + Unpin),
    buf: &'de mut [u8],
) -> Result<T, Box<dyn std::error::Error>> {
    r.read_exact(buf).await?;
    Ok(options().deserialize(buf)?)
}

impl Connection {
    pub async fn new(
        socket: SocketAddr,
        hostname: &str,
        private_key: PrivateKey,
        client_certs: impl IntoIterator<Item = Certificate>,
        ca_certs: impl IntoIterator<Item = Certificate>,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let crypto_config = crate::tls::client(private_key, client_certs, ca_certs)?;
        Self::new_with_crypto_config(socket, hostname, crypto_config).await
    }

    pub async fn new_with_crypto_config(
        socket: SocketAddr,
        hostname: &str,
        crypto_config: impl quinn_proto::crypto::ClientConfig + 'static,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let config = ClientConfig::new(Arc::new(crypto_config));

        let mut client = Endpoint::client("0.0.0.0:0".parse()?)?;
        client.set_default_client_config(config);

        let connecting = client.connect(socket, hostname)?;
        let connection = connecting.await?;
        println!("connection established {:?}", connection.rtt());

        Ok(Self { inner: connection })
    }

    pub async fn publish(
        &self,
        exchange: &str,
        routing_key: &str,
        message: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let (mut send, mut recv) = self.inner.open_bi().await?;

        let message = OpenMessage::Publish(Publish {
            exchange,
            routing_key,
            message,
        });
        write_message(&message, &mut send).await?;

        let confirm: PublishConfirm = read_message_fixed(&mut recv, &mut [0; 1]).await?;
        match confirm {
            PublishConfirm::Ack => Ok(()),
        }
    }

    pub async fn consume(&self, queue: &str) -> Result<Message, Box<dyn std::error::Error>> {
        let (mut send, mut recv) = self.inner.open_bi().await?;
        dbg!("consuming");

        write_message(&OpenMessage::Consume(Consume { queue }), &mut send).await?;
        send.flush().await?;

        dbg!("sent");

        let payload = read_message::<&[u8]>(&mut recv).await?;

        Ok(Message { payload, send })
    }
}

pub struct Message {
    payload: Yoke<&'static [u8], Vec<u8>>,
    send: SendStream,
}

impl Deref for Message {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.payload.get()
    }
}

#[derive(Serialize, Deserialize, Yokeable, Debug)]
pub enum MessageAck {
    Ack,
    Nack,
    Reject,
}

impl Message {
    pub async fn message_ack(
        mut self,
        ack_code: MessageAck,
    ) -> Result<(), Box<dyn std::error::Error>> {
        write_message_fixed(&ack_code, &mut self.send, &mut [0; 1]).await?;
        self.send.finish().await?;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Yokeable, Debug)]
pub enum PublishConfirm {
    Ack,
}
