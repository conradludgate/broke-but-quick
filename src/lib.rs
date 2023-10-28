use std::{net::SocketAddr, sync::Arc};

use quinn::{Endpoint, SendStream};
use quinn_proto::ClientConfig;
use rustls::{Certificate, PrivateKey};
use tokio::io::AsyncWriteExt;

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

pub const PUBLISH: [u8; 4] = *b"SEND";
pub const CONSUME: [u8; 4] = *b"RECV";

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

        send.write_all(&PUBLISH).await?;
        let entire_length = exchange.len() + routing_key.len() + message.len() + 3 * 8;
        send.write_all(&(entire_length as u64).to_be_bytes())
            .await?;
        send.write_all(&(exchange.len() as u64).to_be_bytes())
            .await?;
        send.write_all(exchange.as_bytes()).await?;
        send.write_all(&(routing_key.len() as u64).to_be_bytes())
            .await?;
        send.write_all(routing_key.as_bytes()).await?;
        send.write_all(&(message.len() as u64).to_be_bytes())
            .await?;
        send.write_all(message).await?;
        send.finish().await?;

        let mut confirm = [0];
        recv.read_exact(&mut confirm).await?;

        if confirm != [1] {
            return Err(format!("unconfirmed {confirm:?}").into());
        }

        Ok(())
    }

    pub async fn consume(&self, queue: &str) -> Result<Message, Box<dyn std::error::Error>> {
        let (mut send, mut recv) = self.inner.open_bi().await?;
        dbg!("consuming");

        send.write_all(&CONSUME).await?;
        send.write_all(&(queue.len() as u64).to_be_bytes()).await?;
        send.write_all(queue.as_bytes()).await?;
        send.flush().await?;

        dbg!("sent");

        let mut payload_len = [0; 8];
        recv.read_exact(&mut payload_len).await?;
        let payload_len = dbg!(u64::from_be_bytes(payload_len));

        let payload = recv.read_to_end(payload_len as usize).await?;

        Ok(Message { payload, send })
    }
}

pub struct Message {
    pub payload: Vec<u8>,
    send: SendStream,
}

#[repr(u8)]
pub enum MessageAck {
    Ack = 0,
    Nack = 1,
    Reject = 2,
}

impl Message {
    pub async fn message_ack(
        mut self,
        ack_code: MessageAck,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.send.write_all(&[ack_code as u8]).await?;
        self.send.finish().await?;
        Ok(())
    }
}
