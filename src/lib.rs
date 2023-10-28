// yoke does this
#![allow(clippy::forget_non_drop)]
use std::{net::SocketAddr, ops::Deref, sync::Arc};

use encoding::{read_message_fixed, write_message_fixed};
use quinn::{Endpoint, SendStream};
use quinn_proto::ClientConfig;
use rustls::{Certificate, PrivateKey};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use yoke::{Yoke, Yokeable};

use crate::encoding::{read_message, write_message};

pub mod encoding;
pub mod tls;

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

#[derive(Serialize, Deserialize, Yokeable, Debug)]
pub enum MessageAck {
    Ack,
    Nack,
    Reject,
}

#[derive(Serialize, Deserialize, Yokeable, Debug)]
pub enum PublishConfirm {
    Ack,
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
