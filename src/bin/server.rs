use std::{fs::File, io::BufReader, sync::Arc};

use quinn::{Connecting, Endpoint, RecvStream, SendStream, ServerConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
        "certs/server.key.pem",
    )?))?;
    let key = rustls::PrivateKey(keys.remove(0));
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/ca.pem")?))?;
    let server_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/server.pem")?))?;

    let mut crypto_config = broke_but_quick::tls::server(
        key,
        server_certs.into_iter().map(rustls::Certificate),
        ca_certs.into_iter().map(rustls::Certificate),
    )?;
    crypto_config.alpn_protocols = vec![b"bbq".to_vec()];

    let config = ServerConfig::with_crypto(Arc::new(crypto_config));

    let server = Endpoint::server(config, "0.0.0.0:6789".parse()?)?;

    while let Some(connecting) = server.accept().await {
        tokio::spawn(handle_connection(connecting));
    }

    Ok(())
}

async fn handle_connection(connecting: Connecting) {
    match handle_connection_inner(connecting).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error handling connection {e:?}");
        }
    }
}

async fn handle_connection_inner(connecting: Connecting) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", connecting.remote_address());

    let connection = connecting.await?;
    println!("connection established {:?}", connection.rtt());

    loop {
        let (send, recv) = connection.accept_bi().await?;
        tokio::spawn(handle_stream(send, recv));

        println!("connection continue {:?}", connection.rtt());
    }
}

async fn handle_stream(send: SendStream, recv: RecvStream) {
    match handle_stream_inner(send, recv).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error handling stream {e:?}");
        }
    }
}

async fn handle_stream_inner(
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("new stream {}", send.id());

    let data = recv.read_to_end(128).await?;
    println!("{}", String::from_utf8(data.clone())?);

    send.write_all(&data).await?;
    send.finish().await?;

    Ok(())
}
