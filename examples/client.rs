use std::{fs::File, io::BufReader, sync::Arc};

use quinn::{ClientConfig, Endpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
        "certs/client.key.pem",
    )?))?;
    let key = rustls::PrivateKey(keys.remove(0));
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/ca.pem")?))?;
    let client_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/client.pem")?))?;

    let mut crypto_config = broke_but_quick::tls::client(
        key,
        client_certs.into_iter().map(rustls::Certificate),
        ca_certs.into_iter().map(rustls::Certificate),
    )?;
    crypto_config.alpn_protocols = vec![b"bbq".to_vec()];

    let config = ClientConfig::new(Arc::new(crypto_config));

    let mut client = Endpoint::client("0.0.0.0:0".parse()?)?;
    client.set_default_client_config(config);

    let connecting = client.connect("127.0.0.1:6789".parse()?, "server.broke-but-quick")?;
    let connection = connecting.await?;
    println!("connection established {:?}", connection.rtt());

    let (mut send, mut recv) = connection.open_bi().await?;
    println!("new stream {} {:?}", send.id(), connection.rtt());

    let rx_handle = tokio::spawn(async move {
        let data = recv.read_to_end(128).await.unwrap();
        println!("{}", String::from_utf8(data).unwrap());
    });

    send.write_all(b"hello world").await?;
    send.finish().await?;

    rx_handle.await?;

    Ok(())
}
