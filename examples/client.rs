use std::{fs::File, io::BufReader};

use broke_but_quick::Connection;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
        "certs/client.key.pem",
    )?))?;
    let key = rustls::PrivateKey(keys.remove(0));
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/ca.pem")?))?;
    let client_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/client.pem")?))?;

    let conn = Connection::new(
        "127.0.0.1:6789".parse()?,
        "server.broke-but-quick",
        key,
        client_certs.into_iter().map(rustls::Certificate),
        ca_certs.into_iter().map(rustls::Certificate),
    )
    .await?;

    conn.publish("test-exchange", "test-key2", "hello world".as_bytes())
        .await?;

    Ok(())
}
