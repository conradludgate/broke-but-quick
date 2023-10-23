use std::{collections::HashMap, fs::File, io::BufReader, sync::Arc};

use quinn::{Connecting, Endpoint, RecvStream, SendStream, ServerConfig};
use tokio::sync::Mutex;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut keys = rustls_pemfile::pkcs8_private_keys(&mut BufReader::new(File::open(
        "certs/server.key.pem",
    )?))?;
    let key = rustls::PrivateKey(keys.remove(0));
    let ca_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/ca.pem")?))?;
    let server_certs = rustls_pemfile::certs(&mut BufReader::new(File::open("certs/server.pem")?))?;

    let crypto_config = broke_but_quick::tls::server(
        key,
        server_certs.into_iter().map(rustls::Certificate),
        ca_certs.into_iter().map(rustls::Certificate),
    )?;

    let config = ServerConfig::with_crypto(Arc::new(crypto_config));

    let server = Endpoint::server(config, "0.0.0.0:6789".parse()?)?;

    let state = Arc::new(SharedState {
        map: Mutex::new(HashMap::new()),
    });

    while let Some(connecting) = server.accept().await {
        tokio::spawn(handle_connection(state.clone(), connecting));
    }

    Ok(())
}

struct SharedState {
    map: Mutex<HashMap<(String, String), Vec<Vec<u8>>>>,
}

async fn handle_connection(state: Arc<SharedState>, connecting: Connecting) {
    match handle_connection_inner(state, connecting).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error handling connection {e:?}");
        }
    }
}

async fn handle_connection_inner(
    state: Arc<SharedState>,
    connecting: Connecting,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", connecting.remote_address());

    let connection = connecting.await?;
    println!("connection established {:?}", connection.rtt());

    loop {
        let (send, recv) = connection.accept_bi().await?;
        tokio::spawn(handle_stream(state.clone(), send, recv));

        println!("connection continue {:?}", connection.rtt());
    }
}

async fn handle_stream(state: Arc<SharedState>, send: SendStream, recv: RecvStream) {
    match handle_stream_inner(state, send, recv).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error handling stream {e:?}");
        }
    }
}

async fn handle_stream_inner(
    state: Arc<SharedState>,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("new stream {}", send.id());

    let mut header = [0; 4];
    recv.read_exact(&mut header).await?;

    match header {
        broke_but_quick::PUBLISH => handle_stream_publish(state, send, recv).await?,
        _ => todo!(),
    }

    Ok(())
}

async fn handle_stream_publish(
    state: Arc<SharedState>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut total_len = [0; 8];
    recv.read_exact(&mut total_len).await?;
    let total_len = dbg!(u64::from_be_bytes(total_len)) - 8;

    let payload = recv.read_to_end(total_len as usize).await?;
    let mut payload = payload.as_slice();

    let (len, rest) = payload.split_at(8);
    let exchange_len = u64::from_be_bytes(len.try_into().unwrap());
    let (exchange, rest) = rest.split_at(dbg!(exchange_len) as usize);
    let exchange = std::str::from_utf8(exchange)?;
    payload = rest;

    let (len, rest) = payload.split_at(8);
    let routing_len = u64::from_be_bytes(len.try_into().unwrap());
    let (routing_key, rest) = rest.split_at(dbg!(routing_len) as usize);
    let routing_key = std::str::from_utf8(routing_key)?;
    payload = rest;

    let (len, rest) = payload.split_at(8);
    let message_len = u64::from_be_bytes(len.try_into().unwrap());
    let (message, rest) = rest.split_at(dbg!(message_len) as usize);
    payload = rest;

    if !payload.is_empty() {
        return Err("invalid payload".into());
    }

    let message_str = String::from_utf8_lossy(message);

    println!("{exchange} {routing_key} {message_str}");

    {
        let mut map = state.map.lock().await;

        map.entry((exchange.to_owned(), routing_key.to_owned()))
            .or_default()
            .push(message.to_owned());

        println!("map {map:?}");
    }

    send.write_all(&[1]).await?;
    send.finish().await?;

    Ok(())
}
