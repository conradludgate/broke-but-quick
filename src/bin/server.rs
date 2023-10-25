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

    let exchange_name = "test-exchange".to_owned();
    let queue_name1 = "test-queue1".to_owned();
    let queue_name2 = "test-queue2".to_owned();

    let route1 = "route1".to_owned();
    let route2 = "route2".to_owned();

    let exchange = ExchangesState {
        routes: HashMap::from([
            (route1, vec![queue_name1.clone()]),
            (route2, vec![queue_name1.clone(), queue_name2.clone()]),
        ]),
    };

    let state = Arc::new(SharedState {
        exchanges: HashMap::from([(exchange_name, exchange)]),
        queues: HashMap::from([
            (queue_name1, Mutex::default()),
            (queue_name2, Mutex::default()),
        ]),
    });

    while let Some(connecting) = server.accept().await {
        tokio::spawn(handle_connection(state.clone(), connecting));
    }

    Ok(())
}

type ExchangeName = String;
type Route = String;
type QueueName = String;
type Message = Vec<u8>;

struct SharedState {
    exchanges: HashMap<ExchangeName, ExchangesState>,
    queues: HashMap<QueueName, Mutex<Vec<MessageState>>>,
}

struct ExchangesState {
    routes: HashMap<Route, Vec<QueueName>>,
}

#[derive(Clone)]
struct MessageState {
    id: uuid::Uuid,
    inflight: bool,
    payload: Message,
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
        broke_but_quick::CONSUME => handle_stream_consume(state, send, recv).await?,
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
    let total_len = dbg!(u64::from_be_bytes(total_len));

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

    let exchange = state.exchanges.get(exchange).ok_or("unknown exchange")?;
    let queues = exchange.routes.get(routing_key).ok_or("unknown route")?;
    for queue in queues {
        state
            .queues
            .get(queue)
            .unwrap()
            .lock()
            .await
            .push(MessageState {
                id: uuid::Uuid::new_v4(),
                inflight: false,
                payload: message.to_owned(),
            });
    }

    send.write_all(&[1]).await?;
    send.finish().await?;

    Ok(())
}

async fn handle_stream_consume(
    state: Arc<SharedState>,
    mut send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut queue_len = [0; 8];
    recv.read_exact(&mut queue_len).await?;
    let queue_len = dbg!(u64::from_be_bytes(queue_len));
    let mut queue = vec![0; queue_len as usize];
    recv.read_exact(&mut queue).await?;
    let queue = String::from_utf8(queue)?;
    dbg!(&queue);

    let message = state
        .queues
        .get(&queue)
        .unwrap()
        .lock()
        .await
        .iter_mut()
        .find(|m| !m.inflight)
        .map(|m| {
            m.inflight = true;
            m
        })
        .cloned();

    let Some(message) = message else {
        send.write_all(&[0]).await?;
        return Ok(());
    };

    let message_id = message.id;

    send.write_all(&[1]).await?;

    // let total_len = message.payload.len() + 16 + 8;

    // send.write_all(&(total_len as u64).to_be_bytes()).await?;

    // send.write_all(message.id.as_bytes()).await?;
    // send.finish().await?;

    send.write_all(&(message.payload.len() as u64).to_be_bytes())
        .await?;
    send.write_all(&message.payload).await?;
    send.finish().await?;

    // let mut message_id = [0; 16];
    // recv.read_exact(&mut message_id).await?;
    // let message_id = uuid::Uuid::from_bytes(message_id);

    let mut confirm = [0];
    recv.read_exact(&mut confirm).await?;

    let mut queue = state.queues.get(&queue).unwrap().lock().await;
    let (idx, message) = queue
        .iter_mut()
        .enumerate()
        .find(|m| m.1.id == message_id)
        .ok_or("invalid message")?;

    dbg!(confirm);

    match confirm[0] {
        0 => {
            queue.remove(idx);
        }
        1 => message.inflight = false,
        // DLQ
        2 => {
            queue.remove(idx);
        }
        _ => return Err("invalid ack code".into()),
    }

    Ok(())
}
