use std::{
    collections::{HashMap, HashSet},
    fs::File,
    io::BufReader,
    pin::pin,
    sync::Arc,
};

use broke_but_quick::{
    read_message, read_message_fixed, write_message, write_message_fixed, Consume, MessageAck,
    OpenMessage, Publish, PublishConfirm,
};
use quinn::{Connecting, Endpoint, RecvStream, SendStream, ServerConfig};
use sled::transaction::{ConflictableTransactionError, TransactionError};
use tokio::sync::{Mutex, Notify};

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

    let db: sled::Db = sled::Config::new().path("bbq").open()?;

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
            (queue_name1, QueueState::default()),
            (queue_name2, QueueState::default()),
        ]),
        db,
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
    queues: HashMap<QueueName, QueueState>,
    db: sled::Db,
}

struct ExchangesState {
    routes: HashMap<Route, Vec<QueueName>>,
}

#[derive(Default)]
struct QueueState {
    notify: Notify,
    messages: Mutex<Vec<MessageState>>,
}

struct ConnectionState {
    messages: Mutex<HashSet<(QueueName, uuid::Uuid)>>,
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

    let conn_state = Arc::new(ConnectionState {
        messages: Mutex::default(),
    });

    loop {
        match connection.accept_bi().await {
            Ok((send, recv)) => {
                tokio::spawn(handle_stream(state.clone(), conn_state.clone(), send, recv))
            }
            Err(e) => {
                for (queue_name, message_id) in conn_state.messages.lock().await.drain() {
                    let queue = state.queues.get(&queue_name).unwrap();
                    let mut message_lock = queue.messages.lock().await;
                    if let Some(message) = message_lock.iter_mut().find(|m| m.id == message_id) {
                        message.inflight = false;
                    }
                }

                return Err(e.into());
            }
        };

        println!("connection continue {:?}", connection.rtt());
    }
}

async fn handle_stream(
    state: Arc<SharedState>,
    conn_state: Arc<ConnectionState>,
    send: SendStream,
    recv: RecvStream,
) {
    match handle_stream_inner(state, conn_state, send, recv).await {
        Ok(()) => {}
        Err(e) => {
            eprintln!("error handling stream {e:?}");
        }
    }
}

async fn handle_stream_inner(
    state: Arc<SharedState>,
    conn_state: Arc<ConnectionState>,
    send: SendStream,
    mut recv: RecvStream,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("new stream {}", send.id());

    let message = read_message::<OpenMessage>(&mut recv).await?;

    match message.get() {
        OpenMessage::Publish(publish) => handle_stream_publish(state, send, publish).await?,
        OpenMessage::Consume(consume) => {
            handle_stream_consume(state, conn_state, send, recv, consume).await?
        }
    }

    Ok(())
}

async fn handle_stream_publish(
    state: Arc<SharedState>,
    mut send: SendStream,
    publish: &Publish<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Publish {
        exchange,
        routing_key,
        message,
    } = *publish;
    let message_str = String::from_utf8_lossy(message);

    println!("{exchange} {routing_key} {message_str}");

    let exchange = state.exchanges.get(exchange).ok_or("unknown exchange")?;
    let queues = exchange.routes.get(routing_key).ok_or("unknown route")?;
    for queue in queues {
        let message_id = uuid::Uuid::new_v4();

        let mut key = Vec::new();
        key.extend_from_slice(queue.as_bytes());
        key.extend_from_slice(&[0]);
        key.extend_from_slice(message_id.as_bytes());

        state.db.insert(key, message)?;
        state.db.flush_async().await?;

        let queue = state.queues.get(queue).unwrap();

        queue.messages.lock().await.push(MessageState {
            id: message_id,
            inflight: false,
            payload: message.to_owned(),
        });

        queue.notify.notify_one();
    }

    for entry in state.db.iter() {
        let (key, _) = entry?;
        println!("{}", String::from_utf8_lossy(&key));
    }

    write_message_fixed(&PublishConfirm::Ack, &mut send, &mut [0; 1]).await?;
    send.finish().await?;

    Ok(())
}

async fn handle_stream_consume(
    state: Arc<SharedState>,
    conn_state: Arc<ConnectionState>,
    mut send: SendStream,
    mut recv: RecvStream,
    consume: &Consume<'_>,
) -> Result<(), Box<dyn std::error::Error>> {
    let queue_name = consume.queue;
    dbg!(&queue_name);

    let acquired = state.db.open_tree("acquired")?;

    let mut key = Vec::new();
    key.extend_from_slice(queue_name.as_bytes());
    key.extend_from_slice(&[0]);

    use sled::transaction::Transactional;
    let res = (&*state.db, &acquired).transaction(|(message, acquired)| {
        if let Some(entry) = state.db.range((&*key)..).next() {
            let (key2, value) = entry?;
            if let Some(id) = key2.strip_prefix(&*key) {
                let message_id = uuid::Uuid::from_bytes(id.try_into().unwrap());
                dbg!(message_id);

                let message = message.remove(&key2)?.unwrap();
                acquired.insert(&key2, message)?;
                Ok((message_id, value))
            } else {
                Err(ConflictableTransactionError::Abort(()))
            }
        } else {
            Err(ConflictableTransactionError::Abort(()))
        }
    });

    match res {
        Ok((message_id, value)) => {
            println!("{message_id} {}", String::from_utf8_lossy(&value));
        }
        Err(TransactionError::Abort(())) => return Err("abort".into()),
        Err(TransactionError::Storage(e)) => return Err(e.into()),
    }

    for entry in state.db.iter() {
        let (key, _) = entry?;
        println!("entry {}", String::from_utf8_lossy(&key));
    }
    for entry in acquired.iter() {
        let (key, _) = entry?;
        println!("acquired {}", String::from_utf8_lossy(&key));
    }

    let queue = state.queues.get(queue_name).unwrap();
    let message = loop {
        let mut notified = pin!(queue.notify.notified());
        notified.as_mut().enable();

        let mut conn_state = conn_state.messages.lock().await;
        let mut message_lock = queue.messages.lock().await;

        let message = message_lock.iter_mut().find(|m| !m.inflight);

        match message {
            Some(message) => {
                conn_state.insert((queue_name.to_owned(), message.id));
                dbg!(&conn_state);
                message.inflight = true;

                break message.clone();
            }
            None => {
                drop(message_lock);
                notified.await
            }
        };
    };

    let message_id = message.id;
    write_message(&*message.payload, &mut send).await?;
    send.finish().await?;

    let confirm: MessageAck = read_message_fixed(&mut recv, &mut [0; 1]).await?;

    let mut conn_state = conn_state.messages.lock().await;
    let mut messages = queue.messages.lock().await;
    let (idx, message) = messages
        .iter_mut()
        .enumerate()
        .find(|m| m.1.id == message_id)
        .ok_or("invalid message")?;

    match dbg!(confirm) {
        MessageAck::Ack => {
            messages.remove(idx);
        }
        MessageAck::Nack => message.inflight = false,
        // DLQ
        MessageAck::Reject => {
            messages.remove(idx);
        }
    }

    conn_state.remove(&(queue_name.to_owned(), message_id));
    dbg!(&conn_state);

    Ok(())
}
