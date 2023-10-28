use bincode::Options;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use yoke::{Yoke, Yokeable};

fn options() -> impl Options {
    bincode::DefaultOptions::new()
        .with_little_endian()
        .with_varint_encoding()
        .reject_trailing_bytes()
        .with_no_limit()
}

/// Writes a framed message
pub async fn write_message(
    t: &(impl Serialize + ?Sized),
    w: &mut (impl AsyncWrite + Unpin),
) -> Result<(), Box<dyn std::error::Error>> {
    let message = options().serialize(t)?;
    w.write_all(&(message.len() as u64).to_le_bytes()).await?;
    w.write_all(&message).await?;
    Ok(())
}

/// Writes an unframed message of a fixed known size
pub async fn write_message_fixed(
    t: &(impl Serialize + ?Sized),
    w: &mut (impl AsyncWrite + Unpin),
    buf: &mut [u8],
) -> Result<(), Box<dyn std::error::Error>> {
    options().serialize_into(&mut *buf, t)?;
    w.write_all(buf).await?;
    Ok(())
}

/// Reads a framed message and zero-copy deserialises it
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

/// Reads an unframed message of a fixed known size into the buffer and deserialises it
pub async fn read_message_fixed<'de, T: Deserialize<'de>>(
    r: &mut (impl AsyncRead + Unpin),
    buf: &'de mut [u8],
) -> Result<T, Box<dyn std::error::Error>> {
    r.read_exact(buf).await?;
    Ok(options().deserialize(buf)?)
}
