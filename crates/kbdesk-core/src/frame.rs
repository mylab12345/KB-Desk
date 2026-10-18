//! Length-prefixed frame reader/writer over any async byte stream.

use anyhow::{bail, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Control payload (JSON).
pub const KIND_CONTROL: u8 = 0x01;
/// Video payload (binary screen frame).
pub const KIND_VIDEO: u8 = 0x02;

/// Upper bound on a single frame, to protect against hostile peers.
pub const MAX_MESSAGE: usize = 64 * 1024 * 1024;

/// A raw frame: a one-byte kind plus its payload.
#[derive(Debug, Clone)]
pub struct Packet {
    pub kind: u8,
    pub payload: Vec<u8>,
}

/// Write one frame: `u32` big-endian length (kind + payload), kind, payload.
pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    kind: u8,
    payload: &[u8],
) -> Result<()> {
    let len = payload.len() + 1;
    if len > MAX_MESSAGE {
        bail!("outgoing frame too large: {len} bytes");
    }
    writer.write_all(&(len as u32).to_be_bytes()).await?;
    writer.write_all(&[kind]).await?;
    writer.write_all(payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one frame written by [`write_packet`].
pub async fn read_packet<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Packet> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let len = u32::from_be_bytes(len_bytes) as usize;
    if len == 0 {
        bail!("invalid frame length 0");
    }
    if len > MAX_MESSAGE {
        bail!("incoming frame too large: {len} bytes");
    }
    let mut kind = [0u8; 1];
    reader.read_exact(&mut kind).await?;
    let mut payload = vec![0u8; len - 1];
    reader.read_exact(&mut payload).await?;
    Ok(Packet {
        kind: kind[0],
        payload,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_control_and_video_frames() {
        let (mut client, mut server) = tokio::io::duplex(1024);

        write_packet(&mut client, KIND_CONTROL, b"hello").await.unwrap();
        write_packet(&mut client, KIND_VIDEO, b"\x00\x01\x02").await.unwrap();

        let first = read_packet(&mut server).await.unwrap();
        assert_eq!(first.kind, KIND_CONTROL);
        assert_eq!(first.payload, b"hello");

        let second = read_packet(&mut server).await.unwrap();
        assert_eq!(second.kind, KIND_VIDEO);
        assert_eq!(second.payload, b"\x00\x01\x02");
    }

    #[tokio::test]
    async fn rejects_zero_length_frame() {
        let (mut client, mut server) = tokio::io::duplex(16);
        client.write_all(&0u32.to_be_bytes()).await.unwrap();
        client.flush().await.unwrap();
        assert!(read_packet(&mut server).await.is_err());
    }
}
