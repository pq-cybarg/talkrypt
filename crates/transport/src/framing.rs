//! Shared length-prefixed framing over any tokio `AsyncRead`/`AsyncWrite`.
//!
//! `u32` big-endian length prefix, bounded by `talkrypt_wire::MAX_FRAME`.
//! Used by both the TCP transport and the Arti (`DataStream`) transport, since
//! Arti's `DataStream` implements tokio's async IO traits.

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use talkrypt_wire::MAX_FRAME;

use crate::{Result, TransportError};

pub(crate) async fn write_frame<W: AsyncWriteExt + Unpin>(w: &mut W, frame: &[u8]) -> Result<()> {
    if frame.len() > MAX_FRAME {
        return Err(TransportError::Io("frame exceeds MAX_FRAME".into()));
    }
    w.write_all(&(frame.len() as u32).to_be_bytes())
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    w.write_all(frame)
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    w.flush()
        .await
        .map_err(|e| TransportError::Io(e.to_string()))?;
    Ok(())
}

pub(crate) async fn read_frame<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    match r.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(TransportError::Closed)
        }
        Err(e) => return Err(TransportError::Io(e.to_string())),
    }
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        return Err(TransportError::Io("frame exceeds MAX_FRAME".into()));
    }
    let mut buf = vec![0u8; len];
    r.read_exact(&mut buf)
        .await
        .map_err(|_| TransportError::Closed)?;
    Ok(buf)
}
