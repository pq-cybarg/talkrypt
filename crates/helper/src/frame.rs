//! Length-prefixed async framing over the local IPC stream: `u32 BE len ‖ body`.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{HelperError, Result};

/// Maximum single helper frame. Helper payloads are tiny (keys, passphrases),
/// so this is a generous ceiling that still bounds a hostile allocation.
pub const MAX_FRAME: usize = 4 * 1024 * 1024;

/// Write `body` as one length-prefixed frame and flush.
pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, body: &[u8]) -> Result<()> {
    if body.len() > MAX_FRAME {
        return Err(HelperError::FrameTooLarge(body.len()));
    }
    w.write_all(&(body.len() as u32).to_be_bytes()).await?;
    w.write_all(body).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed frame. A clean EOF before any bytes is reported as
/// [`HelperError::Closed`] (peer hung up between requests).
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Err(HelperError::Closed),
        Err(e) => return Err(e.into()),
    }
    let n = u32::from_be_bytes(len) as usize;
    if n > MAX_FRAME {
        return Err(HelperError::FrameTooLarge(n));
    }
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
