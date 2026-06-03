//! A thin client for the helper IPC channel.

use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{HelperError, Result};
use crate::frame::{read_frame, write_frame};
use crate::protocol::{Request, Response};

/// A connected helper client over any bidirectional stream.
pub struct Client<S> {
    stream: S,
}

#[cfg(unix)]
impl Client<tokio::net::UnixStream> {
    /// Connect to a helper listening on the Unix socket at `path`.
    pub async fn connect(path: &std::path::Path) -> Result<Self> {
        Ok(Self {
            stream: crate::endpoint::connect(path).await?,
        })
    }
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Wrap an already-connected stream (e.g. for in-process tests).
    pub fn from_stream(stream: S) -> Self {
        Self { stream }
    }

    /// Send a request and read the response.
    pub async fn request(&mut self, req: Request) -> Result<Response> {
        write_frame(&mut self.stream, &req.encode()).await?;
        let frame = read_frame(&mut self.stream).await?;
        Response::decode(&frame)
    }

    /// Convenience: liveness check, returns the server's protocol version.
    pub async fn ping(&mut self) -> Result<u32> {
        match self.request(Request::Ping).await? {
            Response::Pong { version } => Ok(version),
            _ => Err(HelperError::Protocol("unexpected response to ping")),
        }
    }
}
