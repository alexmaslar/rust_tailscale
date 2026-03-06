use bytes::BytesMut;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;
use tokio_rustls::client::TlsStream;

use super::noise::NoiseSession;

/// Tailscale Noise transport message type for session data.
const MSG_TYPE_RECORD: u8 = 0x04;
/// Header: 1 byte type + 2 byte BE length.
const HEADER_LEN: usize = 3;
/// Max frame (header + ciphertext): 4096 bytes.
const MAX_FRAME_SIZE: usize = 4096;
/// Max ciphertext per frame: 4093 bytes.
const MAX_CIPHERTEXT_SIZE: usize = MAX_FRAME_SIZE - HEADER_LEN;
/// ChaCha20Poly1305 auth tag overhead.
const AEAD_OVERHEAD: usize = 16;
/// Max plaintext per frame: 4076 bytes.
const MAX_PLAINTEXT_SIZE: usize = MAX_CIPHERTEXT_SIZE - AEAD_OVERHEAD;

/// A framed Noise-encrypted stream over TLS.
///
/// Implements `AsyncRead + AsyncWrite` so it can be used as a transport
/// for HTTP/2 (h2 crate). Each write is encrypted with Tailscale's frame format;
/// each read decrypts a framed ciphertext.
///
/// Frame format: `[1-byte type][2-byte BE ciphertext length][ciphertext]`
pub struct NoiseStream {
    inner: TlsStream<TcpStream>,
    session: NoiseSession,
    /// Buffered decrypted plaintext waiting to be read
    read_plaintext: BytesMut,
    /// Partial frame being read from the wire
    read_frame_buf: BytesMut,
    /// Expected ciphertext length (None = haven't read header yet)
    read_frame_len: Option<usize>,
    /// Buffered frame data to write (for partial writes)
    write_buf: BytesMut,
}

impl NoiseStream {
    pub fn new(inner: TlsStream<TcpStream>, session: NoiseSession) -> Self {
        Self {
            inner,
            session,
            read_plaintext: BytesMut::new(),
            read_frame_buf: BytesMut::new(),
            read_frame_len: None,
            write_buf: BytesMut::new(),
        }
    }
}

impl AsyncRead for NoiseStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // If we have buffered plaintext, return it
        if !this.read_plaintext.is_empty() {
            let to_copy = std::cmp::min(buf.remaining(), this.read_plaintext.len());
            buf.put_slice(&this.read_plaintext.split_to(to_copy));
            return Poll::Ready(Ok(()));
        }

        // Need to read a new frame from the wire
        loop {
            // Step 1: Read the 3-byte header if we don't have it
            if this.read_frame_len.is_none() {
                while this.read_frame_buf.len() < HEADER_LEN {
                    let mut tmp = [0u8; HEADER_LEN];
                    let remaining = HEADER_LEN - this.read_frame_buf.len();
                    let mut read_buf = ReadBuf::new(&mut tmp[..remaining]);
                    let inner = Pin::new(&mut this.inner);
                    match inner.poll_read(cx, &mut read_buf) {
                        Poll::Ready(Ok(())) => {
                            let filled = read_buf.filled();
                            if filled.is_empty() {
                                return Poll::Ready(Ok(()));
                            }
                            this.read_frame_buf.extend_from_slice(filled);
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }

                let header = this.read_frame_buf.split_to(HEADER_LEN);
                let msg_type = header[0];
                let ciphertext_len =
                    u16::from_be_bytes([header[1], header[2]]) as usize;

                tracing::debug!(
                    msg_type = format!("0x{:02x}", msg_type),
                    ciphertext_len,
                    "noise frame header"
                );

                if msg_type != MSG_TYPE_RECORD {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "unexpected noise frame type: 0x{:02x} (expected 0x{:02x})",
                            msg_type, MSG_TYPE_RECORD
                        ),
                    )));
                }

                if ciphertext_len == 0 || ciphertext_len > MAX_CIPHERTEXT_SIZE {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("invalid noise frame ciphertext length: {ciphertext_len}"),
                    )));
                }

                this.read_frame_len = Some(ciphertext_len);
                this.read_frame_buf.clear();
            }

            // Step 2: Read the encrypted frame body
            let frame_len = this.read_frame_len.unwrap();
            while this.read_frame_buf.len() < frame_len {
                let remaining = frame_len - this.read_frame_buf.len();
                let chunk_size = std::cmp::min(remaining, 8192);
                let mut tmp = vec![0u8; chunk_size];
                let mut read_buf = ReadBuf::new(&mut tmp);
                let inner = Pin::new(&mut this.inner);
                match inner.poll_read(cx, &mut read_buf) {
                    Poll::Ready(Ok(())) => {
                        let filled = read_buf.filled();
                        if filled.is_empty() {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "connection closed mid-frame",
                            )));
                        }
                        this.read_frame_buf.extend_from_slice(filled);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            // Step 3: Decrypt the frame
            let ciphertext = this.read_frame_buf.split_to(frame_len);
            this.read_frame_len = None;

            tracing::debug!(
                ciphertext_len = ciphertext.len(),
                ciphertext_hex = %hex::encode(&ciphertext[..std::cmp::min(32, ciphertext.len())]),
                "decrypting noise frame"
            );
            let plaintext = this.session.decrypt(&ciphertext).map_err(|e| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("noise decrypt failed: {e}"),
                )
            })?;

            if !plaintext.is_empty() {
                let to_copy = std::cmp::min(buf.remaining(), plaintext.len());
                buf.put_slice(&plaintext[..to_copy]);
                if to_copy < plaintext.len() {
                    this.read_plaintext
                        .extend_from_slice(&plaintext[to_copy..]);
                }
                return Poll::Ready(Ok(()));
            }
            // Empty plaintext frame — read another
        }
    }
}

impl AsyncWrite for NoiseStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // If we have a partial frame from a previous call, finish writing it first
        if !this.write_buf.is_empty() {
            while !this.write_buf.is_empty() {
                let inner = Pin::new(&mut this.inner);
                match inner.poll_write(cx, &this.write_buf) {
                    Poll::Ready(Ok(n)) => {
                        if n == 0 {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::WriteZero,
                                "write returned 0",
                            )));
                        }
                        let _ = this.write_buf.split_to(n);
                    }
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            // Fall through to process the new data in buf
        }

        // Chunk plaintext to fit in a single Noise frame
        let chunk = &buf[..std::cmp::min(buf.len(), MAX_PLAINTEXT_SIZE)];

        tracing::debug!(
            plaintext_len = chunk.len(),
            plaintext_hex = %hex::encode(&chunk[..std::cmp::min(32, chunk.len())]),
            "encrypting noise frame"
        );

        // Encrypt the plaintext
        let ciphertext = this.session.encrypt(chunk).map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("noise encrypt failed: {e}"),
            )
        })?;

        // Build framed message: [type][2-byte BE length][ciphertext]
        let ct_len = ciphertext.len() as u16;
        let mut frame = Vec::with_capacity(HEADER_LEN + ciphertext.len());
        frame.push(MSG_TYPE_RECORD);
        frame.extend_from_slice(&ct_len.to_be_bytes());
        frame.extend_from_slice(&ciphertext);

        // Write the entire frame
        let inner = Pin::new(&mut this.inner);
        match inner.poll_write(cx, &frame) {
            Poll::Ready(Ok(n)) => {
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "write returned 0",
                    )));
                }
                if n < frame.len() {
                    // Buffer the remainder for next poll_write
                    this.write_buf.extend_from_slice(&frame[n..]);
                }
                Poll::Ready(Ok(chunk.len()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
