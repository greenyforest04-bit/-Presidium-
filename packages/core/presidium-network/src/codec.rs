//! Protobuf codec for the request-response protocol.

use std::io;

use async_trait::async_trait;
use futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use libp2p::request_response::Codec;
use presidium_proto::messages::{NetworkRequest, NetworkResponse};
use prost::Message;

/// Wire protocol id for direct unicast messages.
pub const REQUEST_RESPONSE_PROTOCOL: &str = "/presidium/request-response/0.1.0";

/// Maximum accepted frame size: 16 MiB.
const MAX_FRAME_SIZE: u64 = 16 * 1024 * 1024;

/// A length-prefixed protobuf codec for [`NetworkRequest`] / [`NetworkResponse`].
#[derive(Debug, Clone, Default)]
pub struct EnvelopeCodec;

#[async_trait]
impl Codec for EnvelopeCodec {
    type Protocol = String;
    type Request = NetworkRequest;
    type Response = NetworkResponse;

    async fn read_request<T>(&mut self, _: &Self::Protocol, io: &mut T) -> io::Result<Self::Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_frame(io).await?;
        NetworkRequest::decode(bytes.as_slice()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad request: {e}"))
        })
    }

    async fn read_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
    ) -> io::Result<Self::Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        let bytes = read_frame(io).await?;
        NetworkResponse::decode(bytes.as_slice()).map_err(|e| {
            io::Error::new(io::ErrorKind::InvalidData, format!("bad response: {e}"))
        })
    }

    async fn write_request<T>(&mut self, _: &Self::Protocol, io: &mut T, req: Self::Request) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &req.encode_to_vec()).await
    }

    async fn write_response<T>(
        &mut self,
        _: &Self::Protocol,
        io: &mut T,
        res: Self::Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        write_frame(io, &res.encode_to_vec()).await
    }
}

async fn read_frame<T>(io: &mut T) -> io::Result<Vec<u8>>
where
    T: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    io.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as u64;
    if len > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds size limit",
        ));
    }
    let mut buf = vec![0u8; len as usize];
    io.read_exact(&mut buf).await?;
    Ok(buf)
}

async fn write_frame<T>(io: &mut T, bytes: &[u8]) -> io::Result<()>
where
    T: AsyncWrite + Unpin + Send,
{
    if bytes.len() as u64 > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame exceeds size limit",
        ));
    }
    io.write_all(&(bytes.len() as u32).to_be_bytes()).await?;
    io.write_all(bytes).await?;
    io.close().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::io::Cursor;
    use presidium_proto::messages::NetworkEnvelope;

    #[tokio::test]
    async fn request_roundtrip() {
        let mut codec = EnvelopeCodec;
        let protocol = REQUEST_RESPONSE_PROTOCOL.to_string();
        let req = NetworkRequest {
            envelope: Some(NetworkEnvelope {
                kind: 1,
                conversation_id: b"conv-1".to_vec().into(),
                sender_device_id: vec![1, 2, 3].into(),
                timestamp: 42,
                encrypted_payload: vec![9, 9, 9].into(),
                mac: vec![1].into(),
                protocol_version: 1,
                nonce: vec![2].into(),
                signature: vec![3].into(),
            }),
        };
        let mut buf = Vec::new();
        let mut cursor = Cursor::new(&mut buf);
        codec.write_request(&protocol, &mut cursor, req.clone()).await.unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = codec.read_request(&protocol, &mut cursor).await.unwrap();
        assert_eq!(decoded.envelope, req.envelope);
    }

    #[tokio::test]
    async fn response_roundtrip() {
        let mut codec = EnvelopeCodec;
        let protocol = REQUEST_RESPONSE_PROTOCOL.to_string();
        let res = NetworkResponse {
            status: 1,
            ack_id: b"conv-1".to_vec().into(),
        };
        let mut buf = Vec::new();
        let mut cursor = Cursor::new(&mut buf);
        codec.write_response(&protocol, &mut cursor, res.clone()).await.unwrap();

        let mut cursor = Cursor::new(&buf[..]);
        let decoded = codec.read_response(&protocol, &mut cursor).await.unwrap();
        assert_eq!(decoded, res);
    }
}
