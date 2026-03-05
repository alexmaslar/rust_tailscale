use bytes::{BufMut, BytesMut};

use crate::error::{Result, TailscaleError};

// Frame type constants
const FRAME_SERVER_KEY: u8 = 0x01;
const FRAME_CLIENT_INFO: u8 = 0x02;
const FRAME_SEND_PACKET: u8 = 0x04;
const FRAME_RECV_PACKET: u8 = 0x05;
const FRAME_KEEP_ALIVE: u8 = 0x06;
const FRAME_PEER_GONE: u8 = 0x08;
const FRAME_PEER_PRESENT: u8 = 0x09;
const FRAME_SERVER_INFO: u8 = 0x0a;

#[derive(Debug, Clone)]
pub enum DerpFrame {
    ServerKey { key: [u8; 32] },
    ClientInfo { client_public_key: [u8; 32], info: Vec<u8> },
    SendPacket { dst_key: [u8; 32], payload: Vec<u8> },
    RecvPacket { src_key: [u8; 32], payload: Vec<u8> },
    KeepAlive,
    PeerGone { peer_key: [u8; 32] },
    PeerPresent { peer_key: [u8; 32] },
    ServerInfo { info: Vec<u8> },
}

impl DerpFrame {
    pub fn frame_type(&self) -> u8 {
        match self {
            DerpFrame::ServerKey { .. } => FRAME_SERVER_KEY,
            DerpFrame::ClientInfo { .. } => FRAME_CLIENT_INFO,
            DerpFrame::SendPacket { .. } => FRAME_SEND_PACKET,
            DerpFrame::RecvPacket { .. } => FRAME_RECV_PACKET,
            DerpFrame::KeepAlive => FRAME_KEEP_ALIVE,
            DerpFrame::PeerGone { .. } => FRAME_PEER_GONE,
            DerpFrame::PeerPresent { .. } => FRAME_PEER_PRESENT,
            DerpFrame::ServerInfo { .. } => FRAME_SERVER_INFO,
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.frame_type());

        match self {
            DerpFrame::ServerKey { key } => {
                buf.put_u32(32);
                buf.put_slice(key);
            }
            DerpFrame::ClientInfo { client_public_key, info } => {
                let len = 32 + info.len();
                buf.put_u32(len as u32);
                buf.put_slice(client_public_key);
                buf.put_slice(info);
            }
            DerpFrame::SendPacket { dst_key, payload } => {
                let len = 32 + payload.len();
                buf.put_u32(len as u32);
                buf.put_slice(dst_key);
                buf.put_slice(payload);
            }
            DerpFrame::RecvPacket { src_key, payload } => {
                let len = 32 + payload.len();
                buf.put_u32(len as u32);
                buf.put_slice(src_key);
                buf.put_slice(payload);
            }
            DerpFrame::KeepAlive => {
                buf.put_u32(0);
            }
            DerpFrame::PeerGone { peer_key } => {
                buf.put_u32(32);
                buf.put_slice(peer_key);
            }
            DerpFrame::PeerPresent { peer_key } => {
                buf.put_u32(32);
                buf.put_slice(peer_key);
            }
            DerpFrame::ServerInfo { info } => {
                buf.put_u32(info.len() as u32);
                buf.put_slice(info);
            }
        }

        buf.to_vec()
    }

    pub fn decode(buf: &[u8]) -> Result<(DerpFrame, usize)> {
        if buf.len() < 5 {
            return Err(TailscaleError::Derp("frame too short for header".into()));
        }

        let frame_type = buf[0];
        let payload_len = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]) as usize;
        let total_len = 5 + payload_len;

        if buf.len() < total_len {
            return Err(TailscaleError::Derp(format!(
                "incomplete frame: need {} bytes, have {}",
                total_len,
                buf.len()
            )));
        }

        let payload = &buf[5..total_len];

        let frame = match frame_type {
            FRAME_SERVER_KEY => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("ServerKey frame too short".into()));
                }
                let mut key = [0u8; 32];
                key.copy_from_slice(&payload[..32]);
                DerpFrame::ServerKey { key }
            }
            FRAME_CLIENT_INFO => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("ClientInfo frame too short".into()));
                }
                let mut client_public_key = [0u8; 32];
                client_public_key.copy_from_slice(&payload[..32]);
                let info = payload[32..].to_vec();
                DerpFrame::ClientInfo { client_public_key, info }
            }
            FRAME_SEND_PACKET => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("SendPacket frame too short".into()));
                }
                let mut dst_key = [0u8; 32];
                dst_key.copy_from_slice(&payload[..32]);
                let data = payload[32..].to_vec();
                DerpFrame::SendPacket { dst_key, payload: data }
            }
            FRAME_RECV_PACKET => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("RecvPacket frame too short".into()));
                }
                let mut src_key = [0u8; 32];
                src_key.copy_from_slice(&payload[..32]);
                let data = payload[32..].to_vec();
                DerpFrame::RecvPacket { src_key, payload: data }
            }
            FRAME_KEEP_ALIVE => DerpFrame::KeepAlive,
            FRAME_PEER_GONE => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("PeerGone frame too short".into()));
                }
                let mut peer_key = [0u8; 32];
                peer_key.copy_from_slice(&payload[..32]);
                DerpFrame::PeerGone { peer_key }
            }
            FRAME_PEER_PRESENT => {
                if payload.len() < 32 {
                    return Err(TailscaleError::Derp("PeerPresent frame too short".into()));
                }
                let mut peer_key = [0u8; 32];
                peer_key.copy_from_slice(&payload[..32]);
                DerpFrame::PeerPresent { peer_key }
            }
            FRAME_SERVER_INFO => {
                let info = payload.to_vec();
                DerpFrame::ServerInfo { info }
            }
            _ => {
                return Err(TailscaleError::Derp(format!(
                    "unknown frame type: 0x{:02x}",
                    frame_type
                )));
            }
        };

        Ok((frame, total_len))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keepalive_roundtrip() {
        let frame = DerpFrame::KeepAlive;
        let encoded = frame.encode();
        let (decoded, consumed) = DerpFrame::decode(&encoded).unwrap();
        assert_eq!(consumed, 5);
        assert!(matches!(decoded, DerpFrame::KeepAlive));
    }

    #[test]
    fn test_server_key_roundtrip() {
        let key = [42u8; 32];
        let frame = DerpFrame::ServerKey { key };
        let encoded = frame.encode();
        let (decoded, consumed) = DerpFrame::decode(&encoded).unwrap();
        assert_eq!(consumed, 5 + 32);
        match decoded {
            DerpFrame::ServerKey { key: k } => assert_eq!(k, key),
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn test_send_packet_roundtrip() {
        let dst_key = [1u8; 32];
        let payload = vec![0xDE, 0xAD, 0xBE, 0xEF];
        let frame = DerpFrame::SendPacket { dst_key, payload: payload.clone() };
        let encoded = frame.encode();
        let (decoded, consumed) = DerpFrame::decode(&encoded).unwrap();
        assert_eq!(consumed, 5 + 32 + 4);
        match decoded {
            DerpFrame::SendPacket { dst_key: k, payload: p } => {
                assert_eq!(k, dst_key);
                assert_eq!(p, payload);
            }
            _ => panic!("wrong frame type"),
        }
    }

    #[test]
    fn test_incomplete_frame() {
        let buf = [0x01, 0x00, 0x00]; // too short for header
        assert!(DerpFrame::decode(&buf).is_err());
    }
}
