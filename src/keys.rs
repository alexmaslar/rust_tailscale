use crate::error::{Result, TailscaleError};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use x25519_dalek::{PublicKey, StaticSecret};

/// A Curve25519 key pair used for machine or node identity.
#[derive(Clone)]
pub struct KeyPair {
    secret: StaticSecret,
    public: PublicKey,
}

impl KeyPair {
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn from_secret_bytes(bytes: [u8; 32]) -> Self {
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    pub fn secret_bytes(&self) -> [u8; 32] {
        self.secret.to_bytes()
    }

    pub fn public_bytes(&self) -> [u8; 32] {
        self.public.to_bytes()
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public
    }

    pub fn secret_key(&self) -> &StaticSecret {
        &self.secret
    }
}

impl std::fmt::Debug for KeyPair {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeyPair")
            .field("public", &base64::engine::general_purpose::STANDARD.encode(self.public.as_bytes()))
            .field("secret", &"[redacted]")
            .finish()
    }
}

use base64::Engine;

/// Machine key identifies this machine to the control server.
/// Persisted across restarts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl MachineKey {
    pub fn generate() -> Self {
        let kp = KeyPair::generate();
        Self {
            secret: kp.secret_bytes(),
            public: kp.public_bytes(),
        }
    }

    pub fn key_pair(&self) -> KeyPair {
        KeyPair::from_secret_bytes(self.secret)
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn public_key_string(&self) -> String {
        format!("mkey:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public))
    }
}

/// Node key is this node's WireGuard public key on the tailnet.
/// May be rotated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl NodeKey {
    pub fn generate() -> Self {
        let kp = KeyPair::generate();
        Self {
            secret: kp.secret_bytes(),
            public: kp.public_bytes(),
        }
    }

    pub fn key_pair(&self) -> KeyPair {
        KeyPair::from_secret_bytes(self.secret)
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn public_key_string(&self) -> String {
        format!("nodekey:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public))
    }
}

/// Disco key used for peer discovery and NAT traversal.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoKey {
    secret: [u8; 32],
    public: [u8; 32],
}

impl DiscoKey {
    pub fn generate() -> Self {
        let kp = KeyPair::generate();
        Self {
            secret: kp.secret_bytes(),
            public: kp.public_bytes(),
        }
    }

    pub fn public_bytes(&self) -> &[u8; 32] {
        &self.public
    }

    pub fn public_key_string(&self) -> String {
        format!("discokey:{}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(self.public))
    }
}

/// Parse a key from its string representation (e.g., "nodekey:base64data").
pub fn parse_key(s: &str) -> Result<(String, [u8; 32])> {
    let (prefix, data) = s
        .split_once(':')
        .ok_or_else(|| TailscaleError::Key(format!("invalid key format: {}", s)))?;

    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(data)
        .map_err(|e| TailscaleError::Key(format!("invalid base64: {}", e)))?;

    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| TailscaleError::Key("key must be 32 bytes".into()))?;

    Ok((prefix.to_string(), arr))
}
