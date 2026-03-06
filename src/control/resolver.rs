//! Custom snow CryptoResolver that uses big-endian nonce encoding for ChaChaPoly.
//!
//! Tailscale's control plane (`controlbase/conn.go`) encodes ChaChaPoly nonces
//! using big-endian byte order, while snow's default resolver uses little-endian.
//! Both produce identical output for nonce 0 (all zeros), so the handshake succeeds,
//! but nonce 1+ diverges, breaking the transport phase.
//!
//! This resolver delegates everything to snow's DefaultResolver except for the
//! ChaChaPoly cipher, which uses big-endian nonce encoding to match Tailscale.

use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit};
use snow::params::{CipherChoice, DHChoice, HashChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Random};

const TAGLEN: usize = 16;
const CIPHERKEYLEN: usize = 32;

/// A ChaChaPoly cipher that uses big-endian nonce encoding, matching Tailscale's
/// `controlbase/conn.go` implementation.
#[derive(Default)]
struct CipherChaChaPolyBE {
    key: [u8; 32],
}

impl Cipher for CipherChaChaPolyBE {
    fn name(&self) -> &'static str {
        "ChaChaPoly"
    }

    fn set(&mut self, key: &[u8]) {
        self.key.copy_from_slice(&key[..32]);
    }

    fn encrypt(&self, nonce: u64, authtext: &[u8], plaintext: &[u8], out: &mut [u8]) -> usize {
        // Big-endian nonce: 4 zero bytes + 8-byte BE counter (matches Tailscale)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());

        out[..plaintext.len()].copy_from_slice(plaintext);

        let tag = ChaCha20Poly1305::new(&self.key.into())
            .encrypt_in_place_detached(&nonce_bytes.into(), authtext, &mut out[..plaintext.len()])
            .unwrap();

        out[plaintext.len()..plaintext.len() + TAGLEN].copy_from_slice(&tag);

        plaintext.len() + TAGLEN
    }

    fn decrypt(
        &self,
        nonce: u64,
        authtext: &[u8],
        ciphertext: &[u8],
        out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        // Big-endian nonce: 4 zero bytes + 8-byte BE counter (matches Tailscale)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[4..].copy_from_slice(&nonce.to_be_bytes());

        let message_len = ciphertext.len() - TAGLEN;

        out[..message_len].copy_from_slice(&ciphertext[..message_len]);

        ChaCha20Poly1305::new(&self.key.into())
            .decrypt_in_place_detached(
                &nonce_bytes.into(),
                authtext,
                &mut out[..message_len],
                ciphertext[message_len..].into(),
            )
            .map_err(|_| snow::Error::Decrypt)?;

        Ok(message_len)
    }

    fn rekey(&mut self) {
        let mut ciphertext = [0u8; CIPHERKEYLEN + TAGLEN];
        let ciphertext_len = self.encrypt(u64::MAX, &[], &[0; CIPHERKEYLEN], &mut ciphertext);
        assert_eq!(ciphertext_len, ciphertext.len());
        self.set(&ciphertext[..CIPHERKEYLEN]);
    }
}

/// CryptoResolver that uses big-endian ChaChaPoly to match Tailscale's nonce encoding.
/// All other primitives (DH, Hash, RNG) delegate to snow's DefaultResolver.
pub struct TailscaleResolver {
    default: DefaultResolver,
}

impl TailscaleResolver {
    pub fn new() -> Self {
        Self {
            default: DefaultResolver::default(),
        }
    }
}

impl CryptoResolver for TailscaleResolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        self.default.resolve_rng()
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        self.default.resolve_dh(choice)
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        self.default.resolve_hash(choice)
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match *choice {
            CipherChoice::ChaChaPoly => Some(Box::new(CipherChaChaPolyBE::default())),
            _ => self.default.resolve_cipher(choice),
        }
    }
}
