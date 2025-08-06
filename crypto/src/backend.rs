use rand::{CryptoRng, RngCore};

use crate::error::{error, Result};

/// Backend trait for asymmetric encryption operations.
///
/// Implementors of this trait are able to encrypt and/or decrypt
/// the randomly generated AES key that protects the bulk of the data.
///
/// Only the relevant operation needs to be implemented for a given
/// type. For example public keys implement [`encrypt`] while private
/// keys implement [`decrypt`]. The other operation can keep the default
/// implementation which simply returns an error.
pub trait Backend {
    /// Size, in bytes, of the encrypted representation of the AES key.
    const ENCRYPTED_KEY_LEN: usize;

    /// Encrypt the provided AES key.
    fn encrypt<R: CryptoRng + RngCore>(&self, _rng: &mut R, _data: &[u8]) -> Result<Vec<u8>> {
        Err(error!(Other, "encryption not supported for this key"))
    }

    /// Decrypt the provided AES key.
    fn decrypt(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Err(error!(Other, "decryption not supported for this key"))
    }
}

// ---------------------------------------------------------------------
// RSA backend implementation
// ---------------------------------------------------------------------

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

/// RSA keys encrypt the AES key into a 256‑byte blob (2048‑bit RSA).
const RSA_ENC_LEN: usize = 256;

impl Backend for RsaPublicKey {
    const ENCRYPTED_KEY_LEN: usize = RSA_ENC_LEN;

    fn encrypt<R: CryptoRng + RngCore>(&self, rng: &mut R, data: &[u8]) -> Result<Vec<u8>> {
        self.encrypt(rng, Pkcs1v15Encrypt, data)
            .map_err(|e| error!(Other, "RSA Encryption error: {}", e))
    }
}

impl Backend for RsaPrivateKey {
    const ENCRYPTED_KEY_LEN: usize = RSA_ENC_LEN;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.decrypt(Pkcs1v15Encrypt, data)
            .map_err(|e| error!(Other, "RSA Decryption error: {}", e))
    }
}

// ---------------------------------------------------------------------
// Elliptic Curve backend implementation (P-256)
// ---------------------------------------------------------------------

use p256::{
    ecdh::{EphemeralSecret, SharedSecret},
    PublicKey as EcPublicKey, SecretKey as EcPrivateKey,
};
use p256::elliptic_curve::sec1::ToEncodedPoint;

/// For the EC backend we send the ephemeral public key (65 bytes,
/// uncompressed) concatenated with the XOR of the AES key and the
/// derived shared secret (32 bytes).
const EC_ENC_LEN: usize = 65 + 32;

impl Backend for EcPublicKey {
    const ENCRYPTED_KEY_LEN: usize = EC_ENC_LEN;

    fn encrypt<R: CryptoRng + RngCore>(&self, rng: &mut R, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != 32 {
            Err(error!(InvalidInput, "AES key must be 32 bytes"))?;
        }

        let ephemeral = EphemeralSecret::random(rng);
        let ephemeral_pub = EcPublicKey::from(&ephemeral);
        let shared = ephemeral.diffie_hellman(self);
        let shared_bytes = shared.raw_secret_bytes();

        let mut out = Vec::with_capacity(Self::ENCRYPTED_KEY_LEN);
        out.extend_from_slice(ephemeral_pub.to_encoded_point(false).as_bytes());

        for (a, b) in data.iter().zip(shared_bytes.as_slice()) {
            out.push(a ^ b);
        }

        Ok(out)
    }
}

impl Backend for EcPrivateKey {
    const ENCRYPTED_KEY_LEN: usize = EC_ENC_LEN;

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        if data.len() != Self::ENCRYPTED_KEY_LEN {
            Err(error!(InvalidInput, "invalid encrypted key length"))?;
        }

        let (ephemeral_pub_bytes, encrypted_key) = data.split_at(65);
        let ephemeral_pub = EcPublicKey::from_sec1_bytes(ephemeral_pub_bytes)
            .map_err(|e| error!(Other, "Invalid public key: {}", e))?;

        let shared = SharedSecret::new(&ephemeral_pub, self)
            .map_err(|e| error!(Other, "ECDH error: {}", e))?;
        let shared_bytes = shared.raw_secret_bytes();

        let mut key = Vec::with_capacity(32);
        for (a, b) in encrypted_key.iter().zip(shared_bytes.as_slice()) {
            key.push(a ^ b);
        }

        Ok(key)
    }
}

