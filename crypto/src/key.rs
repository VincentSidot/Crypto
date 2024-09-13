//! The `key` module provides the `RsaKeys` struct. Which holds the RSA public and private keys.
//! The keys can be generated, loaded, and serialized.
//!
//! This module is part of the `crypto` crate. The `crypto` crate provides functionality for
//! encrypting and decrypting data using AES-256-GCM. The data is encrypted using a randomly
//! generated AES key. The AES key is then encrypted using the RSA public key. The encrypted data is
//! written to a writer in a specific format. The data is decrypted using the RSA private key.
//!
//! Currently, the key length is fixed at 2048 bits. (Temporary solution)
//!
//! **Warning**: Currently the memeory of the struct is not locked. (This will be implemented in
//! the future)
//! So, the data can be read from the memory. (This is a security risk)
use super::shared::{setup_rng, RSA_KEY_LEN};
use rand::{CryptoRng, RngCore};
use rsa::{
    pkcs1::{
        DecodeRsaPrivateKey as _, DecodeRsaPublicKey as _, EncodeRsaPrivateKey as _,
        EncodeRsaPublicKey as _,
    },
    pkcs8::der::zeroize::Zeroizing,
    RsaPrivateKey, RsaPublicKey,
};

/// A struct that holds the RSA public and private keys.
/// The keys can be generated, loaded, and serialized.
///
/// Currently the key length is fixed at 2048 bits. (Temporary solution)
///
pub struct RsaKeys {
    pub public_key: Option<RsaPublicKey>,
    pub private_key: Option<RsaPrivateKey>,
}

impl RsaKeys {
    /// Generate a new RSA key pair.
    /// The key length is 2048 bits. (Temporary solution)
    ///
    /// # Returns
    /// A new RSA key pair.
    ///
    pub fn generate() -> Result<Self, Box<dyn std::error::Error>> {
        let mut rng = setup_rng();
        Self::generate_with_rng(&mut rng)
    }

    /// Generate a new RSA key pair with the given random number generator.
    /// The key length is 2048 bits. (Temporary solution)
    ///
    /// # Arguments
    /// - `rng`: The random number generator.
    ///
    /// # Note
    /// The random number generator must be cryptographically secure. And should implement the
    /// `CryptoRng` and `RngCore` traits. (From the `rand` crate)
    ///
    pub fn generate_with_rng<R: CryptoRng + RngCore>(
        rng: &mut R,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let priv_key = RsaPrivateKey::new(rng, RSA_KEY_LEN)?;
        let pub_key = RsaPublicKey::from(&priv_key);

        Ok(Self {
            public_key: Some(pub_key),
            private_key: Some(priv_key),
        })
    }

    /// Create a new `RsaKeys` instance from the given private key.
    ///
    /// # Arguments
    /// - `private_key`: The RSA private key.
    ///
    pub fn from_private_key(private_key: RsaPrivateKey) -> Self {
        let public_key = RsaPublicKey::from(&private_key);
        Self {
            public_key: Some(public_key),
            private_key: Some(private_key),
        }
    }

    /// Convert the private key to a PEM formatted string.
    ///
    /// # Returns
    /// The private key in PEM format.
    ///
    /// # Errors
    /// If the private key is not found.
    ///
    pub fn private_key_to_pem(&self) -> Result<Zeroizing<String>, Box<dyn std::error::Error>> {
        match &self.private_key {
            Some(private_key) => Ok(private_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)?),
            None => Err("private key not found".into()),
        }
    }

    /// Convert the public key to a PEM formatted string.
    ///
    /// # Returns
    /// The public key in PEM format.
    ///
    /// # Errors
    /// If the public key is not found.
    ///
    pub fn public_key_to_pem(&self) -> Result<String, Box<dyn std::error::Error>> {
        match &self.public_key {
            Some(public_key) => Ok(public_key.to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)?),
            None => Err("public key not found".into()),
        }
    }

    /// Create a new `RsaKeys` instance from the given PEM formatted key.
    ///
    /// # Arguments
    /// - `pem`: The PEM formatted private key.
    ///
    /// # Returns
    /// A new `RsaKeys` instance. With both the public and private keys. (Public key is derived
    /// from the private key)
    ///
    /// # Errors
    /// If the key is invalid.
    ///
    pub fn from_key_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        let public_key = RsaPublicKey::from(&private_key);
        Ok(Self {
            public_key: Some(public_key),
            private_key: Some(private_key),
        })
    }

    /// Create a new `RsaKeys` instance from the given PEM formatted private key.
    ///
    /// # Arguments
    /// - `pem`: The PEM formatted private key.
    ///
    /// # Returns
    /// A new `RsaKeys` instance. With only the private key.
    ///
    /// # Errors
    /// If the key is invalid.
    ///
    pub fn from_private_key_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let private_key = RsaPrivateKey::from_pkcs1_pem(pem)?;
        Ok(Self {
            public_key: None,
            private_key: Some(private_key),
        })
    }

    /// Create a new `RsaKeys` instance from the given PEM formatted public key.
    ///
    /// # Arguments
    /// - `pem`: The PEM formatted public key.
    ///
    /// # Returns
    /// A new `RsaKeys` instance. With only the public key.
    ///
    pub fn from_public_key_pem(pem: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let public_key = RsaPublicKey::from_pkcs1_pem(pem)?;
        Ok(Self {
            public_key: Some(public_key),
            private_key: None,
        })
    }
}
