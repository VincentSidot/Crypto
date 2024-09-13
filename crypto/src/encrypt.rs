//! This module provides a writer that encrypts the data before writing it to the writer.
//!
//! The data is encrypted using AES-256-GCM. The AES key is encrypted using the RSA public key.
//!
//! The data is written to the writer in the following format:
//! ```plaintext
//! +-----------------+   +-----------------+   +-----------------+   +-----------------+   
//! |     AES Key     |   |    AES NONCE    |   |     AES Data    |   |     AES Data    |   
//! +-----------------+   +-----------------+   +-----------------+   +-----------------+   
//! |     RSA Enc     |   |                 |   |                 |   |                 |   ...
//! +-----------------+   +-----------------+   +-----------------+   +-----------------+   
//! |   AES KEY LEN   |   |  AES NONCE LEN  |   |   BUFFER_SIZE   |   |   BUFFER_SIZE   |  
//! +-----------------+   +-----------------+   +-----------------+   +-----------------+
//! ```
//!
//! The `BUFFER_SIZE` is the size of the buffer used to store the encrypted data.
//!
//! This module provides a writer that encrypts the data before writing it to the writer.
//! The `CryptoWriter` implements the `std::io::Write` trait. To allow seamless integration with existing
//! Rust code that uses `std::io::Write`.
//!
//! **Warning**: Currently the memeory of the struct is not locked. (This will be implemented in
//! the future)
//! So, the data can be read from the memory. (This is a security risk)
use super::{
    dbg_println,
    error::{error, Result},
    shared::{increment_nonce, setup_rng, Nonce},
};
use aes_gcm::{aead::Aead, AeadCore as _, Aes256Gcm, Key, KeyInit as _};
use rand::{CryptoRng, RngCore};
use rsa::{Pkcs1v15Encrypt, RsaPublicKey};
use std::io::Write as _;

fn generate_aes_key<R: CryptoRng + RngCore>(rng: &mut R) -> Key<Aes256Gcm> {
    Aes256Gcm::generate_key(rng)
}

/// A writer that encrypts the data before writing it to the writer.
///
/// The data is encrypted using AES-256-GCM.
/// The AES key is encrypted using the RSA public key.
///
/// The data is written to the writer in the following format:
/// ```plaintext
/// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
/// |     AES Key     |   |    AES NONCE    |   |     AES Data    |   |     AES Data    |   
/// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
/// |     RSA Enc     |   |                 |   |                 |   |                 |   ...
/// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
/// |   AES KEY LEN   |   |  AES NONCE LEN  |   |   BUFFER_SIZE   |   |   BUFFER_SIZE   |  
/// +-----------------+   +-----------------+   +-----------------+   +-----------------+
/// ```
///
/// The `BUFFER_SIZE` is the size of the buffer used to store the encrypted data.
pub struct CryptoWriter<W: std::io::Write, const BUFFER_SIZE: usize> {
    writer: W,
    nonce: Nonce,
    cipher: Aes256Gcm,
    buffer: [u8; BUFFER_SIZE],
    buffer_len: usize,
    has_been_flushed: bool,
}

impl<W: std::io::Write, const BUFFER_SIZE: usize> CryptoWriter<W, BUFFER_SIZE> {
    /// Create a new `CryptoWriter` instance.
    /// The `key` is used to encrypt the AES key.
    ///
    /// # Arguments
    /// - `writer`: The writer to write the encrypted data.
    /// - `key`: The RSA public key to encrypt the AES key.
    ///
    /// # Returns
    /// A `CryptoWriter` instance.
    ///
    /// # Errors
    /// - `Invalid Rsa Key`: If the RSA key is invalid.
    /// - `Io`: If an I/O error occurs. Details are provided in the error message.
    ///
    /// # Safety
    /// The caller must ensure that the `writer` is not used before the `CryptoWriter` instance
    /// is dropped.
    /// Also, the cryptographic schemes assume that the writer is not used before the creation of
    /// the `CryptoWriter` instance. (As the encrypted AES key and the nonce are written to the
    /// writer in the constructor.)
    ///
    /// Here is a diagram of the data written to the writer:
    ///
    /// ```plaintext
    /// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
    /// |     AES Key     |   |    AES NONCE    |   |     AES Data    |   |     AES Data    |   
    /// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
    /// |     RSA Enc     |   |                 |   |                 |   |                 |   ...
    /// +-----------------+   +-----------------+   +-----------------+   +-----------------+   
    /// |   AES KEY LEN   |   |  AES NONCE LEN  |   |   BUFFER_SIZE   |   |   BUFFER_SIZE   |  
    /// +-----------------+   +-----------------+   +-----------------+   +-----------------+
    /// ```
    ///
    pub fn new(writer: W, key: RsaPublicKey) -> Result<Self> {
        // TODO: memlock secrets in memory
        let mut rng = setup_rng();
        Self::new_with_rng(writer, key, &mut rng)
    }

    /// Create a new `CryptoWriter` instance with the given random number generator.
    /// The `key` is used to encrypt the AES key.
    ///
    /// # Arguments
    /// - `writer`: The writer to write the encrypted data.
    /// - `key`: The RSA public key to encrypt the AES key.
    /// - `rng`: The random number generator.
    ///
    /// # Returns
    /// A `CryptoWriter` instance.
    ///
    /// # Notes
    /// The random number generator must be cryptographically secure. And should implement the
    /// `CryptoRng` and `RngCore` traits. (From the `rand` crate)
    ///
    pub fn new_with_rng<R: CryptoRng + RngCore>(
        mut writer: W,
        key: RsaPublicKey,
        mut rng: R,
    ) -> Result<Self> {
        let aes_key = generate_aes_key(&mut rng);
        let nonce = Aes256Gcm::generate_nonce(&mut rng);

        {
            let raw_aes_key = aes_key.as_slice();
            let data = key
                .encrypt(&mut rng, Pkcs1v15Encrypt, raw_aes_key)
                .map_err(|e| error!(Other, "RSA Encryption error: {}", e))?;

            if writer.write(&data)? != data.len() {
                Err(error!(Other, "Failed to write the encrypted AES key"))?;
            };
            if writer.write(&nonce)? != nonce.len() {
                Err(error!(Other, "Failed to write the AES nonce"))?;
            };
        };
        let cipher = Aes256Gcm::new(&aes_key);

        Ok(Self {
            writer,
            cipher,
            nonce,
            buffer: [0; BUFFER_SIZE],
            buffer_len: 0,
            has_been_flushed: false,
        })
    }

    fn inner_flush(&mut self) -> Result<()> {
        if self.buffer_len == 0 {
            // Nothing to flush
            return Ok(());
        }
        dbg_println!("Block to encrypt: {}", self.buffer_len);
        let encrypted_data = self
            .cipher
            .encrypt(&self.nonce, &self.buffer[..self.buffer_len])
            .map_err(|e| error!(Other, "AES Encryption error: {}", e))?;
        dbg_println!("Block encrypted: {}", encrypted_data.len());
        if self.writer.write(&encrypted_data)? != encrypted_data.len() {
            Err(error!(Other, "Failed to write the encrypted data"))?;
        }; // Write the encrypted data to the writer

        // Reset the buffer
        self.buffer_len = 0;
        self.buffer = [0; BUFFER_SIZE];

        // Increment the nonce
        increment_nonce(&mut self.nonce);

        Ok(())
    }
}

/// Drop the `CryptoWriter` instance.
/// Flush the writer before dropping the `CryptoWriter` instance.
impl<W: std::io::Write, const BUFFER_SIZE: usize> Drop for CryptoWriter<W, BUFFER_SIZE> {
    /// Flush the writer before dropping the `CryptoWriter` instance.
    ///
    /// # Panics
    /// If an I/O error occurs while flushing the writer.
    /// If a Cryptographic error occurs while encrypting the data.
    ///
    /// # Notice
    /// The user should call `flush` before dropping the `CryptoWriter` instance to avoid panics if
    /// an I/O error occurs.
    ///
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            panic!("Failed to flush the writer: {}", e);
        }
    }
}

/// Implement the `Write` trait for the `CryptoWriter` struct.
/// This allows the `CryptoWriter` to be used as a writer to interact seamlessly with other
/// writers.
impl<W: std::io::Write, const BUFFER_SIZE: usize> std::io::Write for CryptoWriter<W, BUFFER_SIZE> {
    /// Write data to the writer.
    /// The data is appended to inner buffer and flushed when the buffer is full.
    ///
    /// ***Warning***: The data is not written to the writer until the buffer is full. (Or if the
    /// `flush` method is called.)
    ///
    /// # Arguments
    /// - `data`: The data to write.
    ///
    /// # Returns
    /// `Ok(())` if the data is written successfully.
    ///
    /// # Errors
    /// Errors are returned if an I/O error occurs while flushing the writer.
    ///
    // pub fn write(&mut self, data: &[u8]) -> Result<()> {}
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let data_len = buf.len();

        if self.buffer_len + data_len < BUFFER_SIZE {
            self.buffer[self.buffer_len..self.buffer_len + data_len].copy_from_slice(buf);
            self.buffer_len += data_len;
            Ok(data_len)
        } else {
            let remaining = BUFFER_SIZE - self.buffer_len;
            self.buffer[self.buffer_len..].copy_from_slice(&buf[..remaining]);
            self.buffer_len = BUFFER_SIZE;
            self.inner_flush()?;
            {
                let mut data = &buf[remaining..];
                loop {
                    if data.len() < BUFFER_SIZE {
                        self.buffer[..data.len()].copy_from_slice(data);
                        self.buffer_len = data.len();
                        break Ok(data_len);
                    } else {
                        let (left, right) = data.split_at(BUFFER_SIZE);
                        self.buffer.copy_from_slice(left);
                        self.buffer_len = BUFFER_SIZE;
                        self.inner_flush()?;
                        data = right;
                    }
                }
            }
        }
    }

    /// Flush the writer.
    /// The data in the buffer is written to the writer.
    /// The writer is dropped after the data is written. (Which means that the writer is closed.)
    ///
    /// This method should be called before dropping the `CryptoWriter` instance.
    /// This method drops the `CryptoWriter` instance because we don't want miss-alignment in the
    /// data written to the writer.
    ///
    fn flush(&mut self) -> std::io::Result<()> {
        if self.has_been_flushed {
            Err(error!(Other, "The writer has already been flushed"))?;
        }
        self.inner_flush()?;
        self.writer.flush()?;
        self.has_been_flushed = true;
        Ok(())
    }
}
