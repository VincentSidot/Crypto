//! This module contains the `CryptoReader` struct that decrypts data read from an underlying reader.
//!
//! The data is decrypted using AES-256-GCM. The AES key is decrypted using the RSA private key.
//!
//! The data is read from the reader in the following format:
//!
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
//! This module contains the `CryptoReader` struct that decrypts data read from an underlying reader.
//! The `CryptoReader` implements the `std::io::Read` trait. To allow seamless integration with existing
//! Rust code that uses `std::io::Read`.
//!
//! **Warning**: Currently the memeory of the struct is not locked. (This will be implemented in
//! the future)
//! So, the data can be read from the memory. (This is a security risk)
use super::{
    dbg_println,
    error::{error, Result},
    shared::{increment_nonce, Nonce, AES_AUTH_TAG_LEN, AES_KEY_LEN, AES_NONCE_LEN},
};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit as _};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

macro_rules! min {
    ($($args:expr),*) => {
        min!(@inner $($args),*)
    };
    (@inner $first:expr, $($rest:expr),*) => {
        std::cmp::min($first, min!(@inner $($rest),*))
    };
    (@inner $only:expr) => {
        $only
    };
}

/// A reader that decrypts data read from an underlying reader.
///
/// The data is decrypted using AES-256-GCM.
/// The AES key is decrypted using the RSA private key.
///
/// The data is read from the reader in the following format:
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
pub struct CryptoReader<R: std::io::Read, const BUFFER_SIZE: usize> {
    reader: R,
    nonce: Nonce,
    cipher: Aes256Gcm,
    enc_buffer_len: usize,
    buffer_len: usize,
    enc_buffer: Vec<u8>,
    // auth_buffer: [u8; AES_AUTH_TAG_LEN],
    buffer: [u8; BUFFER_SIZE],
}

impl<R: std::io::Read, const BUFFER_SIZE: usize> CryptoReader<R, BUFFER_SIZE> {
    /// Create a new `CryptoReader` instance.
    /// The `key` is used to decrypt the AES key.
    ///
    /// # Arguments
    /// - `reader`: The reader from which encrypted data is read.
    /// - `key`: The RSA private key to decrypt the AES key.
    ///
    /// # Returns
    /// A `CryptoReader` instance.
    ///
    /// # Errors
    /// - `Invalid Rsa Key`: If the RSA key is invalid.
    /// - `Io`: If an I/O error occurs. Details are provided in the error message.
    ///
    /// # Safety
    /// The caller must ensure that the `reader` is not used before the `CryptoReader` instance
    /// is dropped.
    /// Also, the cryptographic schemes assume that the reader is not used before the creation of
    /// the `CryptoReader` instance. (As the decrypted AES key and the nonce are written to the
    /// reader in the constructor.)
    ///
    /// Here is a diagram of the data read from the reader:
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
    pub fn new(mut reader: R, key: RsaPrivateKey) -> Result<Self> {
        let cipher = {
            let buffer = &mut [0; AES_KEY_LEN];
            reader.read_exact(buffer)?;

            // Decrypt the AES key
            let raw_aes_key = key
                .decrypt(Pkcs1v15Encrypt, buffer)
                .map_err(|e| error!(Other, "RSA Decryption error: {}", e))?;

            let aes_key = Key::<Aes256Gcm>::from_slice(&raw_aes_key);
            Aes256Gcm::new(aes_key)
        };
        let nonce = {
            let buffer = &mut [0; AES_NONCE_LEN];
            reader.read_exact(buffer)?;
            *Nonce::from_slice(buffer.as_slice())
        };

        Ok(Self {
            reader,
            nonce,
            cipher,
            enc_buffer: vec![0; BUFFER_SIZE + AES_AUTH_TAG_LEN],
            buffer: [0; BUFFER_SIZE],
            enc_buffer_len: 0,
            buffer_len: 0,
        })
    }

    /// Decrypt the data read from the reader.
    fn decrypt_buffer(&mut self) -> Result<()> {
        assert!(self.enc_buffer.len() > AES_AUTH_TAG_LEN);
        dbg_println!(
            "Block to decrypt: {} | {}",
            self.enc_buffer.len(),
            self.enc_buffer_len
        );
        let result = self
            .cipher
            .decrypt(&self.nonce, self.enc_buffer[..self.enc_buffer_len].as_ref())
            .map_err(|e| error!(Other, "AES Decryption error: {}", e))?;
        dbg_println!("Block decrypted: {}", result.len());
        increment_nonce(&mut self.nonce);
        // Setup buffer
        self.buffer_len = self.enc_buffer_len - AES_AUTH_TAG_LEN;
        self.buffer[..self.buffer_len].copy_from_slice(result.as_slice());
        // Reset encrpyted buffer
        self.enc_buffer = vec![0; BUFFER_SIZE + AES_AUTH_TAG_LEN];
        self.enc_buffer_len = 0;
        Ok(())
    }
}

impl<R: std::io::Read, const BUFFER_SIZE: usize> std::io::Read for CryptoReader<R, BUFFER_SIZE> {
    /// Read decrypted data from the underlying reader.
    ///
    /// # Arguments
    /// - `buf`: The buffer to store the decrypted data.
    ///
    /// # Returns
    /// - Ok(usize): The number of bytes read.
    ///
    /// # Notes
    ///
    /// If the number of bytes read is 0, it means:
    /// - The buffer is empty.
    /// - The underlying reader is closed.
    ///
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let target_len = buf.len();
        if target_len == 0 {
            // Nothing to read
            return Ok(0);
        }
        let mut total_read = 0;

        // Check if there are any decrypted data in the buffer
        if self.buffer_len > 0 {
            let to_copy = std::cmp::min(target_len, self.buffer_len);
            let buffer_start_idx = BUFFER_SIZE - self.buffer_len;
            buf[..to_copy]
                .copy_from_slice(&self.buffer[buffer_start_idx..buffer_start_idx + to_copy]);
            self.buffer_len -= to_copy;
            total_read += to_copy;
        }

        if total_read == target_len {
            return Ok(total_read);
        }

        while total_read < target_len {
            loop {
                let read = self
                    .reader
                    .read(&mut self.enc_buffer[self.enc_buffer_len..])?;
                if read == 0 {
                    // The reader is closed
                    break;
                }
                self.enc_buffer_len += read;
                if self.enc_buffer_len == BUFFER_SIZE + AES_AUTH_TAG_LEN {
                    break;
                }
            }

            if self.enc_buffer_len == 0 {
                // The reader is closed
                break;
            }

            // Decrypt the buffer
            self.decrypt_buffer()?;

            let to_copy = min!(target_len - total_read, BUFFER_SIZE, self.buffer_len);
            buf[total_read..total_read + to_copy].copy_from_slice(&self.buffer[..to_copy]);
            self.buffer_len -= to_copy;
            total_read += to_copy;
        }

        Ok(total_read)
    }
}
