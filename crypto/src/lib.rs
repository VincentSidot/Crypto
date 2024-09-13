//! # Crypto Module
//!
//! This module provides encryption and decryption capabilities using RSA and AES encryption schemes.
//! It includes utilities for key management, error handling, and provides both writer and reader
//! abstractions to perform cryptographic operations.
//!
//! The main components are:
//!
//! - `CryptoWriter`: Encrypts data using a public RSA key and writes it to an output buffer.
//!    - It implements the `std::io::Write` trait. To allow seamless integration with existing
//!     Rust code that uses `std::io::Write`.
//! - `CryptoReader`: Decrypts data using a private RSA key and reads it from an input buffer.
//!    - It implements the `std::io::Read` trait. To allow seamless integration with existing
//!    Rust code that uses `std::io::Read
//! - `RsaKeys`: Manages RSA key pairs and provides utilities to generate, serialize, and deserialize keys.
//!
//! ## Encryption Scheme
//!
//! The data is encrypted using AES-256-GCM. The AES key is generated randomly from rng crate.
//! With `new_with_rng` method, you can pass the random number generator of your choice.
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
//! ## Features
//! - **Modular Design**: Encryption and decryption are handled by separate modules.
//! - **Buffer-Sized Operations**: Macros like `CryptoWriter!` and `CryptoReader!` allow users to specify
//!   the buffer size for cryptographic operations, ensuring efficient memory usage.
//! - **Key Management**: The `RsaKeys` struct provides functionality to generate, load, and serialize
//!   RSA keys, enabling flexible key management.
//!
//! ## Examples
//!
//! ```rust
//! // Encrypt and decrypt a message using RSA keys and buffers of size 16
//! use my_crypto_lib::{CryptoReader, CryptoWriter, RsaKeys};
//!
//! let keys = RsaKeys::generate().expect("failed to generate keys");
//! let public_key = keys.public_key().expect("failed to get public key");
//! let private_key = keys.private_key().expect("failed to get private key");
//!
//! let mut encrypted = Vec::new();
//! {
//!     let mut writer = CryptoWriter::<_, 16>::new(&mut encrypted, public_key).unwrap();
//!     writer.write_all(b"Hello, world!").unwrap();
//! }
//!
//! let mut decrypted = Vec::new();
//! {
//!     let mut reader = CryptoReader::<_, 16>::new(&encrypted[..], private_key).unwrap();
//!     reader.read_to_end(&mut decrypted).unwrap();
//! }
//!
//! assert_eq!(b"Hello, world!", &decrypted[..]);
//! ```
//!
//! ## Tests
//! Several tests are provided to ensure the correctness of encryption and decryption functionality,
//! including tests for handling one-block, two-block, less-than-one-block, and more-than-one-block
//! messages.
//!
//! ## License
//! This module is licensed under the MIT License.

mod decrypt;
mod encrypt;
mod error;
mod key;
mod shared;

pub use decrypt::CryptoReader;
pub use encrypt::CryptoWriter;
pub use error::Result; // Alias to std::io::Result
pub use key::RsaKeys;

#[macro_export]
macro_rules! CryptoReader {
    ($buffer:literal) => {
        $crate::CryptoReader::<_, $buffer>
    };
}

#[macro_export]
macro_rules! CryptoWriter {
    ($buffer:literal) => {
        $crate::CryptoWriter::<_, $buffer>
    };
}

#[allow(unused_macros)]
macro_rules! dbg_print {
    ($($arg:tt)*) => {
        // #[cfg(debug_assertions)]
        // {
        //     eprintln!($($arg)*);
        // }
    };
}

#[allow(unused_macros)]
macro_rules! dbg_println {
    ($($arg:tt)*) => {
        // #[cfg(debug_assertions)]
        // {
        //     eprintln!($($arg)*);
        // }
    };
}

#[allow(unused_imports)]
pub(crate) use dbg_print;
#[allow(unused_imports)]
pub(crate) use dbg_println;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read as _, Write as _};

    static mut KEYS: Option<RsaKeys> = None;

    fn get_keys() -> &'static RsaKeys {
        unsafe {
            if let Some(keys) = KEYS.as_ref() {
                keys
            } else {
                let keys = RsaKeys::generate().expect("failed to generate keys");
                KEYS = Some(keys);
                KEYS.as_ref().unwrap()
            }
        }
    }

    fn test_message<const BUFFER_SIZE: usize, T: AsRef<[u8]>>(msg: T) {
        let keys = get_keys();
        let (private_key, public_key) = {
            let private_key = keys.private_key.as_ref().unwrap();
            let public_key = keys.public_key.as_ref().unwrap();
            (private_key.clone(), public_key.clone())
        };

        let mut encrypted = Vec::new();

        {
            let mut writer =
                CryptoWriter::<_, BUFFER_SIZE>::new(&mut encrypted, public_key).unwrap();
            writer.write_all(msg.as_ref()).unwrap();
        }

        let mut decrypted = Vec::new();
        {
            let mut reader =
                CryptoReader::<_, BUFFER_SIZE>::new(encrypted.as_slice(), private_key).unwrap();
            reader.read_to_end(&mut decrypted).unwrap();
        }

        assert_eq!(msg.as_ref(), decrypted.as_slice());
    }

    #[test]
    fn test_key_serialize_deserialize() {
        let keys = get_keys();
        let private_key = keys
            .private_key_to_pem()
            .expect("failed to convert private key to PEM");
        let public_key = keys
            .public_key_to_pem()
            .expect("failed to convert public key to PEM");

        let keys = RsaKeys::from_key_pem(&private_key).expect("failed to parse keys");
        let re_private_key = keys
            .private_key_to_pem()
            .expect("failed to convert private key to PEM");
        let re_public_key = keys
            .public_key_to_pem()
            .expect("failed to convert public key to PEM");

        assert_eq!(private_key, re_private_key);
        assert_eq!(public_key, re_public_key);
    }

    #[test]
    fn test_one_block() {
        test_message::<16, _>(b"Hello, World!   "); // Message is exactly one block
    }

    #[test]
    fn test_two_block() {
        test_message::<16, _>(b"Hello, World!   Hello, World!   "); // Message is exactly two blocks
    }

    #[test]
    fn test_less_than_one_block() {
        test_message::<16, _>(b"Hello, World!"); // Message is less than one block
    }

    #[test]
    fn test_more_than_one_block() {
        test_message::<16, _>("Hello, World!".repeat(10)); // Message is more than one block
    }
}
