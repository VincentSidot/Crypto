# Crypto Module

## Table of Contents

- [Crypto Module](#crypto-module)
  - [Table of Contents](#table-of-contents)
  - [Introduction](#introduction)
  - [Features](#features)
  - [Encryption Scheme](#encryption-scheme)
  - [Next Steps](#next-steps)
  - [Usage](#usage)
    - [Running Tests](#running-tests)
    - [Key Management](#key-management)
    - [Buffer-Sized Operations](#buffer-sized-operations)
  - [Example](#example)
  - [Changelog](#changelog)
  - [License](#license)


## Introduction

This Rust project provides encryption and decryption capabilities using a combination of **RSA** and **AES-256-GCM** encryption schemes. The module includes utilities for managing RSA key pairs, performing cryptographic operations on data streams, and serializing/deserializing RSA keys to/from PEM format.

## Features

- **CryptoWriter**: Encrypts data using AES-256-GCM with a randomly generated AES key, which is then encrypted with an RSA public key. Implements the `std::io::Write` trait.
- **CryptoReader**: Decrypts data encrypted with AES-256-GCM using a private RSA key. Implements the `std::io::Read` trait.
- **RSA Key Management**: Generate, serialize, and deserialize RSA key pairs using `RsaKeys`. Provides utilities for converting RSA keys to PEM format and loading keys from PEM.
- **Buffer-Sized Operations**: Buffer size for encryption and decryption can be customized using the provided macros (`CryptoWriter!` and `CryptoReader!`).
- **Debugging Macros**: Includes `dbg_print!` and `dbg_println!` macros for conditional debug logging, disabled by default.

## Encryption Scheme

The data is encrypted using the AES-256-GCM scheme, where the AES key is randomly generated. The AES key is then encrypted using the RSA public key. The encrypted message format is as follows:

```plaintext
+-----------------+   +-----------------+   +-----------------+   +-----------------+   
|     AES Key     |   |    AES NONCE    |   |     AES Data    |   |     AES Data    |   
+-----------------+   +-----------------+   +-----------------+   +-----------------+   
|     RSA Enc     |   |                 |   |                 |   |                 |   ...
+-----------------+   +-----------------+   +-----------------+   +-----------------+   
|   AES KEY LEN   |   |  AES NONCE LEN  |   |   BUFFER_SIZE   |   |   BUFFER_SIZE   |  
+-----------------+   +-----------------+   +-----------------+   +-----------------+
```

## Next Steps

- Add support for any RSA key size.
- Add support for customizing the AES key size.
- Ensure the memory is securely zeroed after use.
- Ensure the data is memlocked during encryption/decryption. (To prevent swapping to disk and leaking sensitive data)

## Usage

Add this crate to your `Cargo.toml`:

```toml
[dependencies]
crypto = { git = "git@github.com:VincentSidot/crypto-file.git" }
```

Then, in your code:

```rust
use crypto::{CryptoReader, CryptoWriter, RsaKeys};
use std::io::{Write, Read};

fn main() {
    let keys = RsaKeys::generate().expect("Failed to generate RSA keys");
    let public_key = keys.public_key().expect("Failed to retrieve public key");
    let private_key = keys.private_key().expect("Failed to retrieve private key");

    let mut encrypted = Vec::new();
    {
        let mut writer = CryptoWriter::<_, 16>::new(&mut encrypted, public_key).unwrap();
        writer.write_all(b"Hello, world!").unwrap();
    }

    let mut decrypted = Vec::new();
    {
        let mut reader = CryptoReader::<_, 16>::new(encrypted.as_slice(), private_key).unwrap();
        reader.read_to_end(&mut decrypted).unwrap();
    }

    assert_eq!(b"Hello, world!", &decrypted[..]);
}
```

### Running Tests

To run the tests, use the following command:

```bash
cargo test
```

### Key Management

The `RsaKeys` struct provides an easy way to generate, load, and serialize RSA keys. You can generate new keys and convert them to PEM format as follows:

```rust
let keys = RsaKeys::generate().expect("Failed to generate RSA keys");
let private_pem = keys.private_key_to_pem().expect("Failed to convert private key to PEM");
let public_pem = keys.public_key_to_pem().expect("Failed to convert public key to PEM");
```

### Buffer-Sized Operations

Both `CryptoWriter` and `CryptoReader` allow specifying a buffer size using the provided macros. For example, to use a buffer of size 16:

```rust
let mut writer = CryptoWriter::<_, 16>::new(&mut encrypted, public_key).unwrap();
```

## Example

Encrypt and decrypt a message using RSA keys and buffers of size 16:

```rust
use my_crypto_lib::{CryptoReader, CryptoWriter, RsaKeys};
use std::io::{Write, Read};

fn main() {
    let keys = RsaKeys::generate().expect("Failed to generate RSA keys");
    let public_key = keys.public_key().expect("Failed to retrieve public key");
    let private_key = keys.private_key().expect("Failed to retrieve private key");

    let mut encrypted = Vec::new();
    {
        let mut writer = CryptoWriter::<_, 16>::new(&mut encrypted, public_key).unwrap();
        writer.write_all(b"Hello, world!").unwrap();
    }

    let mut decrypted = Vec::new();
    {
        let mut reader = CryptoReader::<_, 16>::new(encrypted.as_slice(), private_key).unwrap();
        reader.read_to_end(&mut decrypted).unwrap();
    }

    assert_eq!(b"Hello, world!", &decrypted[..]);
}
```

## Changelog

All notable changes to this project will be documented in the [CHANGELOG](./CHANGELOG.md) file.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for more details.