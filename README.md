

# RSA-AES Encryption Tool

This project provides a command-line tool for generating RSA key pairs, encrypting files using a combination of AES and RSA, and decrypting the files. It utilizes the `aes-gcm` crate for AES encryption and `rsa` crate for RSA encryption.

## Table of Contents

- [RSA-AES Encryption Tool](#rsa-aes-encryption-tool)
  - [Table of Contents](#table-of-contents)
  - [Features](#features)
  - [Next Steps](#next-steps)
  - [Dependencies](#dependencies)
  - [How It Works](#how-it-works)
  - [Usage](#usage)
    - [Key Generation](#key-generation)
    - [File Encryption](#file-encryption)
    - [File Decryption](#file-decryption)
  - [Performance](#performance)
  - [Encryption Scheme](#encryption-scheme)
  - [License](#license)


## Features

- **Key generation**: Generates an RSA private and public key pair.
- **File encryption**: Encrypts files using AES-256 for data encryption and RSA for encrypting the AES key.
- **File decryption**: Decrypts files encrypted with the tool by decrypting the AES key using RSA, then decrypting the data with AES.

## Next Steps

- **Stream encryption**: Implement stream encryption for encrypting log streams.

## Dependencies

This project requires the following crates:
- `aes-gcm`
- `clap`
- `rand`
- `rsa`

To install the required dependencies and build the target binnary, use:

```bash
cargo build --release # Build the release binary (Major performance improvements)
```

## How It Works

- **AES Encryption**: AES-256 is used for encrypting the actual data. A random key is generated for each encryption operation.
- **RSA Encryption**: The AES key is encrypted using RSA, and the resulting encrypted AES key is stored alongside the encrypted data.
- **AES Decryption**: The AES key is decrypted using RSA, and then the data is decrypted using the decrypted AES key.

## Usage

The tool supports three main commands: `keygen`, `encrypt`, and `decrypt`.

### Key Generation

Generate an RSA key pair with a specified key size:

```bash
cargo run -- keygen -b <KEY_SIZE> <OUTPUT_PATH>
```

- `KEY_SIZE`: Size of the RSA key in bits (e.g., 2048, 4096).
- `OUTPUT_PATH`: File path to save the private key. The public key will be saved in the same directory with a `.pub` extension.

Example:

```bash
cargo run -- keygen -b 2048 my_key
```

This will generate `my_key` (private key) and `my_key.pub` (public key).

### File Encryption

Encrypt a file using a public key:

```bash
cargo run -- encrypt <PUBLIC_KEY> <INPUT_FILE> [OUTPUT_FILE]
```

- `PUBLIC_KEY`: Path to the RSA public key.
- `INPUT_FILE`: File to encrypt.
- `OUTPUT_FILE`: Optional. Path to save the encrypted file (default: `<INPUT_FILE>.enc`).

Example:

```bash
cargo run -- encrypt my_key.pub secret.txt
```

This will generate `secret.txt.enc` containing the encrypted data.

### File Decryption

Decrypt a file using a private key:

```bash
cargo run -- decrypt <PRIVATE_KEY> <INPUT_FILE> [OUTPUT_FILE]
```

- `PRIVATE_KEY`: Path to the RSA private key.
- `INPUT_FILE`: File to decrypt.
- `OUTPUT_FILE`: Optional. Path to save the decrypted file (default: `<INPUT_FILE>.dec`).

Example:

```bash
cargo run -- decrypt my_key secret.txt.enc
```

This will generate `secret.txt.enc.dec` containing the decrypted data.

## Performance

The program prints the time taken for each operation (key generation, encryption, and decryption).

## Encryption Scheme

The tool uses the following encryption scheme:

1. Generate a random AES key.
2. Encrypt the data using AES-256.
3. Encrypt the AES key using RSA.
4. Save the encrypted AES key and the encrypted data.

The encrypted file structure is as follows:
```
+-----------------+   +-----------------+   +-----------------+
|     AES Key     |   |    AES NONCE    |   |     AES Data    |
+-----------------+   +-----------------+   +-----------------+
|     RSA Enc     |   |                 |   |                 |
+-----------------+   +-----------------+   +-----------------+
```

- **AES Key**: Random AES key used for encrypting the data. (256 bytes)
- **AES Nonce**: Random nonce used for AES encryption. (12 bytes)
- **AES Data**: Encrypted data using AES-256. (Variable length)

> **Note**: The file structure will be updated to handle streamed data. (AES nonce may be built with a counter, and data block may be encrypted in chunks.)
> 
> The implementation will look like:
> ```
> +-----------------+   +-----------------+   +-----------------+   +-----------------+   
> |     AES Key     |   |    AES NONCE    |   |     AES Data    |   |     AES Data    |   
> +-----------------+   +-----------------+   +-----------------+   +-----------------+   ...
> |     RSA Enc     |   |                 |   |                 |   |                 |   
> +-----------------+   +-----------------+   +-----------------+   +-----------------+   
> ```
>
> The AES data will be encrypted in chunks, and the AES nonce will be initialized with a random value and incremented for each chunk.

## License

This project is licensed under the MIT License.
