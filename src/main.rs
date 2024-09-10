use std::{io::Write, path::PathBuf};

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm,
    Key, // Or `Aes128Gcm`
    Nonce,
};
use clap::{Parser, Subcommand};
use rand::rngs::ThreadRng;
use rsa::{
    pkcs1::{DecodeRsaPrivateKey, DecodeRsaPublicKey, EncodeRsaPrivateKey, EncodeRsaPublicKey},
    Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey,
};

const AES_KEY_LEN: usize = 256; // RSA 2048 bits creates a 256 bytes encrypted data chunk.
const AES_NONCE_LEN: usize = 12;

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    subcommand: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    Keygen {
        #[clap(short, long, default_value = "2048", help = "Key size in bits")]
        bits: usize,
        #[clap(
            help = "File to save the private key. Public key will be saved in the same directory with the same name but with a .pub extension (e.g. like ssh-keygen utility)"
        )]
        output: PathBuf,
    },
    Encrypt {
        #[clap(help = "File to encrypt")]
        input: PathBuf,
        #[clap(help = "Public key to encrypt the data")]
        key: String,
        #[clap(help = "File to save the encrypted data (default: <data>.enc)")]
        output: Option<PathBuf>,
    },
    Decrypt {
        #[clap(help = "File to decrypt")]
        input: PathBuf,
        #[clap(help = "Private key to decrypt the data")]
        key: String,
        #[clap(help = "File to save the decrypted data (default: <data>.dec)")]
        output: Option<PathBuf>,
    },
}

fn setup_rng() -> ThreadRng {
    rand::thread_rng()
}

fn generate_keys(bits: usize, output: PathBuf) {
    let mut rng = setup_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, bits).expect("failed to generate a key");
    let pub_key = RsaPublicKey::from(&priv_key);

    let priv_key_pem = priv_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to convert to pem");
    let pub_key_pem = pub_key
        .to_pkcs1_pem(rsa::pkcs8::LineEnding::LF)
        .expect("failed to convert to pem");

    std::fs::write(&output, priv_key_pem).expect("failed to write private key");

    let pub_output = PathBuf::from(format!("{}.pub", output.display()));

    std::fs::write(&pub_output, pub_key_pem).expect("failed to write public key");
    println!(
        "Keys generated and saved to {} and {}",
        output.display(),
        pub_output.display()
    );
}

fn encrypt(public_key: String, input: PathBuf, output: Option<PathBuf>) {
    let mut rng = setup_rng();

    // AES encryption
    let key = generate_aes_key(&mut rng);
    let data = std::fs::read(&input).expect("failed to read data");
    let enc_data = encrypt_aes(&mut rng, &key, &data);

    // RSA encryption
    let pub_key_pem = std::fs::read_to_string(public_key).expect("failed to read public key");
    let pub_key = RsaPublicKey::from_pkcs1_pem(&pub_key_pem).expect("failed to parse public key");
    let raw_aes_key = key.as_slice();
    let enc_aes_key = pub_key
        .encrypt(&mut rng, Pkcs1v15Encrypt, raw_aes_key)
        .expect("failed to encrypt AES key");

    // File construction
    let output = output.unwrap_or_else(|| PathBuf::from(format!("{}.enc", input.display())));
    let mut file = std::fs::File::create(&output).expect("failed to create file");
    file.write_all(&enc_aes_key)
        .expect("failed to write encrypted AES key");
    file.write_all(&enc_data)
        .expect("failed to write encrypted data");

    println!("Encrypted data saved to {}", output.display());
}

fn decrypt(private_key: String, input: PathBuf, output: Option<PathBuf>) {
    let data = std::fs::read(&input).expect("failed to read data");

    // Extract the encrypted AES key and data
    let enc_aes_key = &data[..AES_KEY_LEN];
    let enc_data = &data[AES_KEY_LEN..];

    // RSA decryption
    let priv_key_pem = std::fs::read_to_string(private_key).expect("failed to read private key");
    let priv_key =
        RsaPrivateKey::from_pkcs1_pem(&priv_key_pem).expect("failed to parse private key");
    let raw_aes_key = priv_key
        .decrypt(Pkcs1v15Encrypt, enc_aes_key)
        .expect("failed to decrypt AES key");
    let key = Key::<Aes256Gcm>::from_slice(&raw_aes_key);

    // AES decryption
    let dec_data = decrypt_aes(&key, enc_data);

    // File construction
    let output = output.unwrap_or_else(|| PathBuf::from(format!("{}.dec", input.display())));
    std::fs::write(&output, dec_data).expect("failed to write decrypted data");

    println!("Decrypted data saved to {}", output.display());
}

fn generate_aes_key(rng: &mut ThreadRng) -> Key<Aes256Gcm> {
    Aes256Gcm::generate_key(rng)
}

fn encrypt_aes(rng: &mut ThreadRng, key: &Key<Aes256Gcm>, data: &[u8]) -> Vec<u8> {
    let nonce = Aes256Gcm::generate_nonce(rng);
    let cipher = Aes256Gcm::new(key);
    let encrypted = cipher.encrypt(&nonce, data).expect("failed to encrypt");
    // Prepend the nonce to the encrypted data
    let mut result = Vec::with_capacity(AES_NONCE_LEN + encrypted.len());
    result.extend_from_slice(nonce.as_ref());
    result.extend_from_slice(&encrypted);
    result
}

fn decrypt_aes(key: &Key<Aes256Gcm>, data: &[u8]) -> Vec<u8> {
    let nonce = Nonce::from_slice(&data[..AES_NONCE_LEN]);
    let cipher = Aes256Gcm::new(key);
    cipher
        .decrypt(nonce, &data[AES_NONCE_LEN..])
        .expect("failed to decrypt")
}

enum Operation {
    Keygen,
    Encrypt,
    Decrypt,
}

fn main() {
    let start = std::time::Instant::now();
    let args: Args = Args::parse();

    let op = match args.subcommand {
        Subcommands::Keygen { bits, output } => {
            generate_keys(bits, output);
            Operation::Keygen
        }
        Subcommands::Encrypt {
            key: public_key,
            input: data,
            output,
        } => {
            encrypt(public_key, data, output);
            Operation::Encrypt
        }
        Subcommands::Decrypt {
            key: private_key,
            input: data,
            output,
        } => {
            decrypt(private_key, data, output);
            Operation::Decrypt
        }
    };

    let elapsed = start.elapsed();
    match op {
        Operation::Keygen => println!("Key generation took {:?}", elapsed),
        Operation::Encrypt => println!("Encryption took {:?}", elapsed),
        Operation::Decrypt => println!("Decryption took {:?}", elapsed),
    }
}
