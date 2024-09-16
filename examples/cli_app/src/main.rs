use clap::{Parser, Subcommand};
use crypto::{CryptoReader, CryptoWriter, RsaKeys};
use std::{io::Write as _, path::PathBuf};

#[derive(Parser)]
struct Args {
    #[clap(subcommand)]
    subcommand: Subcommands,
}

#[derive(Subcommand)]
enum Subcommands {
    Keygen {
        #[clap(
            help = "File to save the private key. Public key will be saved in the same directory with the same name but with a .pub extension (e.g. like ssh-keygen utility)"
        )]
        output: PathBuf,
    },
    Encrypt {
        #[clap(help = "File to encrypt")]
        input: PathBuf,
        #[clap(help = "Public key to encrypt the data")]
        key: PathBuf,
        #[clap(help = "File to save the encrypted data (default: <data>.enc)")]
        output: Option<PathBuf>,
    },
    Decrypt {
        #[clap(help = "File to decrypt")]
        input: PathBuf,
        #[clap(help = "Private key to decrypt the data")]
        key: PathBuf,
        #[clap(help = "File to save the decrypted data (default: <data>.dec)", default_value="-")]
        output: String,
    },
}

enum Operation {
    Keygen,
    Encrypt,
    Decrypt,
}

fn main() {
    let start = std::time::Instant::now();
    let args: Args = Args::parse();

    let mut footer_print = true;

    let op = match args.subcommand {
        Subcommands::Keygen { output } => {
            generate_keys(output);
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
            if &output == "-" {
                footer_print = false;
            }
            decrypt(private_key, data, output);
            Operation::Decrypt
        }
    };

    let elapsed = start.elapsed();
    if footer_print {
        match op {
            Operation::Keygen => println!("Key generation took {:?}", elapsed),
            Operation::Encrypt => println!("Encryption took {:?}", elapsed),
            Operation::Decrypt => println!("Decryption took {:?}", elapsed),
        }
    }
}

pub fn generate_keys(output: PathBuf) {
    let keys = crypto::RsaKeys::generate().expect("failed to generate keys");
    let private_key = keys
        .private_key_to_pem()
        .expect("failed to convert private key to PEM");
    let public_key = keys
        .public_key_to_pem()
        .expect("failed to convert public key to PEM");

    std::fs::write(&output, private_key).expect("failed to write private key");
    std::fs::write(output.with_extension("pub"), public_key).expect("failed to write public key");

    println!(
        "Keys saved to {} and {}",
        output.display(),
        output.with_extension("pub").display()
    );
}

pub fn encrypt(public_key: PathBuf, input: PathBuf, output: Option<PathBuf>) {
    let key = RsaKeys::from_public_key_pem(
        &std::fs::read_to_string(public_key).expect("failed to read public key"),
    )
    .expect("failed to parse public key")
    .public_key
    .unwrap();

    let output = output.unwrap_or_else(|| PathBuf::from(format!("{}.enc", input.display())));

    let file = std::fs::File::create(&output).expect("failed to open file");

    let mut writer = CryptoWriter::<_, 16>::new(file, key).expect("failed to create CryptoWriter");

    let data = std::fs::read(&input).expect("failed to read data");

    writer.write_all(&data).expect("failed to write data");

    println!("Encrypted data saved to {}", output.display());
}

pub fn decrypt(private_key: PathBuf, input: PathBuf, output: String) {
    let key = RsaKeys::from_private_key_pem(
        &std::fs::read_to_string(private_key).expect("failed to read private key"),
    )
    .expect("failed to parse private key")
    .private_key
    .unwrap();

    let file = std::fs::File::open(&input).expect("Failed to open input file");

    let mut reader = CryptoReader::<_, 16>::new(file, key).expect("failed to create CryptoReader");
    let mut file: Box<dyn std::io::Write> = if output == "-" {
        Box::new(std::io::stdout())
    } else {
        Box::new(std::fs::File::create(&output).expect("failed to open output file"))
    };

    std::io::copy(&mut reader, &mut file).expect("failed to write decrypted data");

    if output != "-" {
        println!("Decrypted data saved to {}", output);
    }
}
