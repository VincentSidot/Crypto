use crypto::{CryptoReader, CryptoWriter, RsaKeys};
use std::io::{Read, Write};
use std::time::Instant;

const KB: usize = 1024; // 1 KB buffer size
const MB: usize = 1024 * KB; // 1 MB buffer size
const GB: usize = 1024 * MB; // 1 GB buffer size

const BUFFER_SIZE: usize = 100 * KB; // 100 KB buffer size

fn main() {
    let keys = RsaKeys::generate().expect("failed to generate keys");
    let public = keys.public_key.expect("missing public key");
    let private = keys.private_key.expect("missing private key");

    let data = vec![0u8; 1 * GB]; // 1GB of data

    let mut encrypted = Vec::new();
    let start = Instant::now();
    {
        let mut writer = CryptoWriter::<_, BUFFER_SIZE>::new(&mut encrypted, public.clone())
            .expect("create writer");
        writer.write_all(&data).expect("encrypt data");
    }
    let enc_time = start.elapsed();

    let mut decrypted = Vec::new();
    let start = Instant::now();
    {
        let mut reader = CryptoReader::<_, BUFFER_SIZE>::new(encrypted.as_slice(), private)
            .expect("create reader");
        reader.read_to_end(&mut decrypted).expect("decrypt data");
    }
    let dec_time = start.elapsed();

    let dec_speed = (data.len() / MB) as f64 / dec_time.as_secs_f64();
    let enc_speed = (data.len() / MB) as f64 / enc_time.as_secs_f64();

    println!(
        "Encrypted {} bytes in {:?}, decrypted in {:?}",
        data.len(),
        enc_time,
        dec_time
    );

    println!("Decryption speed: {:.2} MB/s", dec_speed);
    println!("Encryption speed: {:.2} MB/s", enc_speed);
}
