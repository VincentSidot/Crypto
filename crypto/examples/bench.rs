use crypto::{CryptoReader, CryptoWriter, RsaKeys};
use std::io::{Read, Write};
use std::time::Instant;

fn main() {
    let keys = RsaKeys::generate().expect("failed to generate keys");
    let public = keys.public_key.expect("missing public key");
    let private = keys.private_key.expect("missing private key");
    let data = vec![0u8; 1024 * 1024]; // 1 MB

    let mut encrypted = Vec::new();
    let start = Instant::now();
    {
        let mut writer =
            CryptoWriter::<_, 8192>::new(&mut encrypted, public.clone()).expect("create writer");
        writer.write_all(&data).expect("encrypt data");
    }
    let enc_time = start.elapsed();

    let mut decrypted = Vec::new();
    let start = Instant::now();
    {
        let mut reader =
            CryptoReader::<_, 8192>::new(encrypted.as_slice(), private).expect("create reader");
        reader.read_to_end(&mut decrypted).expect("decrypt data");
    }
    let dec_time = start.elapsed();

    println!(
        "Encrypted {} bytes in {:?}, decrypted in {:?}",
        data.len(),
        enc_time,
        dec_time
    );
}
