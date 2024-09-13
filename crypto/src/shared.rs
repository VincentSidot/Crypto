use aes_gcm::{
    aead::{
        consts::{B0, B1},
        generic_array::GenericArray,
    },
    aes::cipher::typenum::{UInt, UTerm},
};
use rand::rngs::ThreadRng;

// Enforce 2048 bits key length. (Temporary solution)
pub(crate) const RSA_KEY_LEN: usize = 2048;
// RSA 2048 bits creates a 256 bytes encrypted data chunk.
pub(crate) const AES_KEY_LEN: usize = 256;
// 96 bits nonce for AES-GCM.
pub(crate) const AES_NONCE_LEN: usize = 12;
// 128 bits authentication tag for AES-GCM.
pub(crate) const AES_AUTH_TAG_LEN: usize = 16; // [Currently not used but present in the encryption scheme]

pub(crate) fn setup_rng() -> ThreadRng {
    rand::thread_rng()
}
pub(crate) type Nonce = GenericArray<u8, UInt<UInt<UInt<UInt<UTerm, B1>, B1>, B0>, B0>>;

pub(crate) fn increment_nonce(nonce: &mut Nonce) {
    let mut has_been_incremented = false;
    for i in (0..nonce.len()).rev() {
        if nonce[i] == u8::MAX {
            nonce[i] = 0;
        } else {
            nonce[i] += 1;
            has_been_incremented = true;
            break;
        }
    }
    if !has_been_incremented {
        // Reset the nonce
        for i in 0..nonce.len() {
            nonce[i] = 0;
        }
    }
}
