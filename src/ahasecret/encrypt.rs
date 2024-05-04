use paris::{info, error};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm
};
use crate::ahasecret::client::AhaClient;

#[derive(Debug)]
pub struct Encrypted {
    pub key: String,
    pub nonce: String,
    pub cipher: String
}

pub fn encrypt(plaintext: Vec<u8>, verbose: bool) -> Encrypted {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted_buf = cipher.encrypt(&nonce, plaintext.as_ref())
        .unwrap_or_else(|e| {
            error!("Failed to encrypt: {}", e);
            std::process::exit(1);
        });

    let encrypted = Encrypted {
        key: STANDARD.encode(&key),
        nonce: STANDARD.encode(&nonce),
        cipher: STANDARD.encode(&encrypted_buf)
    };

    if verbose {
        info!("Encrypted Length: {}", encrypted.cipher.len());
        info!("Encrypting Algorithm: Aes256Gcm");
    }

    return encrypted;
}

pub fn send(encrypted: Encrypted, url: String, retention: u32, verbose: bool) {
    let mut ahaclient = AhaClient::new(verbose);
    ahaclient.fetch_token(url.clone());
    let bin_id = ahaclient.store_secret(url.as_str(), encrypted.cipher.as_str(), retention);
    println!("Visit to decrypt: {}/bins/{}#{}&{}", url, bin_id, encrypted.key, encrypted.nonce);
}
