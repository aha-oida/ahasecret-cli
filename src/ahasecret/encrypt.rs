use paris::{info, error};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm
};
use rand_core::{RngCore, OsRng};
use pbkdf2::{pbkdf2_hmac_array};
use sha2::{Sha256};
use serde_json::json;
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

fn b64_url_enc(b64str: String) -> String {
    let tmp = b64str.clone();
    return tmp.replace("+", "-").replace("/", "_");
}

pub fn encrypt_with_pass(plaintext: Vec<u8>, password: String, verbose: bool) -> Vec<u8> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let n = 100_000;
    let key_slice = pbkdf2_hmac_array::<Sha256, 32>(password.as_str().as_bytes(), &salt, n);
    if verbose {
        println!("key_len: {}", key_slice.len());
    }
    let cipher = Aes256Gcm::new_from_slice(&key_slice).unwrap_or_else(|e| {
        error!("encrypt_with_pass could not derive key: {}", e);
        std::process::exit(1);
    });

    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let encrypted_buf = cipher.encrypt(&nonce, plaintext.as_ref())
        .unwrap_or_else(|e| {
            error!("Failed to encrypt: {}", e);
            std::process::exit(1);
        });

    let encrypted = json!( {
        "salt": STANDARD.encode(&salt),
        "iv": STANDARD.encode(&nonce),
        "cipher": STANDARD.encode(&encrypted_buf)
    });

    if verbose {
        println!("{}", encrypted);   
    }

    return encrypted.to_string().into_bytes();
}

pub fn send(encrypted: Encrypted, url: String, extra_pw: bool, retention: u32, verbose: bool) {
    let mut ahaclient = AhaClient::new(verbose);
    ahaclient.fetch_token(url.clone());
    let bin_id = ahaclient.store_secret(url.as_str(), encrypted.cipher.as_str(), extra_pw, retention);
    println!("Visit to decrypt: {}/bins/{}#{}&{}", url, bin_id, b64_url_enc(encrypted.key), b64_url_enc(encrypted.nonce));
}
