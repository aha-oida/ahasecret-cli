use std::str;
use paris::{info, warn, error};
use base64::{engine::general_purpose, Engine as _};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm
};
use scraper::{Html, Selector};
use serde::{Deserialize};
use serde_json;

#[derive(Debug)]
pub struct Encrypted {
    pub key: String,
    pub nonce: String,
    pub cipher: String
}

#[derive(Deserialize, Debug)]
pub struct Bin {
    pub id: String,
    pub url: String
}

pub fn encrypt(plaintext: Vec<u8>, verbose: bool) -> Encrypted {
    let key = Aes256Gcm::generate_key(OsRng);
    let cipher = Aes256Gcm::new(&key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let encrypted_buf = cipher.encrypt(&nonce, str::from_utf8(&plaintext).unwrap().as_ref())
        .unwrap_or_else(|e| {
            error!("Failed to encrypt: {}", e);
            std::process::exit(1);
        });

    let encrypted = Encrypted {
        key: general_purpose::STANDARD.encode(&key),
        nonce: general_purpose::STANDARD.encode(&nonce),
        cipher: general_purpose::STANDARD.encode(&encrypted_buf)
    };

    if verbose {
        info!("Encrypted Length: {}", encrypted.cipher.len());
        info!("Encrypting Algorithm: Aes256Gcm");
    }

    return encrypted;
}

pub fn send(encrypted: Encrypted, url: String, retention: u32) {
    let client = reqwest::blocking::Client::builder().cookie_store(true).build().unwrap();
    let res = client.get(url.as_str())
        .send()
        .unwrap_or_else(|e| {
            error!("Request failed: {}", e);
            std::process::exit(1);
        });

    let document = Html::parse_document(&res.text().unwrap());
    let selector = Selector::parse(r#"meta[name="authenticity_token"]"#).unwrap();
    let mut token = "";
    for element in document.select(&selector) {
        token = element.value().attr("content").unwrap();
    }

    let encoded_data: String = form_urlencoded::Serializer::new(String::new())
        .append_pair("bin[payload]", encrypted.cipher.as_str())
        .append_pair("retention", retention.to_string().as_str())
        .append_pair("authenticity_token", token)
        .finish();

    let res = client.post(url.as_str())
        .body(encoded_data)
        .send()
        .unwrap_or_else(|e| {
            error!("Request failed: {}", e);
            std::process::exit(1);
        });

    let status = res.status();

    if ! status.is_success() {
        error!("Warning status code {}: maybe the message was to long", status.as_str());
        warn!("Length of encrypted message: {} bytes", encrypted.cipher.len());
        std::process::exit(1)
    }

    let jres: Bin = serde_json::from_str(res.text().unwrap().as_str())
        .unwrap_or_else(|e| {
            error!("Parsing JSON failed: {}", e);
            std::process::exit(1);
        });

    println!("Visit to decrypt: {}/bins/{}#{}&{}", url, jres.id, encrypted.key, encrypted.nonce);
}
