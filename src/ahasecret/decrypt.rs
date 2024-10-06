use paris::{info, warn, error};
use url::Url;
use std::io::{self, Write};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::{
    aead::{Aead, KeyInit, Error},
    Aes256Gcm, Key, Nonce
};
use serde::{Deserialize};
use pbkdf2::{pbkdf2_hmac_array};
use sha2::{Sha256};

use crate::ahasecret::client::AhaClient;
use crate::ahasecret::utils;

#[derive(Debug)]
struct ParsedUrl {
    key: String,
    nonce: String,
    path: String,
    bin_url: String
}

#[derive(Deserialize, Debug)]
struct PWSecret {
    iv: String,
    cipher: String,
    salt: String,
}

fn b64_url_dec(b64str: String) -> String {
    let tmp = b64str.clone();
    return tmp.replace("-", "+").replace("_", "/").replace("\\", "");
}

fn bin_url(mut url: Url, path: &str) -> Result<Url,String> {
    match url.path_segments_mut() {
        Ok(mut path) => {
            path.clear();
        }
        Err(_) => {
            Err("Cannot be a base")?
        }
    }

    /*
     * Remove last character if it is a slash
     */
    let mut path_trimmed = String::from(path);
    if path.chars().last().unwrap() == '/' {
        path_trimmed = String::from(&path_trimmed[..path_trimmed.len()-1]);
    }

    url.set_query(None);
    url.set_fragment(None);

    Ok(url.join(path_trimmed.as_str()).unwrap())
}

fn parse_decrypt_url(url: String, verbose: bool) -> ParsedUrl {
    let parsed_url = Url::parse(url.as_str())
        .unwrap_or_else(|e| {
            error!("Parsing Url failed: {}", e);
            std::process::exit(1);
        });

    let secret_parts: Vec<&str> = parsed_url.fragment().unwrap().split("&").collect();
    if secret_parts.len() != 2 {
        error!("Unable to parse secret and nonce from url");
        std::process::exit(1);
    }
    let bin = bin_url(parsed_url.clone(), parsed_url.path())
        .unwrap_or_else(|e| {
            error!("Parsing Url failed: {}", e);
            std::process::exit(1);
        }); 

    let parsed = ParsedUrl {
        key: b64_url_dec(String::from(secret_parts[0])),
        nonce: b64_url_dec(String::from(secret_parts[1])),
        path: String::from(parsed_url.path()),
        bin_url: String::from(bin.as_str())
    };

    if verbose {
        info!("Key: {:?}", parsed.key);
        info!("Nonce: {:?}", parsed.nonce);
        info!("Path: {:?}", parsed.path);
        info!("Bin-Url: {:?}", parsed.bin_url);
    }

    return parsed;
}

fn choose() -> bool {
    loop {
        print!("Do you really want to reveal the secret? (y/N): ");
        std::io::stdout().flush().unwrap();
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).unwrap();
        let choice = input.chars().next().unwrap().to_ascii_lowercase();
        match choice {
            'y' => return true,
            'n'|'\n' => {
                warn!("Your choice was NO. Aborted.");
                std::process::exit(1);
            }
            _ => continue
        }
    }
}

fn decrypt_with_pw(payload: Vec<u8>, password: String) -> Result<(), Error> {
    let n = 100_000;
    let pwsec: PWSecret = serde_json::from_slice(&payload).unwrap();
    let salt = STANDARD.decode(pwsec.salt)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode salt: {}", e);
            std::process::exit(1);
    });

    let vnonce = STANDARD.decode(pwsec.iv)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode nonce: {}", e);
            std::process::exit(1);
    });

    let nonce = Nonce::from_slice(&vnonce);

    let encrypted = STANDARD.decode(pwsec.cipher)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode cipher: {}", e);
            std::process::exit(1);
    });

    let key_slice = pbkdf2_hmac_array::<Sha256, 32>(password.as_str().as_bytes(), &salt, n);
    let cipher = Aes256Gcm::new_from_slice(&key_slice).unwrap_or_else(|e| {
        error!("encrypt_with_pass could not derive key: {}", e);
        std::process::exit(1);
    });

    let plaintext = cipher.decrypt(&nonce, encrypted.as_ref())?;

    io::stdout().write(&plaintext)
        .unwrap_or_else(|e| {
            error!("Failed to write to stdout: {}", e);
            std::process::exit(1);
        });

    io::stdout().flush()
        .unwrap_or_else(|e| {
            error!("Failed to flush stdout: {}", e);
            std::process::exit(1);
        });

    Ok(())
}

fn decrypt(parsed_url: ParsedUrl, payload: String) -> Vec<u8> {
    let key = STANDARD.decode(parsed_url.key)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode key: {}", e);
            std::process::exit(1);
        });

    let vnonce = STANDARD.decode(parsed_url.nonce)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode nonce: {}", e);
            std::process::exit(1);
        });

    let nonce = Nonce::from_slice(&vnonce);
    let plaintext = STANDARD.decode(payload)
        .unwrap_or_else(|e| {
            error!("Failed to b64-decode payload: {}", e);
            std::process::exit(1);
        });

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let cipher = Aes256Gcm::new(&key);
    let plaintext = cipher.decrypt(&nonce, plaintext.as_ref())
        .unwrap_or_else(|e| {
            error!("Failed to decrypt payload: {}", e);
            std::process::exit(1);
        });

    return plaintext;
}

pub fn reveal(url: String, verbose: bool, force: bool) {
    let mut ahaclient = AhaClient::new(verbose);
    let parsed = parse_decrypt_url(url, verbose);
    ahaclient.fetch_token(parsed.bin_url.clone());

    if ! force {
        choose(); 
    }

    let bin = ahaclient.reveal(parsed.bin_url.clone());
    let dec_msg = decrypt(parsed, bin.payload);

    if bin.has_password {
        println!("This secret is passwort-protected!");
        loop {
            let password = utils::read_password_from_stdin();
            
            match decrypt_with_pw(dec_msg.clone(), password){
                Ok(_some) => break,
                Err(_) => { 
                    println!("Decryption failed. Is the password correct?");
                    continue 
                }
            };
        }
    } else {
        io::stdout().write(&dec_msg)
            .unwrap_or_else(|e| {
                error!("Failed to write to stdout: {}", e);
                std::process::exit(1);
            });

        io::stdout().flush()
            .unwrap_or_else(|e| {
                error!("Failed to flush stdout: {}", e);
                std::process::exit(1);
            });
    }
}
