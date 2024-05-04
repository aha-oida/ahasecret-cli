use paris::{info, warn, error};
use url::Url;
use std::io::{self, Write};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Key, Nonce
};

use crate::ahasecret::client::AhaClient;

#[derive(Debug)]
struct ParsedUrl {
    key: String,
    nonce: String,
    path: String,
    bin_url: String
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
        key: String::from(secret_parts[0]).replace("\\", ""),
        nonce: String::from(secret_parts[1]).replace("\\", ""),
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

fn decrypt(parsed_url: ParsedUrl, payload: String) {
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
}

pub fn reveal(url: String, verbose: bool) {
    let mut ahaclient = AhaClient::new(verbose);
    let parsed = parse_decrypt_url(url, verbose);
    ahaclient.fetch_token(parsed.bin_url.clone());

    choose(); 

    let payload = ahaclient.reveal(parsed.bin_url.clone());
    decrypt(parsed, payload);
}
