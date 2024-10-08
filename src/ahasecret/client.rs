use scraper::{Html, Selector};
use paris::{info, warn, error};
use url::Url;
use serde::{Deserialize};
use serde_json;

#[derive(Debug)]
pub struct AhaClient {
    pub client: reqwest::blocking::Client,
    token: String,
    verbose: bool
}

#[derive(Deserialize, Debug)]
pub struct Bin {
    pub id: String,
    pub url: String
}

#[derive(Deserialize, Debug)]
pub struct CryptBin {
    pub payload: String,
    pub has_password: bool
}

impl AhaClient {

    pub fn new(verbose: bool) -> Self {
        const APP_USER_AGENT: &str = concat!(
                env!("CARGO_PKG_NAME"),
                "/",
                env!("CARGO_PKG_VERSION")
        );

        if verbose {
            info!("User-Agent: {}", APP_USER_AGENT);
        }

        Self { client: reqwest::blocking::Client::builder()
                        .cookie_store(true)
                        .user_agent(APP_USER_AGENT)
                        .build()
                        .unwrap(),
                token: String::new(),
                verbose: verbose
        }
    }

    pub fn fetch_token(&mut self, url: String) -> String {
        let res = self.client.get(url.as_str())
            .send()
            .unwrap_or_else(|e| {
                error!("Request failed: {}", e);
                std::process::exit(1);
            });
    
        let document = Html::parse_document(&res.text().unwrap());
        let selector = Selector::parse(r#"meta[name="authenticity_token"]"#).unwrap();
        for element in document.select(&selector) {
            self.token = String::from(element.value().attr("content").unwrap());
        }
        return self.token.clone();
    }

    pub fn reveal(&mut self, url: String) -> CryptBin {
        let mut patch_base: String = url.clone(); 
        patch_base.push_str("/reveal");
    
        let mut patch_url = Url::parse(patch_base.as_str()).unwrap();
        patch_url.query_pairs_mut().append_pair("authenticity_token", self.token.as_str());
        if self.verbose {
            info!("Reveal-URL: {}", patch_url);
        }

        let res = self.client.patch(patch_url.as_str())
            .send()
            .unwrap_or_else(|e| {
                error!("Request failed: {}", e);
                std::process::exit(1);
            });

        let status = res.status();
    
        if ! status.is_success() {
            error!("Warning status code {}: Revealing the secret failed", status.as_str());
            std::process::exit(1)
        }
    
        let jres: CryptBin = serde_json::from_str(res.text().unwrap().as_str())
            .unwrap_or_else(|e| {
                error!("Parsing JSON failed: {}", e);
                std::process::exit(1);
            });

        return jres;
    }

    pub fn store_secret(&mut self, url: &str, cipher: &str, extra_pw: bool, retention: u32) -> String {
        let mut has_pw = String::from("false");
        if extra_pw {
            has_pw = String::from("true");
        }
        let encoded_data: String = form_urlencoded::Serializer::new(String::new())
            .append_pair("bin[payload]", cipher)
            .append_pair("bin[has_password]", has_pw.as_str())
            .append_pair("retention", retention.to_string().as_str())
            .append_pair("authenticity_token", self.token.as_str())
            .finish();
    
        let res = self.client.post(url)
            .body(encoded_data)
            .send()
            .unwrap_or_else(|e| {
                error!("Sending data failed: {}", e);
                std::process::exit(1);
            });
    
        let status = res.status();
    
        if ! status.is_success() {
            error!("Warning status code {}: maybe the message was to long", status.as_str());
            warn!("Length of encrypted message: {} bytes", cipher.len());
            std::process::exit(1)
        }
    
        let jres: Bin = serde_json::from_str(res.text().unwrap().as_str())
            .unwrap_or_else(|e| {
                error!("Parsing JSON failed: {}", e);
                std::process::exit(1);
            });

        return jres.id;
    }
}


