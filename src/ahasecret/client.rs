use scraper::{Html, Selector};
use paris::{info, error};
use url::Url;

#[derive(Debug)]
pub struct AhaClient {
    pub client: reqwest::blocking::Client,
    token: String,
    verbose: bool
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

    pub fn reveal(&mut self, url: String) -> String {
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
        return res.text().unwrap();
    }

}


