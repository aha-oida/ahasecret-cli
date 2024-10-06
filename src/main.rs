use clap::Parser;
use std::io::{self, Read};
use paris::error;
use paris::info;
use linkify::{LinkFinder};


/*
 * Currently the backend allows max 10000 characters.
 * When 7450 bytes are encrypted, it is just below this
 * limit.
 */
const MAX_TEXT_LENGTH: usize = 7450;

pub mod ahasecret;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
struct Config {
    /// The url to aha-secret
    #[arg(short,long)]
    url: Option<String>,
    /// Retention time to keep the secret
    #[arg(short, long, default_value = "7d")]
    retention: String,
    /// Verbose output
    #[arg(short,long)]
    verbose: bool,
    /// Decrypt using a URL
    #[arg(short,long)]
    decrypt: bool,
    /// Use extra password
    #[arg(short, long)]
    password: bool,
    /// Force and do not ask questions.
    #[arg(short,long)]
    force: bool,
}

fn read_bytewise_from_stdin(buffer: &mut Vec::<u8>) {
    let mut counter = 0;
    let stdin = io::stdin();
    for byte in stdin.bytes() {
        if counter >= MAX_TEXT_LENGTH {
            error!("Input must be smaller than {} bytes", MAX_TEXT_LENGTH);
            std::process::exit(1)
        }
        buffer.push(byte.unwrap());
        counter = counter + 1;
    }
}

fn read_url_from_stdin() -> String {
    let mut buffer = String::new();
    let stdin = io::stdin();
    stdin.read_line(&mut buffer)
        .unwrap_or_else(|e| {
            error!("Read url from stdin failed: {}", e);
            std::process::exit(1);
        });

    let finder = LinkFinder::new();
    let links: Vec<_> = finder.links(buffer.as_str()).collect();

    if links.len() < 1 {
        error!("Unable to find url in provided input(stdin)");
        std::process::exit(1);
    }

    return String::from(links[0].as_str());
}

fn main() {
    let args = Config::parse();
    let mut extra_pw = false;

    let mut buffer = Vec::<u8>::with_capacity(MAX_TEXT_LENGTH);

    let minutes: u32 = match ahasecret::utils::timeconvert(&args.retention) {
        Ok(num) => num,
        Err(error) => {
            error!("{:?}", error);
            std::process::exit(1)
        }
    };

    if args.decrypt {
        let url = match args.url {
            Some(x) => x,
            None => {
                read_url_from_stdin()
            }
        };

        ahasecret::decrypt::reveal(url, args.verbose, args.force);
    }
    else {
        read_bytewise_from_stdin(&mut buffer);

        /* 
         * do not put this block above read_bytewise_from_stdin
         * this would mess up the encryption
         */
        if args.password {
            if args.force {
                error!("Interactive password and force can not be used together");
                std::process::exit(1)
            }
            let custompw = ahasecret::utils::read_password_from_stdin();
            buffer = ahasecret::encrypt::encrypt_with_pass(buffer, custompw, args.verbose);
            extra_pw = true;
        }

        let url = match args.url {
            Some(x) => x,
            None => {
                error!("Url is required for encryption");
                std::process::exit(1)
            }
        };

        if args.verbose {
            info!("Input length: {} bytes", buffer.len());
        }

        let encrypted = ahasecret::encrypt::encrypt(buffer, args.verbose);
        ahasecret::encrypt::send(encrypted, url, extra_pw, minutes, args.verbose);
    }
}
