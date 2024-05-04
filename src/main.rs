use clap::Parser;
use std::io::{self, Read};
use paris::error;
use paris::info;

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
    url: String,
    /// Retention time to keep the secret
    #[arg(short, long, default_value = "7d")]
    retention: String,
    /// Verbose output
    #[arg(short,long)]
    verbose: bool,
    /// Decrypt using a URL
    #[arg(short,long)]
    decrypt: bool,
    /// Force and do not ask questions.
    #[arg(short,long)]
    force: bool,
}

fn main() {
    let args = Config::parse();

    let mut buffer = Vec::<u8>::with_capacity(MAX_TEXT_LENGTH);
    let stdin = io::stdin();
    let mut counter = 0;

    let minutes: u32 = match ahasecret::utils::timeconvert(&args.retention) {
        Ok(num) => num,
        Err(error) => {
            error!("{:?}", error);
            std::process::exit(1)
        }
    };

    if args.decrypt {
        ahasecret::decrypt::reveal(args.url, args.verbose, args.force);
    }
    else {
        for byte in stdin.bytes() {
            if counter >= MAX_TEXT_LENGTH {
                error!("Input must be smaller than {} bytes", MAX_TEXT_LENGTH);
                std::process::exit(1)
            }
            buffer.push(byte.unwrap());
            counter = counter + 1;
        }

        if args.verbose {
            info!("Input length: {} bytes", buffer.len());
        }

        let encrypted = ahasecret::encrypt::encrypt(buffer, args.verbose);
        ahasecret::encrypt::send(encrypted, args.url, minutes, args.verbose);
    }
}
