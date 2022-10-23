use cargo_cryptile::*;
use std::env;
use std::process;
use sha256;

struct Config {
}

impl Config {
    fn parse(args: &Vec<String>) -> Result<Config, ()> {
        if args.len() < 3 {
            return Err(());
        }

        Ok(Config {
        })
    }
}


fn main() {
    let args: Vec<String> = env::args().collect();

    let config = match Config::parse(&args) {
        Ok(c) => c,
        Err(_) => {
            eprintln!("Usage: minigrep <QUERY_STRING> <FILEPATH>");
            process::exit(1);
        }
    };
}
