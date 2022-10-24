use cargo_cryptile::*;
use std::env;
use std::process;
use sha256;

mod config;
use config::Config;


fn main() {
    let args: Vec<String> = env::args().collect();

    let config = match Config::parse(&args) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("{}", m);
            process::exit(1);
        }
    };
}
