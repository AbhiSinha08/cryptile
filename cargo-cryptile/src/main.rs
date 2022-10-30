use cargo_cryptile as cryptile;
use std::env;
use std::process;
use std::io::{self, ErrorKind, Write};
use dialoguer::Password;

mod config;
use config::{Config, Operation, Pass};


impl<'a> Config<'a> {
    fn get_args(&self) -> ([u8; 32], &str, bool) {
        let key = match self.get_key() {
            Ok(k) => k,
            Err(m) => {
                eprintln!("{}", m);
                process::exit(1)
            }
        };
        let filename = self.file().unwrap();
        let replace = self.replace();

        (key, filename, replace)
    }
}

fn get_pass_input() -> String {
    let password = Password::new().with_prompt("Enter a password")
        .with_confirmation("Confirm password", "Passwords mismatching")
        .interact();

    match password {
        Err(_) => {
            eprintln!("Cannot read from the stdin");
            process::exit(1)
        }
        Ok(password) => password
    }
}

fn get_input(s: &str) -> String {
    print!("{}", s);
    io::stdout().flush().unwrap();

    let mut input = String::new();

    if let Err(_) = io::stdin().read_line(&mut input) {
        eprintln!("Cannot read from the stdin");
        process::exit(1)
    }
    input.trim().to_owned()
}

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut config = match Config::parse(&args) {
        Ok(c) => c,
        Err(m) => {
            eprintln!("{}", m);
            process::exit(1);
        }
    };

    match config.operation {
        Operation::Help(text) => {
            println!("{text}");
            process::exit(0);
        },
        Operation::Encrypt => {
            let (key, filename, replace) = config.get_args();

            if let Err(e) = cryptile::encrypt(filename, &key) {
                let new_name = filename.to_owned() + cryptile::FILE_EXTENSION;
                match e.kind() {
                    ErrorKind::NotFound => {
                        eprintln!("Error: File Not Found!");
                        process::exit(1);
                    }
                    ErrorKind::PermissionDenied => {
                        eprintln!("Error: Permission Denied");
                        process::exit(1);
                    }
                    _ => {
                        cryptile::delete(&new_name);
                        eprintln!("{}", e);
                        process::exit(1)
                    }
                }
            }
            println!("Successfully Encrypted the file");
            if replace {
                cryptile::delete(filename);
            }
        }
        Operation::Decrypt => {
            let (key, filename, replace) = config.get_args();

            if let Err(e) = cryptile::decrypt(filename, &key) {
                let new_name = filename.replace(cryptile::FILE_EXTENSION, "");
                match e.kind() {
                    ErrorKind::Unsupported => {
                        eprintln!("Error: Unsupported File type");
                        process::exit(1)
                    }
                    ErrorKind::PermissionDenied => {
                        eprintln!("Error: Permission Denied");
                        process::exit(1);
                    }
                    ErrorKind::InvalidInput => {
                        eprintln!("Error: Wrong key given");
                        process::exit(1)
                    }
                    ErrorKind::NotFound => {
                        eprintln!("Error: File Not Found!");
                        process::exit(1);
                    }
                    ErrorKind::UnexpectedEof => {
                        eprintln!("Error: Unexpected End of File");
                        process::exit(1)
                    }
                    _ => {
                        cryptile::delete(&new_name);
                        eprintln!("{}", e);
                        process::exit(1)
                    }
                }
            }
            println!("Successfully Decrypted the file");
            if replace {
                cryptile::delete(filename);
            }
        }
        Operation::Set => {
            match config.pass.as_ref().unwrap() {
                Pass::Master => {
                    let pass = get_pass_input();
                    config.set_pass(pass, None);
                }
                Pass::Saved { identifier: _ } => {
                    let pass = get_pass_input();
                    let id = get_input("Enter an identifier: ");
                    config.set_pass(pass, Some(id));
                }
                _ => ()
            }
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pw_input() {
        let p = get_pass_input();

        println!("start->{}<-end", p);
    }
}