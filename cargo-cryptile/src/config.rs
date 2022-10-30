use directories::ProjectDirs;
use hmac_sha256::Hash;
use std::io::Write;
use std::path::PathBuf;
use std::fs::{self, File};
use toml;
use serde::Deserialize;

fn config_path() -> Option<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "cryptile", "cryptile") {
        let mut path = proj_dirs.config_dir().to_owned();
        path.push("saved.toml");
        return Some(path);

        // Linux:   /home/username/.config/cryptile/saved.toml
        // Windows: C:\Users\Username\AppData\Roaming\cryptile\cryptile\saved.toml
        // macOS:   /Users/Username/Library/Application Support/com.cryptile.cryptile/saved.toml
    }
    None
}

enum Pass<'a> {
    Saved { identifier: &'a str },
    Given { given: &'a str },
    Master,
}

#[derive(Deserialize)]
struct Key {
    key: [u8; 32],
    identifier: String
}

#[derive(Deserialize)]
struct SavedConfig {
    master: Option<[u8; 32]>,
    keys: Option<Vec<Key>>
}

#[derive(PartialEq)]
pub enum Operation<'a> {
    Encrypt,
    Decrypt,
    Set,
    Help(&'a str),
}

pub struct Config<'a> {
    pub operation: Operation<'a>,
    file: Option<&'a str>,
    pass: Option<Pass<'a>>,
    saved: Option<SavedConfig>,
    replace: bool,
}

fn get_pass<'a>(flag: &'a str, p: Option<&'a String>) -> Option<Pass<'a>> {
    match flag {
        "-p" => {
            if let None = p {
                return None;
            }
            return Some(Pass::Given { given: p.unwrap() });
        }
        "-s" | "--saved" => {
            if let None = p {
                return None;
            }
            return Some(Pass::Saved {
                identifier: p.unwrap(),
            });
        }
        "-m" | "--master" => return Some(Pass::Master),
        _ => return None,
    }
}

fn get_saved_pass() -> Result<SavedConfig, &'static str> {
    let path = match config_path() {
        Some(p) => p,
        None => {
            return Err("Error: No valid path for config file\
                        could be retrieved from\
                        the operating system")
        }
    };
    if !path.exists() {
        if let Err(_) = fs::create_dir_all(path.parent().unwrap()) {
            return Err("Error creating config file")
        }

        if let Err(_) = File::create(&path) {
            return Err("Error creating config file")
        }
    }
    let config_file = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Err("Error Reading the config file")
    };
    match toml::from_str(&config_file) {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("{}", e);
            return Err("Error parsing the Config File.")
        }
    }
}

impl<'a> Config<'a> {
    pub fn parse(args: &Vec<String>) -> Result<Config, &str> {
        let mut x = 0;
        for (i, arg) in args.iter().enumerate() {
            if arg == "cryptile" {
                x = i;
                break;
            }
        }
        // Config Parsing Logic
        let op = match args.get(x + 1).unwrap_or(&"".to_owned()).as_str() {
            "encrypt" => Operation::Encrypt,
            "decrypt" => Operation::Decrypt,
            "set" => Operation::Set,
            "--help" | "-h" => {
                return Ok(Config {
                    operation: Operation::Help(HELP_TEXT),
                    file: None,
                    pass: None,
                    saved: None,
                    replace: false,
                })
            }
            _ => return Err(HELP_TEXT),
        };

        if op == Operation::Encrypt || op == Operation::Decrypt {
            if let None = args.get(x + 2) {
                return Err(HELP_TEXT);
            }
            let file;
            let pass;
            match args[x + 2].as_str() {
                "-p" | "-s" | "--saved" | "-m" | "--master" => {
                    pass = match get_pass(&args[x + 2], args.get(x + 3)) {
                        Some(p) => p,
                        _ => return Err(HELP_TEXT),
                    };
                    file = match args.get(x + 4) {
                        Some(f) => f.as_str(),
                        _ => return Err(HELP_TEXT),
                    }
                }
                filename => {
                    file = filename;
                    if args.len() < x + 4 {
                        return Err(HELP_TEXT);
                    }
                    pass = match get_pass(&args[x + 3], args.get(x + 4)) {
                        Some(p) => p,
                        _ => return Err(HELP_TEXT),
                    }
                }
            };
            let replace = args.contains(&"--replace".to_owned());

            return Ok(Config {
                operation: op,
                file: Some(file),
                pass: Some(pass),
                saved: None,
                replace,
            });
        }

        if op == Operation::Set {
            let saved = match get_saved_pass() {
                Ok(s) => s,
                Err(m) => return Err(m)
            };

            return Ok(Config {
                operation: op,
                file: None,
                pass: None,
                saved: Some(saved),
                replace: false
            })
            // TODO
        }

        return Err(HELP_TEXT);
    }

    pub fn get_key(&self) -> Result<[u8; 32], &str> {
        match self.pass.as_ref().unwrap() {
            Pass::Given { given } => {
                let pass: Vec<u8> = (*given).bytes().collect();
                return Ok(Hash::hash(&pass));
            }
            Pass::Saved { identifier } => {
                // TODO
            }
            Pass::Master => {
                //TODO
            }
        };

        Err("Error Getting Password")
    }

    pub fn file(&self) -> Option<&str> {
        self.file
    }

    pub fn replace(&self) -> bool {
        self.replace
    }
}

const HELP_TEXT: &str = "\
        A Command line tool for encrypting and decrypting your files.\n\
        (Still In Development. set command and saved passwords won't work.)\n\
        \n\
        Usage:\n\
        \tcryptile [COMMAND] [FLAGS]\n\
        Commands:\n\
        \tencrypt <FILENAME> [PASSWORD_OPTIONS]       Encrypt file using given password\n\
        \tdecrypt <FILENAME> [PASSWORD_OPTIONS]       Decrypt file using given password\n\
        \t    Password Options:\n\
        \t        -p <PASSWORD>                       Specify a password\n\
        \t        -s, --saved <SAVED_IDENTIFIER>      Use a saved password using it's identifier\n\
        \t        -m, --master                        Use the master password (if set)\n\
        \tset [SET_OPTIONS]\n\
        \t    Set Options:\n\
        \t        -m, --master                        Set a master password\n\
        \t        -p                                  Save a password and it's identifier name\n\
        Flags:\n\
        \t-h, --help                                  Display this help information\n\
        \t--replace                                   Remove the original file after Encryption/Decryption\n\
          ";

