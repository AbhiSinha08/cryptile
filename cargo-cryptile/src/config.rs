use directories::ProjectDirs;
use hmac_sha256::Hash;
use serde::Deserialize;
use serde::Serialize;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use toml;

fn config_path() -> Option<PathBuf> {
    if let Some(proj_dirs) = ProjectDirs::from("com", "cryptile", "cryptile") {
        let mut path = proj_dirs.config_dir().to_owned();
        path.push(".saved.toml");
        return Some(path);

        // Linux:   /home/username/.config/cryptile/.saved.toml
        // Windows: C:\Users\Username\AppData\Roaming\cryptile\cryptile\.saved.toml
        // macOS:   /Users/Username/Library/Application Support/com.cryptile.cryptile/.saved.toml
    }
    None
}

#[derive(PartialEq)]
pub enum Pass<'a> {
    Saved { identifier: Option<&'a str> },
    Given { given: &'a str },
    Master,
}

#[derive(Deserialize, Serialize)]
struct Key {
    key: [u8; 32],
    identifier: String,
}

#[derive(Deserialize, Serialize)]
struct SavedConfig {
    master: Option<[u8; 32]>,
    keys: Option<Vec<Key>>,
}

impl SavedConfig {
    fn search(&self, id: &str) -> Option<[u8; 32]> {
        match self.keys
                    .as_ref()
                    .unwrap()
                    .iter()
                    .filter(|k| {
                        (*k).identifier == id
                    })
                    .next()
        {
            None => None,
            Some(k) => Some(k.key)
        }
    }
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
    pub pass: Option<Pass<'a>>,
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
                identifier: Some(p.unwrap()),
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
            return Err("Error creating config file");
        }

        if let Err(_) = File::create(&path) {
            return Err("Error creating config file");
        }
    }
    let config_file = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(_) => return Err("Error Reading the config file"),
    };
    match toml::from_str(&config_file) {
        Ok(s) => Ok(s),
        Err(e) => {
            eprintln!("{}", e);
            return Err("Error parsing the Config File.");
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
            if let None = args.get(x + 2) {
                return Err(HELP_TEXT);
            }

            let saved = match get_saved_pass() {
                Ok(s) => s,
                Err(m) => return Err(m),
            };

            let pass;
            match args[x + 2].as_str() {
                "-p" => pass = Pass::Saved { identifier: None },
                "-m" | "--master" => pass = Pass::Master,
                _ => return Err(HELP_TEXT),
            }

            return Ok(Config {
                operation: op,
                file: None,
                pass: Some(pass),
                saved: Some(saved),
                replace: false,
            });
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
                let saved = match get_saved_pass() {
                    Ok(s) => s,
                    Err(m) => return Err(m),
                };

                match saved.keys {
                    Some(_) => {
                        match saved.search(identifier.unwrap()) {
                            Some(k) => Ok(k),
                            None => Err("No saved password with the given identifier found")
                        }
                    }
                    None => Err("No Passwords saved.\n\
                                Save one using `cryptile set -p` command")  
                }
            }
            Pass::Master => {
                let saved = match get_saved_pass() {
                    Ok(s) => s,
                    Err(m) => return Err(m),
                };

                match saved.master {
                    Some(m) => Ok(m),
                    None => Err("No master password set.\n\
                                Set one using `cryptile set -m` command"),
                }
            }
        }
    }

    pub fn set_pass(&mut self, pass: String, id: Option<String>) {
        if self.operation == Operation::Set {
            let pass: Vec<u8> = pass.bytes().collect();
            let pass = Hash::hash(&pass);

            if let Some(Pass::Master) = self.pass {
                let mut saved = self.saved.take().unwrap();
                saved.master = Some(pass);
                self.saved = Some(saved);
            } else if let Some(Pass::Saved { identifier: _ }) = self.pass {
                let mut saved = self.saved.take().unwrap();

                let mut keys = match saved.keys {
                    Some(keys) => keys,
                    None => Vec::new(),
                };

                keys.push(Key {
                    key: pass,
                    identifier: id.unwrap(),
                });
                saved.keys = Some(keys);
                self.saved = Some(saved);
            }
        }
    }

    pub fn file(&self) -> Option<&str> {
        self.file
    }

    pub fn replace(&self) -> bool {
        self.replace
    }
}

impl<'a> Drop for Config<'a> {
    fn drop(&mut self) {
        if let Some(saved) = &self.saved {
            let config_file = toml::to_string(saved).unwrap();

            let path = config_path().unwrap();
            File::create(path)
                .unwrap()
                .write(config_file.as_bytes())
                .unwrap();
        }
    }
}

const HELP_TEXT: &str = "\
        A Command line tool for encrypting and decrypting your files.\n\
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
