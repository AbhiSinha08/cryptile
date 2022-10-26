use hmac_sha256::Hash;

#[derive(Debug)]
enum Pass<'a> {
    Saved {
        identifier: &'a str
    },
    Given {
        given: &'a str
    },
    Master
}

#[derive(PartialEq, Debug)]
pub enum Operation<'a> {
    Encrypt,
    Decrypt,
    Set,
    Help(&'a str)
}

#[derive(Debug)]
pub struct Config<'a> {
    pub operation: Operation<'a>,
    file: Option<&'a str>,
    pass: Option<Pass<'a>>,
    replace: bool,
}

fn get_pass<'a>(flag: &'a str, p: Option<&'a String>) -> Option<Pass<'a>> {
    match flag {
        "-p" => {
            if let None = p {
                return None
            }
            return Some(Pass::Given { given: p.unwrap() })
        },
        "-s" | "--saved" => {
            if let None = p {
                return None
            }
            return Some(Pass::Saved { identifier: p.unwrap() })
        },
        "-m" | "--master" => {
            return Some(Pass::Master)
        },
        _ => return None
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
        let op = match args.get(x+1).unwrap_or(&"".to_owned()).as_str() {
            "encrypt" => Operation::Encrypt,
            "decrypt" => Operation::Decrypt,
            "set" => Operation::Set,
            "--help" | "-h" => {
                return Ok(Config {
                    operation: Operation::Help(HELP_TEXT),
                    file: None,
                    pass: None,
                    replace: false
                })
            },
            _ => return Err(HELP_TEXT)
        };

        if op == Operation::Encrypt || op == Operation::Decrypt {
            if let None = args.get(x+2) {
                return Err(HELP_TEXT)
            }
            let file;
            let pass;
            match args[x+2].as_str() {
                "-p" | "-s" | "--saved" | "-m" | "--master" => {
                    pass = match get_pass(&args[x+2], args.get(x+3)){
                        Some(p) => p,
                        _ => return Err(HELP_TEXT)
                    };
                    file = match args.get(x+4) {
                        Some(f) => f.as_str(),
                        _ => return Err(HELP_TEXT)
                    }
                },
                filename => {
                    file = filename;
                    if args.len() < x+4 {
                        return Err(HELP_TEXT)
                    }
                    pass = match get_pass(&args[x+3], args.get(x+4)) {
                        Some(p) => p,
                        _ => return Err(HELP_TEXT)
                    }
                }
            };
            let replace = args.contains(&"--replace".to_owned());

            return Ok(Config {
                operation: op,
                file: Some(file),
                pass: Some(pass),
                replace
            })
        }


        if op == Operation::Set {
            // TODO
        }


        return Err(HELP_TEXT);
    }

    pub fn get_key(&self) -> Result<[u8; 32], &str> {
        match self.pass.as_ref().unwrap() {
            Pass::Given { given } => {
                let pass: Vec<u8> = (*given).bytes().collect();
                return Ok(Hash::hash(&pass))
            },
            Pass::Saved { identifier } => {
                // TODO
            },
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