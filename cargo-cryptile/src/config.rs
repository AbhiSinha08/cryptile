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
enum Operation<'a> {
    Encrypt,
    Decrypt,
    Set,
    Help(&'a str)
}

#[derive(Debug)]
pub struct Config<'a> {
    operation: Operation<'a>,
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
        
        // Config Parsing Logic
        let op = match args.get(1).unwrap_or(&"".to_owned()).as_str() {
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
            if let None = args.get(2) {
                return Err(HELP_TEXT)
            }
            let file;
            let pass;
            match args[2].as_str() {
                "-p" | "-s" | "--saved" | "-m" | "--master" => {
                    pass = match get_pass(&args[2], args.get(3)){
                        Some(p) => p,
                        _ => return Err(HELP_TEXT)
                    };
                    file = match args.get(4) {
                        Some(f) => f.as_str(),
                        _ => return Err(HELP_TEXT)
                    }
                },
                filename => {
                    file = filename;
                    if args.len() < 4 {
                        return Err(HELP_TEXT)
                    }
                    pass = match get_pass(&args[3], args.get(4)) {
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
}



const HELP_TEXT: &str = "\
        A Command line tool for encrypting and decrypting your files.\n\
        (Still In Development. Won't Work.)\n\
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