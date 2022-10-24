enum Pass<'a> {
    Saved {
        identifier: &'a str
    },
    Given {
        given: &'a str
    },
    Master
}

enum Operation<'a> {
    Encrypt,
    Decrypt,
    Set,
    Help(&'a str)
}

pub struct Config<'a> {
    operation: Operation<'a>,
    file: Option<&'a str>,
    pass: Option<Pass<'a>>,
    replace: bool,
}


impl<'a> Config<'a> {
    pub fn parse(args: &Vec<String>) -> Result<Config, &str> {
        
        // Config Parsing Logic

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