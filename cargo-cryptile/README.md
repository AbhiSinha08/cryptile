# cargo-cryptile
cargo-cryptile is a CLI tool for encrypting and decrypting files with a password.

The file are encrypted using AES256 secure encryption with almost zero overhead.

You can securely save your encryption passwords using `set` command to quickly encrypt and decrypt files using them.

## Install
```cargo install cargo-cryptile```

## Using Cryptile
Just run `cargo cryptile --help` for a list of available commands and options.

## Examples
- Encrypt a file with a password:   
  ```cargo cryptile encrypt "file.txt" -p <password>```
- Decrypt a file with a password and remove the encrypted file:      
  ```cargo cryptile decrypt "file.txt.cryptile" -p <password> --replace```
- Set a master password to use:  
  ```cargo cryptile set -m```
- Save a password along with an identifier to use:  
  ```cargo cryptile set -p```
- Encrypt a file using master password:  
  ```cargo cryptile encrypt file.txt -m```
- Decrypt a file using an identifier of a saved password:  
  ```cargo cryptile decrypt file.txt.cryptile -s my_pass```


### More Features To Be Added...