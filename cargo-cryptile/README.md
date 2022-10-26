# cargo-cryptile
cargo-cryptile is a CLI tool for encrypting and decrypting files with a password.

The file are encrypted using AES256 secure encryption with almost zero overhead.

## Install
```cargo install cargo-cryptile```

## Using Cryptile
Just run `cargo cryptile --help` for a list of available commands and options.

## Examples
```cargo cryptile encrypt "file.txt" -p password```
```cargo cryptile decrypt "file.txt.cryptile" -p password --replace```