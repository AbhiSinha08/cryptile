# **Cryptile**
### A **Desktop App** and **CLI tool** to encrypt and decrypt your files with a secure password :lock:. Military grade fast encryption with almost zero overhead.

## (GUI in develpoment)

- Uses AES256 Encryption
- written in Rust :crab:
- GUI made using Tauri and React
  
</br>

### To start the GUI - dev :
- install `rustc, cargo, npm`
- clone the repo and `cd` into the folder
- `npm install` and `cargo install tauri-cli`
- (optional) `npm run tailwind`
- `cargo tauri dev`

### Production Build GUI :
- `npm run tailwind_build`
- `cargo tauri build`

### CLI Tool:
- Currently only available via cargo
- install `rustc, cargo`
- [CLI Tool](cargo-cryptile/README.md)