use std::io::{Read, Write};
use std::fs::File;
use std::io::{Error, ErrorKind};
use aes::Aes128;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};

enum Stage {
    Encrypt,
    Decrypt(Option<u8>)
}

fn read_bytes_as_blocks(filename: &str, stage: Stage) -> Result<Vec<[u8; 16]>, Error> {
    let mut file = File::open(filename)?;
    
    let mut bytes = Vec::new();

    loop {
        let mut block = [0u8; 16];
        match file.read(&mut block) {
            Ok(b) if b < 16 => {
                if let Stage::Encrypt = stage {
                    let padding = (16 - b) as u8;
                    block[16 - 1] = padding;
                    bytes.push(block);
                }
                break
            },
            Err(e) => return Err(Error::from(e)),
            Ok(_) => ()
        }
        bytes.push(block);
    }
    
    Ok(bytes)
}

fn cipher_init(key_str: &str) -> Aes128 {
    let mut key = [0u8; 16];
    for (i, byte) in key_str.bytes().enumerate() {
        key[i] = byte;
    }

    let key = GenericArray::from(key);
    Aes128::new(&key)
}

fn encrypt_bytes(blocks: &mut Vec<[u8; 16]>, key: &str) {
    let cipher = cipher_init(key);

    for byte_block in blocks.iter_mut() {
        let mut block = GenericArray::from(byte_block.to_owned());

        cipher.encrypt_block(&mut block);
        let mut encrypted_block = [0u8; 16];
        
        for (i, byte) in block.bytes().enumerate() {
            if let Ok(byte) = byte {
                encrypted_block[i] = byte;
            }
        }
        *byte_block = encrypted_block;
    }
}

fn decrypt_bytes(blocks: &mut Vec<[u8; 16]>, key: &str) -> u8 {
    let cipher = cipher_init(key);
    let mut padding = 0;

    for byte_block in blocks.iter_mut() {
        let mut block = GenericArray::from(byte_block.to_owned());

        cipher.decrypt_block(&mut block);
        let mut decrypted_block = [0u8; 16];
        
        for (i, byte) in block.bytes().enumerate() {
            if let Ok(byte) = byte {
                decrypted_block[i] = byte;
            }
        }
        *byte_block = decrypted_block;
        padding = decrypted_block.last().unwrap().clone();
    }
    padding
}

fn write_bytes_from_blocks(filename: &str, blocks: &Vec<[u8; 16]>, stage: Stage) -> Result<(), Error> {
    let mut file = match File::create(filename) {
        Ok(file) => file,
        Err(e) => return Err(e)
    };

    let mut blocks = blocks.iter().peekable();
    while let Some(block) = blocks.next() {
        if blocks.peek().is_none() {
            if let Stage::Decrypt(Some(padding)) = stage {
                let t = (16 - padding) as usize;
                if let Err(e) = file.write(&block[..t]) {
                    return Err(e)
                }
                break
            }
        }
        if let Err(e) = file.write(block) {
            return Err(e)
        }
    }

    Ok(())
}


#[cfg(test)]
mod tests {
    use super::*;
    const TEST_KEY: &str = "0123456789ABCDEF";

    #[test]
    fn encrypt_file() {
        let mut blocks = read_bytes_as_blocks("test.txt", Stage::Encrypt)
                                            .expect("Some error in reading");
        println!("bytes: {:?}", blocks);
        encrypt_bytes(&mut blocks, TEST_KEY);
        println!("encrypted bytes: {:?}", blocks);
        write_bytes_from_blocks("test.txt.cryptile", &blocks, Stage::Encrypt)
            .expect("Some error in writing");
    }

    #[test]
    fn decrypt_file() {
        let mut blocks = read_bytes_as_blocks("test.txt.cryptile", Stage::Decrypt(None))
                                            .expect("Some error in reading");
        println!("bytes: {:?}", blocks);
        let padding = decrypt_bytes(&mut blocks, TEST_KEY);
        println!("decrypted bytes: {:?}\npadding:{}", blocks, padding);
        write_bytes_from_blocks("test2.txt", &blocks, Stage::Decrypt(Some(padding)))
            .expect("Some error in writing");
    }
}