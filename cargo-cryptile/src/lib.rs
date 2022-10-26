//! Cryptile:
//! CLI tool for Encrypting and Decrypting files
//! with a password using AES256 encryption
//! 
//! # Example
//! ```
//! ```


use std::io::{Read, Write};
use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use threads_pool::ThreadPool;
use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use hmac_sha256::Hash;

enum Stage {
    Encrypt,
    Decrypt(Option<u8>)
}

const SMALL_FILE_SIZE_LIMIT: u64 = 26_214_400 * 3;
const _CHUNK_SIZE: usize = 26_214_400;
pub const FILE_EXTENSION: &str = ".cryptile";


fn cipher_init(key: &[u8; 32]) -> Aes256 {
    let key = GenericArray::from(*key);
    Aes256::new(&key)
}

fn encrypt_chunk_serially(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256) {
    for byte_block in blocks.iter_mut() {
        let mut block = GenericArray::from(byte_block.to_owned());

        cipher.encrypt_block(&mut block);
        
        for (i, byte) in block.bytes().enumerate() {
            if let Ok(byte) = byte {
                (*byte_block)[i] = byte;
            }
        }
    }
}

fn decrypt_chunk_serially(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256) {
    for byte_block in blocks.iter_mut() {
        let mut block = GenericArray::from(byte_block.to_owned());

        cipher.decrypt_block(&mut block);
        
        for (i, byte) in block.bytes().enumerate() {
            if let Ok(byte) = byte {
                (*byte_block)[i] = byte;
            }
        }
    }
}

fn _encrypt_chunk_parallelly(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256, n_threads: usize) {
    let pool = ThreadPool::new(n_threads);

    for byte_block in blocks.iter_mut() {
        let block_ptr = byte_block as *mut [u8; 16];
        let block_ptr = block_ptr as usize;

        let cipher_ptr = cipher as *const Aes256;
        let cipher_ptr = cipher_ptr as usize;
        pool.execute(move || {
            let block_ptr = block_ptr as *mut [u8; 16];
            let cipher = cipher_ptr as *const Aes256;
            unsafe {
                let mut block = GenericArray::from(*(block_ptr).to_owned());

                (*cipher).encrypt_block(&mut block);
                
                for (i, byte) in block.bytes().enumerate() {
                    if let Ok(byte) = byte {
                        (*block_ptr)[i] = byte;
                    }
                }
            }
        }).unwrap();
    }
}

fn _decrypt_chunk_parallelly(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256, n_threads: usize) {
    let pool = ThreadPool::new(n_threads);

    for byte_block in blocks.iter_mut() {
        let block_ptr = byte_block as *mut [u8; 16];
        let block_ptr = block_ptr as usize;

        let cipher_ptr = cipher as *const Aes256;
        let cipher_ptr = cipher_ptr as usize;
        pool.execute(move || {
            let block_ptr = block_ptr as *mut [u8; 16];
            let cipher = cipher_ptr as *const Aes256;
            unsafe {
                let mut block = GenericArray::from(*(block_ptr).to_owned());

                (*cipher).decrypt_block(&mut block);
                
                for (i, byte) in block.bytes().enumerate() {
                    if let Ok(byte) = byte {
                        (*block_ptr)[i] = byte;
                    }
                }
            }
        }).unwrap();
    }
}

fn encrypt_small_file(r_file: &mut File, cipher: &Aes256, w_file: &mut File) -> Result<(), Error> {
    let mut blocks = read_entire_as_blocks(r_file, Stage::Encrypt)?;
    encrypt_chunk_serially(&mut blocks, &cipher);
    write_entire_from_blocks(w_file, &blocks, Stage::Encrypt)?;

    Ok(())
}

fn decrypt_small_file(r_file: &mut File, cipher: &Aes256, w_file: &mut File) -> Result<(), Error> {
    let mut blocks = read_entire_as_blocks(r_file, Stage::Decrypt(None))?;
    decrypt_chunk_serially(&mut blocks, &cipher);
    let last_block = blocks.last();
    if let Some(block) = last_block {
        if let Some(padding) = block.last() {
            write_entire_from_blocks(w_file, &blocks, Stage::Decrypt(Some(*padding)))?;
        }
        else {
            return Err(Error::from(ErrorKind::UnexpectedEof))
        }
    }
    else {
        return Err(Error::from(ErrorKind::UnexpectedEof))
    }
    Ok(())
}

fn hash_encrypt_write(hash: [u8; 32], cipher: &Aes256, file: &mut File) -> Result<(), Error> {
    let mut temp_block = [0u8; 16];
    for (i, byte) in hash[0..16].iter().enumerate() {
        temp_block[i] = *byte;
    }
    let mut block1 = GenericArray::from(temp_block);

    let mut temp_block = [0u8; 16];
    for (i, byte) in hash[16..32].iter().enumerate() {
        temp_block[i] = *byte;
    }
    let mut block2 = GenericArray::from(temp_block);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    file.write(&block1)?;
    file.write(&block2)?;
    Ok(())
}

fn hash_read_decrypt(cipher: &Aes256, file: &mut File) -> Result<[u8; 32], Error> {
    let mut block1 = [0u8; 16];
    let mut block2 = [0u8; 16];
    file.read(&mut block1)?;
    file.read(&mut block2)?;

    let mut block1 = GenericArray::from(block1);
    let mut block2 = GenericArray::from(block2);

    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    let mut res = [0u8; 32];
    let mut i: usize = 0;
    for byte in block1 {
        res[i] = byte;
        i += 1;
    }
    for byte in block2 {
        res[i] = byte;
        i += 1;
    }

    Ok(res)
}

fn read_entire_as_blocks(file: &mut File, stage: Stage) -> Result<Vec<[u8; 16]>, Error> {
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

fn write_entire_from_blocks(file: &mut File, blocks: &Vec<[u8; 16]>, stage: Stage) -> Result<(), Error> {

    let mut blocks = blocks.iter().peekable();
    while let Some(block) = blocks.next() {
        if blocks.peek().is_none() {
            if let Stage::Decrypt(Some(padding)) = stage {
                if padding > 16 {
                    return Err(Error::from(ErrorKind::InvalidInput));
                }
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

/// Function to encrypt a file using a 32-bit key
/// Returns Result type 
/// 
/// # Errors
/// This function will return an appropriate variant of
/// `std::io::Error` if there is any error reading the file
/// or creating the encrypted file
pub fn encrypt(filename: &str, key: &[u8; 32]) -> Result<(), Error> {
    let key_hash = Hash::hash(key);
    let cipher = cipher_init(key);
    let new_file_name = filename.to_owned() + FILE_EXTENSION;

    let mut reader = File::open(filename)?;
    let size = reader.metadata()?.len();
    let mut writer = File::create(&new_file_name)?;

    hash_encrypt_write(key_hash, &cipher, &mut writer)?;

    if size < SMALL_FILE_SIZE_LIMIT {
        encrypt_small_file(&mut reader, &cipher, &mut writer)?;
    }
    else {
        encrypt_small_file(&mut reader, &cipher, &mut writer)?;
        // encrypt_large_file()?;
    }

    Ok(())
}

/// Function to decrypt a previously ecrypted file using the `encrypt` function
/// Returns Result type
/// 
/// # Errors
/// This function will return an appropriate variant of
/// `std::io::Error` if there is any error reading the file
/// or creating the decrypted file.
/// 
/// If the file given as the arguement isn't a file encrypted
/// with this tool (i.e. not ending with .cryptile),
/// It will give a `std::io::ErrorKind::Unsupported` error.
/// 
/// If the key given as the arguement isn't the key used to
/// encrypt the file and can't be used as a decryption key,
/// It will give a `std::io::ErrorKind::InvalidInput` error.
pub fn decrypt(filename: &str, key: &[u8; 32]) -> Result<(), Error> {
    if !filename.ends_with(FILE_EXTENSION) {
        return Err(Error::from(ErrorKind::Unsupported))
    }

    let key_hash = Hash::hash(key);
    let cipher = cipher_init(key);

    let new_file_name = filename.replace(FILE_EXTENSION, "");

    let mut reader = File::open(filename)?;
    let size = reader.metadata()?.len();

    let hash = hash_read_decrypt(&cipher, &mut reader)?;
    if key_hash != hash {
        return Err(Error::from(ErrorKind::InvalidInput))
    }
    let mut writer = File::create(&new_file_name)?;

    if size < SMALL_FILE_SIZE_LIMIT {
        decrypt_small_file(&mut reader, &cipher, &mut writer)?;
    }
    else {
        decrypt_small_file(&mut reader, &cipher, &mut writer)?;
        // encrypt_large_file()?;
    }

    Ok(())
}

// pub fn encrypt_parallel(filename: &str, key: &str) -> Result<(), Error> {
//     Ok(())
// }

// pub fn decrypt_parallel(filename: &str, key: &str) -> Result<(), Error> {
//     Ok(())
// }

// pub fn encrypt_parallel_with(filename: &str, key: &str, n_threads: usize) -> Result<(), Error> {
//     Ok(())
// }

// pub fn decrypt_parallel_with(filename: &str, key: &str, n_threads: usize) -> Result<(), Error> {
//     Ok(())
// }


/// Function to determine whether a key is correct for an encrypted file
/// Returns a `Result<bool>` type
/// 
/// # Errors
/// This function will return an appropriate variant of
/// `std::io::Error` if there is any error reading the file
/// 
/// If the file given as the arguament isn't a file encrypted
/// with this tool (i.e. not ending with .cryptile),
/// It will give a `std::io::ErrorKind::Unsupported` error.
pub fn is_correct_key(filename: &str, key: &[u8; 32]) -> Result<bool, Error> {
    if !filename.ends_with(FILE_EXTENSION) {
        return Err(Error::from(ErrorKind::Unsupported))
    }

    let key_hash = Hash::hash(key);
    let cipher = cipher_init(key);
    let mut reader = File::open(filename)?;

    let hash = hash_read_decrypt(&cipher, &mut reader)?;
    if key_hash != hash {
        return Ok(false)
    }

    Ok(true)
}

/// Function to try to delete a file from filesystem
/// to be called after encryption or decryption to delete the original file
/// Ignores whether the delete operation fails or not
pub fn delete(filename: &str) {
    _ = fs::remove_file(filename);
}



pub mod benches {
    use super::*;

    pub fn bench_serially_encrypt(filename: &str) {
        let pass = "0123456789ABCDEF";
        let pass: Vec<u8> = (*pass).bytes().collect();
        let key = Hash::hash(&pass);
        encrypt(filename, &key).expect("Error in Encrypting");
    }

    // pub fn bench_parallelly_encrypt(filename: &str) {}

    pub fn bench_serially_decrypt(filename: &str) {
        let pass = "0123456789ABCDEF";
        let pass: Vec<u8> = (*pass).bytes().collect();
        let key = Hash::hash(&pass);
        decrypt(filename, &key).expect("Error in Decrypting");
    }

    // pub fn bench_parallelly_decrypt(filename: &str) {}

}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use std::thread;
    use std::thread::available_parallelism;
    const TEST_KEY: &str = "0123456789ABCDEF0123456789ABCDEF";

    #[test]
    fn encrypt_file() {
        let pass = "0123456789ABCDEF";
        let pass: Vec<u8> = (*pass).bytes().collect();
        let key = Hash::hash(&pass);
        encrypt("test.jpg", &key).expect("Error in Encrypting");
    }

    #[test]
    fn decrypt_file() {
        let pass = "0123456789ABCDEF";
        let pass: Vec<u8> = (*pass).bytes().collect();
        let key = Hash::hash(&pass);
        decrypt("test.jpg.cryptile", &key).expect("Error in Decrypting");
    }

    #[test]
    fn num_cpus() {
        let default_parallelism_approx = available_parallelism().unwrap().get();

        println!("Number of availaible parallelism: {}", default_parallelism_approx);
    }

    #[test]
    fn thread_pool_test() {
        let pool = ThreadPool::new(4);
        
        for i in 1..=10 {
            println!("Starting thread {}", i);
            pool.execute(move || {
                thread::sleep(Duration::from_secs(1));
                println!("thread {} finished", i);
            }).unwrap();
        }
        
        drop(pool);

        println!("finished function... All tasks should be completed before this");
    }
}