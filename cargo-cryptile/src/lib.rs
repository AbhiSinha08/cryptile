use std::io::{Read, Write};
use std::fs::{self, File};
use std::io::{Error, ErrorKind};
use std::time::Duration;
use std::thread::{
    self,
    available_parallelism
};
use threads_pool::ThreadPool;
use aes::Aes256;
use aes::cipher::{
    BlockEncrypt, BlockDecrypt, KeyInit,
    generic_array::GenericArray,
};
use sha256;

enum Stage {
    Encrypt,
    Decrypt(Option<u8>)
}

const SMALL_FILE_SIZE_LIMIT: u64 = 26_214_400 * 3;
const CHUNK_SIZE: usize = 26_214_400;
const FILE_EXTENSION: &str = ".cryptile";


fn cipher_init(key_str: &str) -> Aes256 {
    let mut key = [0u8; 32];
    for (i, byte) in key_str.bytes().enumerate() {
        key[i] = byte;
    }

    let key = GenericArray::from(key);
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

fn encrypt_chunk_parallelly(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256, n_threads: usize) {
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

fn decrypt_chunk_parallelly(blocks: &mut Vec<[u8; 16]>, cipher: &Aes256, n_threads: usize) {
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
    let mut blocks = read_entire_as_blocks(r_file, Stage::Encrypt)?;
    decrypt_chunk_serially(&mut blocks, &cipher);
    write_entire_from_blocks(w_file, &blocks, Stage::Encrypt)?;

    Ok(())
}

fn hash_encrypt_write(hash: String, cipher: &Aes256, file: &mut File) -> Result<(), Error> {
    let mut temp_block = [0u8; 16];
    for (i, byte) in hash[0..16].as_bytes().iter().enumerate() {
        temp_block[i] = *byte;
    }
    let mut block1 = GenericArray::from(temp_block);

    let mut temp_block = [0u8; 16];
    for (i, byte) in hash[16..32].as_bytes().iter().enumerate() {
        temp_block[i] = *byte;
    }
    let mut block2 = GenericArray::from(temp_block);

    cipher.encrypt_block(&mut block1);
    cipher.encrypt_block(&mut block2);

    file.write(&block1)?;
    file.write(&block2)?;
    Ok(())
}

fn hash_read_decrypt(cipher: &Aes256, file: &mut File) -> Result<String, Error> {
    let mut block1 = [0u8; 16];
    let mut block2 = [0u8; 16];
    file.read(&mut block1)?;
    file.read(&mut block2)?;

    let mut block1 = GenericArray::from(block1);
    let mut block2 = GenericArray::from(block2);

    cipher.decrypt_block(&mut block1);
    cipher.decrypt_block(&mut block2);

    let key1: String = block1.iter().map(|byte| {
        *byte as char
    }).collect();
    let key2: String = block2.iter().map(|byte| {
        *byte as char
    }).collect();

    Ok(key1 + &key2)
}


// TODO
pub fn encrypt(filename: &str, key: &str) -> Result<(), Error> {
    let key_hash = sha256::digest(key);
    let cipher = cipher_init(key);
    let new_file_name = filename.to_owned() + FILE_EXTENSION;

    let mut reader = File::open(filename)?;
    let size = reader.metadata()?.len();
    let mut writer = File::open(&new_file_name)?;

    hash_encrypt_write(key_hash, &cipher, &mut writer)?;

    if size < SMALL_FILE_SIZE_LIMIT {
        encrypt_small_file(&mut reader, &cipher, &mut writer)?;
    }
    else {
        // encrypt_large_file()?;
    }

    Ok(())
}

pub fn decrypt(filename: &str, key: &str) -> Result<(), Error> {
    let key_hash = sha256::digest(key);
    let cipher = cipher_init(key);

    if !filename.ends_with(FILE_EXTENSION) {
        return Err(Error::from(ErrorKind::Unsupported))
    }

    let new_file_name = filename.replace(FILE_EXTENSION, "");

    let mut reader = File::open(filename)?;
    let size = reader.metadata()?.len();
    let mut writer = File::open(&new_file_name)?;

    let hash = hash_read_decrypt(&cipher, &mut reader)?;
    if key_hash != hash {
        return Err(Error::from(ErrorKind::InvalidInput))
    }

    if size < SMALL_FILE_SIZE_LIMIT {
        decrypt_small_file(&mut reader, &cipher, &mut writer)?;
    }
    else {
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

pub fn is_correct_key(filename: &str, key: &str) -> Result<bool, Error> {
    let key_hash = sha256::digest(key);
    let cipher = cipher_init(key);
    let mut reader = File::open(filename)?;

    let hash = hash_read_decrypt(&cipher, &mut reader)?;
    if key_hash != hash {
        return Ok(false)
    }

    Ok(true)
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







// To be removed

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

fn write_bytes_from_blocks(filename: &str, blocks: &Vec<[u8; 16]>, stage: Stage) -> Result<(), Error> {
    let mut file = match File::create(filename) {
        Ok(file) => file,
        Err(e) => return Err(e)
    };

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


pub mod benches {
    use super::*;

    pub fn bench_serially_encrypt(filename: &str) {
        let cipher = cipher_init("0123456789ABCDEF0123456789ABCDEF");
        let mut blocks = read_bytes_as_blocks(filename, Stage::Encrypt)
                                            .expect("Some error in reading");
        encrypt_chunk_serially(&mut blocks, &cipher);
        write_bytes_from_blocks(&(filename.to_owned() + "1.cryptile"), &blocks, Stage::Encrypt)
            .expect("Some error in writing");
    }

    pub fn bench_parallelly_encrypt(filename: &str) {
        let default_parallelism_approx = available_parallelism().unwrap().get();
        // let default_parallelism_approx = 8;
        let cipher = cipher_init("0123456789ABCDEF0123456789ABCDEF");
        let mut blocks = read_bytes_as_blocks(filename, Stage::Encrypt)
                                            .expect("Some error in reading");
        encrypt_chunk_parallelly(&mut blocks, &cipher, default_parallelism_approx);
        write_bytes_from_blocks(&(filename.to_owned() + "2.cryptile"), &blocks, Stage::Encrypt)
            .expect("Some error in writing");
    }

    pub fn bench_serially_decrypt(filename: &str) {
        let cipher = cipher_init("0123456789ABCDEF0123456789ABCDEF");
        let mut blocks = read_bytes_as_blocks(&(filename.to_owned() + "1.cryptile"), Stage::Encrypt)
                                            .expect("Some error in reading");
        decrypt_chunk_serially(&mut blocks, &cipher);
        // write_bytes_from_blocks(filename, &blocks, Stage::Encrypt)
        //     .expect("Some error in writing");
    }

    pub fn bench_parallelly_decrypt(filename: &str) {
        let default_parallelism_approx = available_parallelism().unwrap().get();
        // let default_parallelism_approx = 8;
        let cipher = cipher_init("0123456789ABCDEF0123456789ABCDEF");
        let mut blocks = read_bytes_as_blocks(&(filename.to_owned() + "2.cryptile"), Stage::Encrypt)
                                            .expect("Some error in reading");
        decrypt_chunk_parallelly(&mut blocks, &cipher, default_parallelism_approx);
        // write_bytes_from_blocks(filename, &blocks, Stage::Encrypt)
        //     .expect("Some error in writing");
    }

}

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_KEY: &str = "0123456789ABCDEF0123456789ABCDEF";

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
        let mut blocks = read_bytes_as_blocks("test2.jpg.cryptile", Stage::Decrypt(None))
                                            .expect("Some error in reading");
        println!("bytes: {:?}", blocks);
        let padding = decrypt_bytes(&mut blocks, TEST_KEY);
        println!("decrypted bytes: {:?}\npadding:{}", blocks, padding);
        write_bytes_from_blocks("test2_decrypted.jpg", &blocks, Stage::Decrypt(Some(padding)))
            .expect("Some error in writing");
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