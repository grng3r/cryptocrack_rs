use std::{
    error::Error,
    fs::File,
    io::{BufRead, BufReader, Lines}
};

use sha1::Digest;
use serde_json::{Map, Value};

const SHA1_HEX_STR_LEN: usize = 40;

//read lines from wordlist file
fn read_wordlist(filename: &str) -> Result<Lines<BufReader<File>>, &'static str> {
    let f = File::open(filename).map_err(|_| "[ERR] No wordlist")?;

    Ok(BufReader::new(f).lines())
}

//crack given hash by hashing values from wordlist
pub fn sha1_crack(hash: &str, wordlist: &str) -> Result<(), Box<dyn Error>> {
    if hash.len() != SHA1_HEX_STR_LEN {
        return Err("Not SHA1".into());
    }

    if let Ok(lines) = read_wordlist(wordlist) {
        for line in lines {
            if let Ok(l) = line {
                let pass: &str = l.trim();
                if hash == &hex::encode(sha1::Sha1::digest(pass.as_bytes())) {
                    println!("Pass found: {}", &pass);
                    return Ok(());
                } else {
                    return Err("SHA1 encryption failed".into());
                }
            }

        }
    }
    return Err("Pass not found in wordlist".into());
}

//TODO do the hash table computation by multithreading and file writing async
fn sha1_hash_table(wordlist: &str) -> serde_json::Value {
    let mut map = Map::new();

    if let Ok(lines) = read_wordlist(wordlist) {
        for line in lines {
            if let Ok(l) = line {
                let pass: String = l.trim().to_string();
                let hash: String = format!("{:x}", sha1::Sha1::digest(pass.as_bytes()));
                map.insert(pass, Value::String(hash));
            }
        }
    }
    let obj = Value::Object(map);
    obj
}


pub fn hash_table_to_file(wordlist: &str, filename: &str) {
    serde_json::to_writer(&File::create(filename).expect("[ERR] Can't open file"), &sha1_hash_table(wordlist)).expect("[ERR] json writer");
}



