use num_bigint::BigInt;
use num_bigint::IntoBigInt;
use num_bigint::ModInverse;
use num_integer::Integer;
use rsa::{pkcs1::FromRsaPublicKey, pkcs8::FromPublicKey, BigUint, PublicKeyParts, RsaPublicKey};
use std::{collections::HashMap, fs, io, path::Path, time::Instant};

fn read_pems(dir: &Path) -> io::Result<HashMap<String, RsaPublicKey>> {
    let mut pub_keys: HashMap<String, RsaPublicKey> = HashMap::new();

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let f_name = String::from(entry.file_name().to_string_lossy());
            if f_name.contains(".pem") {
                if path.is_file() {
                    println!("\t--> key file {}", f_name);
                    let pub_key = RsaPublicKey::read_pkcs1_pem_file(&path);
                    match pub_key {
                        Ok(k) => pub_keys.insert(f_name, k),
                        Err(_e) => {
                            let pub_key = RsaPublicKey::read_public_key_pem_file(&path).unwrap();
                            pub_keys.insert(f_name, pub_key)
                        }
                    };
                } else {
                    continue;
                }
            } else {
                continue;
            }
        }
    }
    Ok(pub_keys)
}

#[derive(Debug)]
struct VulnK {
    files: (String, String),
    p: BigUint,
    n1: BigUint,
    n2: BigUint,
    e: BigUint,
}

impl VulnK {
    fn new(fs: (String, String), p: BigUint, n1: BigUint, n2: BigUint, e: BigUint) -> Self {
        Self {
            files: fs,
            p,
            n1,
            n2,
            e,
        }
    }
}

fn vuln_keys(pub_keys: HashMap<String, RsaPublicKey>) -> Vec<VulnK> {
    let mut vulns: Vec<VulnK> = Vec::new();
    for (k, v) in &pub_keys {
        for (k1, v1) in &pub_keys {
            if v1 != v {
                let n1 = v.n();
                let n2 = v1.n();
                let p = n1.gcd(n2);

                if p > BigUint::from(1u32) {
                    println!("\t--> Vulnerable file: {}", k);
                    let vuln = VulnK::new(
                        (k.to_string(), k1.to_string()),
                        n1.to_owned(),
                        n2.to_owned(),
                        p,
                        v.e().to_owned(),
                    );
                    vulns.push(vuln);
                }
            }
        }
    }
    vulns
}

pub fn gcd_rsa() {
    let t = Instant::now();
    println!("[LOG] Collecting all key files");
    let pub_keys = read_pems(std::path::Path::new("./rsa/challenge")).unwrap();
    println!("[LOG] Filtering for vulnerable files");
    let vuln_keys = vuln_keys(pub_keys);
    println!("");

    for key in vuln_keys {
        let q = key.n1.clone() / key.p.clone();
        let mut m = key.n1.into_bigint().unwrap()
            - (key.p.into_bigint().unwrap() + q.into_bigint().unwrap() - 1u32);
        if m > BigInt::from(0u32) {
            let priv_key = key.e.mod_inverse(m).unwrap();
            println!("{:?}\n{}", key.files, priv_key)
        } else {
            println!("[TODO] m is negative");
        }
    }
    let el = t.elapsed();
    println!("Finished in: {:?}", el);
}

//TODO message signing
