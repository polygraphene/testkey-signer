use sha2::Sha256;
use sha2::Sha512;
use sha2::Digest;

use crate::bindings::AvbAlgorithmType;
use crate::Result;

const SHA256_ALGOES: [u32; 3] = [
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA2048 as u32,
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA4096 as u32,
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA256_RSA8192 as u32,
];
const SHA512_ALGOES: [u32; 3] = [
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA2048 as u32,
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA4096 as u32,
    AvbAlgorithmType::AVB_ALGORITHM_TYPE_SHA512_RSA8192 as u32,
];

pub enum Hasher {
    Sha256(Sha256),
    Sha512(Sha512),
}

impl Hasher {
    pub fn new(algo_type: u32) -> Result<Self> {
        if SHA256_ALGOES.contains(&algo_type) {
            Ok(Hasher::Sha256(Sha256::new()))
        } else if SHA512_ALGOES.contains(&algo_type) {
            Ok(Hasher::Sha512(Sha512::new()))
        } else {
            Err(format!("Unknown algorithm type: {}", algo_type).into())
        }
    }

    pub fn new_by_name(name: &str) -> Result<Self> {
        if name == "sha256" {
            Ok(Hasher::Sha256(Sha256::new()))
        } else if name == "sha512" {
            Ok(Hasher::Sha512(Sha512::new()))
        } else {
            Err(format!("Unknown digest algorithm: {}", name).into())
        }
    }

    pub fn digest_size(algo_type: u32) -> Result<usize> {
        if SHA256_ALGOES.contains(&algo_type) {
            Ok(32)
        } else if SHA512_ALGOES.contains(&algo_type) {
            Ok(64)
        } else {
            Err(format!("Unknown algorithm type: {}", algo_type).into())
        }
    }

    pub fn update(&mut self, data: &[u8]) {
        match self {
            Hasher::Sha256(h) => h.update(data),
            Hasher::Sha512(h) => h.update(data),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            Hasher::Sha256(h) => h.finalize().to_vec(),
            Hasher::Sha512(h) => h.finalize().to_vec(),
        }
    }
}