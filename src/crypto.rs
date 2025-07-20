use ed25519_dalek::{Verifier, SigningKey, Signer, Signature, VerifyingKey};
use rand::{RngCore, rngs::OsRng};
use crate::LOG_PREFIX;

pub fn random() -> (String, String) {
    let mut csprng = OsRng;
    let mut sk = [0u8; 32];
    csprng.fill_bytes(&mut sk);
    let signk = SigningKey::from_bytes(&sk);
    let pk = signk.verifying_key().to_bytes();
    (
        hex::encode(&sk),
        hex::encode(&pk)
    )
}

pub fn sign(
    key: &[u8; 32],
    input: &[u8],
) -> [u8; 64] {
    let sk = SigningKey::from_bytes(key);
    sk.sign(input).to_bytes()
}

pub fn verify(
    key: &[u8; 32],
    sig: &[u8; 64],
    input: &[u8],
) -> bool {
    let res_vk = VerifyingKey::from_bytes(key);
    if let Err(e) = res_vk { 
        eprintln!("{} crypto-verify err={}", LOG_PREFIX, e);
        return false 
    }
    let vk = res_vk.unwrap();
    let sig = Signature::from_bytes(sig);
    match vk.verify(input, &sig) {
        Ok(_) => true,
        Err(_) => false,
    }
}