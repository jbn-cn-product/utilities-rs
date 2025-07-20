use utilities_rs::crypto;
use hex;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::TryRngCore;

#[test]
fn test_random_key_pair_generation() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk_bytes = hex::decode(sk_hex).unwrap();
    let pk_bytes = hex::decode(pk_hex).unwrap();

    assert_eq!(sk_bytes.len(), 32);
    assert_eq!(pk_bytes.len(), 32);

    // Verify that the public key derived from the secret key matches the generated public key
    let signing_key = SigningKey::from_bytes(sk_bytes.as_slice().try_into().unwrap());
    let verifying_key = VerifyingKey::from_bytes(pk_bytes.as_slice().try_into().unwrap()).unwrap();
    assert_eq!(signing_key.verifying_key().to_bytes(), verifying_key.to_bytes());
}

#[test]
fn test_sign_and_verify_valid_message() {
    let mut csprng = OsRng;
    let mut sk_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();

    let message = b"Hello, world!";
    let signature = crypto::sign(&sk_bytes, message);

    assert_eq!(signature.len(), 64);

    let is_valid = crypto::verify(&verifying_key.to_bytes(), &signature, message);
    assert!(is_valid);
}

#[test]
fn test_sign_and_verify_empty_message() {
    let mut csprng = OsRng;
    let mut sk_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();

    let message = b"";
    let signature = crypto::sign(&sk_bytes, message);

    assert_eq!(signature.len(), 64);

    let is_valid = crypto::verify(&verifying_key.to_bytes(), &signature, message);
    assert!(is_valid);
}

#[test]
fn test_verify_with_incorrect_signature() {
    let mut csprng = OsRng;
    let mut sk_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();

    let message = b"Hello, world!";
    let mut signature = crypto::sign(&sk_bytes, message);

    // Tamper with the signature
    signature[0] = signature[0].wrapping_add(1);

    let is_valid = crypto::verify(&verifying_key.to_bytes(), &signature, message);
    assert!(!is_valid);
}

#[test]
fn test_verify_with_incorrect_message() {
    let mut csprng = OsRng;
    let mut sk_bytes = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes).unwrap();
    let signing_key = SigningKey::from_bytes(&sk_bytes);
    let verifying_key = signing_key.verifying_key();

    let message = b"Hello, world!";
    let signature = crypto::sign(&sk_bytes, message);

    let tampered_message = b"Hello, world!!"; // Slightly different message
    let is_valid = crypto::verify(&verifying_key.to_bytes(), &signature, tampered_message);
    assert!(!is_valid);
}

#[test]
fn test_verify_with_incorrect_public_key() {
    let mut csprng = OsRng;
    let mut sk_bytes_1 = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes_1).unwrap();
    let signing_key_1 = SigningKey::from_bytes(&sk_bytes_1);
    let _verifying_key_1 = signing_key_1.verifying_key();

    let mut sk_bytes_2 = [0u8; 32];
    csprng.try_fill_bytes(&mut sk_bytes_2).unwrap();
    let signing_key_2 = SigningKey::from_bytes(&sk_bytes_2);
    let verifying_key_2 = signing_key_2.verifying_key();

    let message = b"Hello, world!";
    let signature = crypto::sign(&sk_bytes_1, message); // Signed with key 1

    // Try to verify with key 2
    let is_valid = crypto::verify(&verifying_key_2.to_bytes(), &signature, message);
    assert!(!is_valid);
}

#[test]
fn test_verify_with_invalid_public_key_bytes() {
    let invalid_pk_bytes = [0u8; 32]; // All zeros, likely an invalid public key
    let signature = [0u8; 64];
    let message = b"test";

    let is_valid = crypto::verify(&invalid_pk_bytes, &signature, message);
    assert!(!is_valid);
}
