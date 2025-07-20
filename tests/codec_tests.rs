#![allow(unused_variables)]
use utilities_rs::{
    codec:: {self, LEN_KEY, LEN_MSG, LEN_SIG}, crypto};
use hex;

// Helper to convert hex string secret key to [u8; LEN_KEY]
fn sk_from_hex(sk_hex: &str) -> [u8; LEN_KEY] {
    let sk_vec = hex::decode(sk_hex).unwrap();
    sk_vec.try_into().unwrap()
}

// Helper to convert hex string public key to [u8; LEN_KEY]
fn pk_from_hex(pk_hex: &str) -> [u8; LEN_KEY] {
    let pk_vec = hex::decode(pk_hex).unwrap();
    pk_vec.try_into().unwrap()
}

#[test]
fn test_encode_decode_simple_message() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"This is a test message.";
    let id = "test_id_123";

    let signature = crypto::sign(&sk, message);
    let encoded = codec::encode(message, &signature, id);
    let decoded = codec::decode(&encoded).unwrap();

    assert_eq!(decoded.0, message.to_vec());
    assert_eq!(decoded.2.as_bytes(), id.as_bytes());

    // Verify the signature separately using the crypto module
    assert!(crypto::verify(&pk, &decoded.1, &decoded.0));
}

#[test]
fn test_encode_decode_empty_message() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"";
    let id = "empty_msg_id";

    let signature = crypto::sign(&sk, message);
    let encoded = codec::encode(message, &signature, id);
    let decoded = codec::decode(&encoded).unwrap();

    assert_eq!(decoded.0, message.to_vec());
    assert_eq!(decoded.2.as_bytes(), id.as_bytes());

    assert!(crypto::verify(&pk, &decoded.1, &decoded.0));
}

#[test]
fn test_encode_decode_long_message() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let long_message = vec![0u8; 1000]; // 1KB message
    let id = "long_msg_id";

    let signature = crypto::sign(&sk, &long_message);
    let encoded = codec::encode(&long_message, &signature, id);
    let decoded = codec::decode(&encoded).unwrap();

    assert_eq!(decoded.0, long_message);
    assert_eq!(decoded.2.as_bytes(), id.as_bytes());

    assert!(crypto::verify(&pk, &decoded.1, &decoded.0));
}

#[test]
fn test_decode_invalid_signature() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"message with bad sig";
    let id = "bad_sig_id";

    let signature = crypto::sign(&sk, message);
    let mut encoded = codec::encode(message, &signature, id);
    // Tamper with the signature part of the encoded message
    let msg_len = (message.len() as u16).to_be_bytes().len();
    let sig_start = msg_len + message.len();
    encoded[sig_start] = encoded[sig_start].wrapping_add(1);

    let decoded = codec::decode(&encoded).unwrap();
    assert!(!crypto::verify(&pk, &decoded.1, &decoded.0));
}

#[test]
fn test_decode_tampered_message() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"original message";
    let id = "tampered_msg_id";

    let signature = crypto::sign(&sk, message);
    let mut encoded = codec::encode(message, &signature, id);
    // Tamper with the message part of the encoded message
    let msg_start = LEN_MSG; // After length prefix
    encoded[msg_start] = encoded[msg_start].wrapping_add(1);

    let decoded = codec::decode(&encoded).unwrap();
    assert!(!crypto::verify(&pk, &decoded.1, &decoded.0));
}

#[test]
fn test_decode_with_incorrect_key() {
    let (sk_hex_1, pk_hex_1) = crypto::random().unwrap();
    let sk_1 = sk_from_hex(&sk_hex_1);
    let _pk_1 = pk_from_hex(&pk_hex_1);

    let (_sk_hex_2, pk_hex_2) = crypto::random().unwrap(); // Generate a different key pair
    let pk_2 = pk_from_hex(&pk_hex_2);

    let message = b"message for wrong key";
    let id = "wrong_key_id";

    let signature = crypto::sign(&sk_1, message);
    let encoded = codec::encode(message, &signature, id);
    // Try to decode with the wrong public key
    let decoded = codec::decode(&encoded).unwrap();
    assert!(!crypto::verify(&pk_2, &decoded.1, &decoded.0));
}

#[test]
fn test_decode_truncated_input_too_short_for_len_prefix() {
    let (_sk_hex, pk_hex) = crypto::random().unwrap();
    let pk = pk_from_hex(&pk_hex);

    let input = vec![0u8; 1]; // Too short for even the length prefix
    let decoded = codec::decode(&input);
    assert!(decoded.is_none());
}

#[test]
fn test_decode_truncated_input_missing_signature() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"short message";
    let id = "short_id";

    let signature = crypto::sign(&sk, message);
    let encoded = codec::encode(message, &signature, id);
    // Truncate before the signature is complete
    let truncated_encoded = encoded[0..encoded.len() - LEN_KEY].to_vec(); // Remove half of signature + id
    let decoded = codec::decode(&truncated_encoded);
    assert!(decoded.is_none());
}

#[test]
fn test_decode_truncated_input_missing_id() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"message with missing id";
    let id = "some_id";

    let signature = crypto::sign(&sk, message);
    let encoded = codec::encode(message, &signature, id);
    // Truncate just before the ID starts
    let sig_start = LEN_MSG + message.len();
    let sig_end = sig_start + LEN_SIG;
    let truncated_encoded = encoded[0..sig_end].to_vec();
    let decoded = codec::decode(&truncated_encoded).unwrap();
    assert_eq!(decoded.2, "".to_string());
}

#[test]
fn test_decode_message_length_exceeds_input_length() {
    let (_sk_hex, pk_hex) = crypto::random().unwrap();
    let pk = pk_from_hex(&pk_hex);

    let mut encoded_data = vec![0u8; 100];
    // Manually set a message length that is too large for the actual input
    let large_len: u16 = 500; // Message length is 500, but input is only 100 bytes
    encoded_data[0..2].copy_from_slice(&large_len.to_be_bytes());

    // Fill some dummy data for the rest to make it a valid slice length
    // (though the internal message length will cause issues)
    let decoded = codec::decode(&encoded_data);
    assert!(decoded.is_none());
}

#[test]
fn test_encode_decode_id_with_special_chars() {
    let (sk_hex, pk_hex) = crypto::random().unwrap();
    let sk = sk_from_hex(&sk_hex);
    let pk = pk_from_hex(&pk_hex);

    let message = b"message with special id";
    let id = "!@#$%^&*()_+{}[]|\\;:'\",.<>/?`~";

    let signature = crypto::sign(&sk, message);
    let encoded = codec::encode(message, &signature, id);
    let decoded = codec::decode(&encoded).unwrap();

    assert_eq!(decoded.0, message.to_vec());
    assert_eq!(decoded.2, id.to_string());
}
