use crate::{LOG_PREFIX, crypto};

pub const LEN_KEY: usize = 32;
pub const LEN_SIG: usize = 64;
pub const LEN_MSG: usize = 2;

// len([u8; 2]) + msg([u8]) + signature([u8; LEN_SIG]) + id([u8])
pub fn encode(
    key: &[u8; LEN_KEY],
    id: &str,
    input: &[u8]
) -> Vec<u8> {
    let sig: [u8; LEN_SIG] = crypto::sign(key, input);
    let len: [u8; LEN_MSG] = (input.len() as u16).to_be_bytes();
    let mut output = Vec::new();
    output.extend_from_slice(&len);
    output.extend_from_slice(input);
    output.extend_from_slice(&sig);
    output.extend_from_slice(id.as_bytes());
    output
}

// len([u8; 2]) + msg([u8]) + signature([u8; LEN_SIG]) + id([u8])
pub fn decode(
    key: &[u8; LEN_KEY],
    input: &[u8]
) -> Option<(
    Vec<u8>,  // 
    [u8; LEN_SIG], // signature
    String,   // id
)>{
    let len = input.len();
    if len < LEN_SIG + LEN_MSG { 
        eprintln!("{} codec-decode invalid-len-0={}", LOG_PREFIX, len);
        return None; 
    }
    let len = u16::from_be_bytes(input[0 .. LEN_MSG].try_into().unwrap()) as usize;
    let msg_start = LEN_MSG;
    let msg_end = msg_start + len;
    let sig_start = msg_end;
    let sig_end = sig_start + LEN_SIG;
    if input.len() < sig_end {
        eprintln!("{} codec-decode invalid-len-1={}", LOG_PREFIX, input.len());
        return None;
    }
    let msg = &input[msg_start .. msg_end];
    let mut sig: [u8; LEN_SIG] = [0; LEN_SIG];
    sig.copy_from_slice(&input[sig_start .. sig_end]);
    if !crypto::verify(key, &sig, msg) {
        eprintln!("{} codec-decode invalid-sig", LOG_PREFIX);
        return None;
    }
    let id = &input[sig_end..];
    Some((msg.to_vec(), sig, String::from_utf8_lossy(id).into_owned()))
}