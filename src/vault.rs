//! Encrypted secret files.
//!
//! One secret per file. Layout:
//!
//! ```text
//! "TKY1" | generation (16) | expiry, unix secs, BE (8) | XChaCha20 nonce (24) | ciphertext+tag
//! ```
//!
//! The first three fields are cleartext so readers can pick the right key and
//! prune expired files, but all of them are authenticated: the AEAD's associated
//! data is the header plus the keyset and key names. A file therefore cannot be
//! swapped with another key's file, moved to another keyset, or have its expiry
//! extended without decryption failing.

use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};

use crate::sys::Secret;

pub const KEY_LEN: usize = 32;
pub const GEN_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"TKY1";
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = 4 + GEN_LEN + 8;

pub type Generation = [u8; GEN_LEN];

pub struct Header {
    pub generation: Generation,
    pub expiry: u64,
}

pub fn hex(generation: &Generation) -> String {
    generation.iter().map(|b| format!("{b:02x}")).collect()
}

fn aad(header: &[u8], set: &str, name: &str) -> Vec<u8> {
    let mut a = header.to_vec();
    for part in [set, name] {
        a.push(0);
        a.extend_from_slice(part.as_bytes());
    }
    a
}

/// Parse and validate the cleartext header; does not authenticate it.
pub fn parse_header(file: &[u8]) -> Result<Header, String> {
    if file.len() < HEADER_LEN + NONCE_LEN || &file[..4] != MAGIC {
        return Err("not a tempkeys secret file".into());
    }
    Ok(Header {
        generation: file[4..4 + GEN_LEN].try_into().unwrap(),
        expiry: u64::from_be_bytes(file[4 + GEN_LEN..HEADER_LEN].try_into().unwrap()),
    })
}

pub fn encrypt(
    key: &[u8],
    generation: &Generation,
    expiry: u64,
    set: &str,
    name: &str,
    plaintext: &[u8],
    nonce: &[u8; NONCE_LEN],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + plaintext.len() + 16);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(generation);
    out.extend_from_slice(&expiry.to_be_bytes());
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key length")?;
    let sealed = cipher
        .encrypt(
            &XNonce::from(*nonce),
            Payload {
                msg: plaintext,
                aad: &aad(&out, set, name),
            },
        )
        .map_err(|_| "encryption failed")?;
    out.extend_from_slice(nonce);
    out.extend_from_slice(&sealed);
    Ok(out)
}

pub fn decrypt(key: &[u8], file: &[u8], set: &str, name: &str) -> Result<Secret, String> {
    parse_header(file)?;
    let (header, rest) = file.split_at(HEADER_LEN);
    let (nonce, sealed) = rest.split_at(NONCE_LEN);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| "bad key length")?;
    let nonce = XNonce::try_from(nonce).map_err(|_| "bad nonce")?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: sealed,
                aad: &aad(header, set, name),
            },
        )
        .map(Secret)
        .map_err(|_| "decryption failed: wrong key, or the file was modified or moved".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [7; KEY_LEN];
    const GEN: Generation = [1; GEN_LEN];
    const NONCE: [u8; NONCE_LEN] = [9; NONCE_LEN];

    fn seal(set: &str, name: &str, msg: &[u8]) -> Vec<u8> {
        encrypt(&KEY, &GEN, 1000, set, name, msg, &NONCE).unwrap()
    }

    #[test]
    fn round_trip_binary() {
        let msg = [0u8, 255, 10, 0, 42];
        let f = seal("s", "K", &msg);
        let h = parse_header(&f).unwrap();
        assert_eq!((h.generation, h.expiry), (GEN, 1000));
        assert_eq!(decrypt(&KEY, &f, "s", "K").unwrap().0, msg);
        assert!(!f.windows(msg.len()).any(|w| w == msg));
    }

    #[test]
    fn wrong_key_or_context_fails() {
        let f = seal("s", "K", b"v");
        assert!(decrypt(&[8; KEY_LEN], &f, "s", "K").is_err());
        assert!(decrypt(&KEY, &f, "s", "OTHER").is_err(), "swapped key name");
        assert!(decrypt(&KEY, &f, "t", "K").is_err(), "moved keyset");
    }

    #[test]
    fn tampering_fails() {
        let f = seal("s", "K", b"v");
        for i in [5, HEADER_LEN - 1, HEADER_LEN + 3, f.len() - 1] {
            let mut g = f.clone();
            g[i] ^= 1;
            assert!(decrypt(&KEY, &g, "s", "K").is_err(), "byte {i}");
        }
    }
}
