use crate::*;
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{ aead::{Aead, KeyInit}, Aes256Gcm, Nonce };

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignCrypt {
  nonce: [u8; NONCEBYTES],
  ciphertext: Vec<u8>,
  sig: [u8; SIGNBYTES],
  curve: Curve,
}

pub fn signcrypt(
  sender_keys: &Keypair, recipient_public_key: &[u8; 32], msg: &[u8],
) -> Result<SignCrypt, SignCryptError>
{
  let mut crypt_key = [0u8; SHAREDBYTES];
  let mut sig = [0u8; SIGNBYTES];
  let mut st = SignState::default();
  let mut nonce = [0u8; NONCEBYTES];

  OsRng.fill_bytes(&mut nonce);

  sign_before(
    &mut st, &mut crypt_key, b"sender", b"recipient", &nonce, 
    &sender_keys.expose_secret(), recipient_public_key, &msg, sender_keys.curve
  )?;

  let cipher = Aes256Gcm::new(&crypt_key.into());
  // Use the high 96 bits of the signcrypt nonce
  let ciphertext = cipher.encrypt(Nonce::from_slice(&nonce[..12]), msg).unwrap();

  sign_after(
    &mut st, &mut sig, &sender_keys.expose_secret(), 
    &ciphertext, sender_keys.curve
  );
  Ok(SignCrypt { nonce, ciphertext, sig, curve: sender_keys.curve})
}

pub fn unsigncrypt(
  signcrypt: SignCrypt, sender_public_key: &[u8; 32], recipient_keys: &Keypair,
) -> Result<Vec<u8>, SignCryptError>
{
  let mut st = SignState::default();
  let mut crypt_key = [0u8; SHAREDBYTES];
  verify_before(
    &mut st, &mut crypt_key, &signcrypt.sig, b"sender",
    b"recipient", &signcrypt.nonce, &sender_public_key,
    &recipient_keys.expose_secret(), signcrypt.curve
  )?; 

  let cipher = Aes256Gcm::new(&crypt_key.into());
  let plaintext = cipher.decrypt(
    // Use the high 96 bits of the signcrypt nonce
    Nonce::from_slice(&signcrypt.nonce[..12]), &*signcrypt.ciphertext
  ).map_err(|_| SignCryptError::Decryption)?;

  verify_after(
    &mut st, &signcrypt.sig, &sender_public_key, 
    &signcrypt.ciphertext, signcrypt.curve
  )?;
  Ok(plaintext)
}