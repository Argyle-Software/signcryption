use crate::*;
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{ aead::{Aead, KeyInit}, Aes256Gcm, Nonce };

/// Data structure containing the ciphertext, signature and additional data
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SignCrypt {
  pub ciphertext: Vec<u8>,
  pub sig: [u8; SIGNBYTES],
  pub nonce: [u8; NONCEBYTES],
  pub curve: Curve,
}

/// Signs and encrypts a Message
/// 
/// This is a higher level function that runs through both `sign_before` and
/// `sign_after` and encrypts the message with RustCrypto's
/// [AES-GCM](https://docs.rs/aes-gcm/latest/aes_gcm/index.html) crate using AES256-GCM.  
/// 
/// The resulting `SignCrypt` struct is then passed to  [unsigncrypt](crate::unsigncrypt) for 
/// decryption and signature verification. 
/// 
/// # Example
/// ```
/// # use signcryption::*;
/// let alice = Keypair::default();
/// let bob = Keypair::default();
/// let msg = "Hello".as_bytes();
/// let encrypted = signcrypt(&alice, &bob.public, &msg).unwrap();
/// assert_eq!(encrypted.ciphertext.len(), msg.len() + MACBYTES);
/// ```
pub fn signcrypt(
  sender_keys: &Keypair, recipient_public_key: &[u8; 32], msg: &[u8],
) -> Result<SignCrypt, SignCryptError>
{
  let mut crypt_key = [0u8; SHAREDBYTES];
  let mut sig = [0u8; SIGNBYTES];
  let mut state = SignState::default();
  let mut nonce = [0u8; NONCEBYTES];

  OsRng.fill_bytes(&mut nonce);

  sign_before(
    &mut state, &mut crypt_key, b"sender", b"recipient", &nonce, 
    &sender_keys.expose_secret(), recipient_public_key, &msg, sender_keys.curve
  )?;

  let cipher = Aes256Gcm::new(&crypt_key.into());
  let ciphertext = cipher.encrypt(
    Nonce::from_slice(&nonce), msg
  ).map_err(|_| SignCryptError::Encryption)?;

  sign_after(
    &mut state, &mut sig, &sender_keys.expose_secret(), 
    &ciphertext, sender_keys.curve
  );
  Ok(SignCrypt { nonce, ciphertext, sig, curve: sender_keys.curve})
}

/// Verifies and decrypts a `SignCrypt` struct
/// 
/// This is a higher level function that runs through both `verify_before` and
/// `verify_after` and decrypts the message with RustCrypto's
/// [AES-GCM](https://docs.rs/aes-gcm/latest/aes_gcm/index.html) crate using AES256-GCM.
/// 
/// Return the plaintext.
/// 
/// # Example 
/// ```
/// # use signcryption::*;
/// # let alice = Keypair::default();
/// # let bob = Keypair::default();
/// let msg = "Hello".as_bytes();
/// let encrypted = signcrypt(&alice, &bob.public, &msg).unwrap();
/// let plaintext = unsigncrypt(encrypted, &alice.public, &bob).unwrap();
/// assert_eq!(msg, plaintext);
/// ```
pub fn unsigncrypt(
  signcrypt: SignCrypt, sender_public_key: &[u8; 32], recipient_keys: &Keypair,
) -> Result<Vec<u8>, SignCryptError>
{
  let mut state = SignState::default();
  let mut crypt_key = [0u8; SHAREDBYTES];
  verify_before(
    &mut state, &mut crypt_key, &signcrypt.sig, b"sender",
    b"recipient", &signcrypt.nonce, &sender_public_key,
    &recipient_keys.expose_secret(), signcrypt.curve
  )?; 

  let cipher = Aes256Gcm::new(&crypt_key.into());
  let plaintext = cipher.decrypt(
    Nonce::from_slice(&signcrypt.nonce), &*signcrypt.ciphertext
  ).map_err(|_| SignCryptError::Decryption)?;

  verify_after(
    &mut state, &signcrypt.sig, &sender_public_key, 
    &signcrypt.ciphertext, signcrypt.curve
  )?;
  Ok(plaintext)
}