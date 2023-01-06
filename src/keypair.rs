use crate::*;
use zeroize::{Zeroize, ZeroizeOnDrop}; 
use libsodium_sys::*;
use std::fmt;

/// A signcryption keypair used to sign, verify and encrypt messages.
/// 
/// Comes in two variants: [`Curve::Ed25519`] or [`Curve::Ristretto255`] 
#[derive(Clone, PartialEq)]
pub struct Keypair {
  /// The public portion of the keypair
  pub public: [u8; PUBLICKEYBYTES],
  secret: SecretKey,
  /// The curve used in key generation, using `Keypair::default()` it is Ristretto255
  pub curve: Curve
}

#[derive(Clone, PartialEq, Zeroize, ZeroizeOnDrop)]
struct SecretKey([u8; SCALARBYTES]);

impl Keypair {
  /// Generates a new keypair
  /// 
  /// # Example
  /// ```
  /// # use signcryption::*;
  /// let keys = Keypair::new(Curve::Ed25519);
  /// ```
  pub fn new(curve: Curve) -> Self {
    let mut public = [0u8; BYTES]; 
    let mut secret = SecretKey([0u8; SECRETKEYBYTES]);
    unsafe {
      match curve {
        Curve::Ed25519 => {
          crypto_core_ed25519_scalar_random(secret.0.as_mut_ptr());
          crypto_scalarmult_ed25519_base_noclamp(public.as_mut_ptr(), secret.0.as_ptr());
        },
        Curve::Ristretto255 => {
          crypto_core_ristretto255_scalar_random(secret.0.as_mut_ptr());
          crypto_scalarmult_ristretto255_base(public.as_mut_ptr(), secret.0.as_ptr());
        }
      }
    }
    Self {public, secret, curve}
  }

  /// Explicitly expose the secret key
  /// 
  /// # Example
  /// ```
  /// # use signcryption::*;
  /// let keys = Keypair::default();
  /// let secret = keys.expose_secret();
  /// ```
  pub fn expose_secret(&self) -> &[u8; SCALARBYTES] {
    &self.secret.0
  }

  /// Creates a new keypair from an existing secret key or provided bytes. The source
  /// must always be from a cryptographically secure RNG.
  /// 
  /// # Example
  /// ```
  /// # use signcryption::*;
  /// # use rand::RngCore;
  /// let mut secret_key = [0u8; SECRETKEYBYTES];
  /// rand::rngs::OsRng.fill_bytes(&mut secret_key);
  /// let keys = Keypair::from_secret(secret_key, Curve::Ristretto255);
  /// ``` 
  pub fn from_secret(secret_bytes: [u8; SECRETKEYBYTES], curve: Curve) -> Self {
    let mut public = [0u8; BYTES]; 
    let secret = SecretKey(secret_bytes);
    unsafe {
      match curve {
        Curve::Ed25519 => {
          crypto_scalarmult_ed25519_base_noclamp(public.as_mut_ptr(), secret.0.as_ptr());
        },
        Curve::Ristretto255 => {
          crypto_scalarmult_ristretto255_base(public.as_mut_ptr(), secret.0.as_ptr());
        }
      }
    }
    Self{public, secret, curve}
  }

  /// Creates a keypair from a 64 byte seed. Unless for testing purposes you 
  /// should always use a cryptographically secure source for the seed bytes.
  /// 
  /// # Example
  /// ```
  /// # use rand::RngCore;
  /// # use signcryption::*;
  /// let mut seed = [111u8; SEEDBYTES];
  /// Keypair::from_seed(&seed, Curve::Ed25519);
  /// ```
  pub fn from_seed(seed: &[u8; SEEDBYTES], curve: Curve) -> Self {
    let mut public = [0u8; BYTES]; 
    let mut secret = SecretKey([0u8; SECRETKEYBYTES]);
    unsafe {
      match curve {
        Curve::Ed25519 => {
          crypto_core_ed25519_scalar_reduce(secret.0.as_mut_ptr(), seed.as_ptr());
          crypto_scalarmult_ed25519_base_noclamp(public.as_mut_ptr(), secret.0.as_ptr());
        }, 
        Curve::Ristretto255 => {
          crypto_core_ristretto255_scalar_reduce(secret.0.as_mut_ptr(), seed.as_ptr());
          crypto_scalarmult_ristretto255_base(public.as_mut_ptr(), secret.0.as_ptr());
        }
      }
    }
    Keypair { public, secret, curve }
  }
}

/// `Keypair::default()` returns a [`Curve::Ristretto255`] keypair
impl Default for Keypair {
  fn default() -> Self {
      Keypair::new(Curve::Ristretto255)
  }
}

/// Debug will elide the secret key, to debug the secret key use the 
/// `Keypair::expose_secret()` function
impl fmt::Debug for Keypair {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    write!(
      f, 
      "Curve: {:?}\nPublic Key: {}\nSecret Key: <Elided>", 
      self.curve, encode_hex(&self.public)
    )
  }
}

fn encode_hex(bytes: &[u8]) -> String {
  let mut output = String::with_capacity(bytes.len() * 2);
  for b in bytes {
    output.push_str(&format!("{:02X}", b));
  }
  output
}