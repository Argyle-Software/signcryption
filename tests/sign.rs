use signcryption::*;
use rand::{rngs::OsRng, RngCore};

// TODO: incorrect aad / incorrect curve 

#[test]
fn before_ed25519() {
  for curve in [Curve::Ed25519, Curve::Ristretto255] {
    let mut state = SignState::default();
    let mut crypt_key = [0u8; SHAREDBYTES];
    let mut nonce = [0u8; NONCEBYTES];
    
    let alice = Keypair::new(curve);
    let bob = Keypair::new(curve);
    let msg = b"test";
  
    OsRng.fill_bytes(&mut nonce);
    sign_before(
      &mut state, &mut crypt_key, b"sender", b"recipient", &nonce, 
      &alice.expose_secret(), &bob.public, &*msg, curve
    ).unwrap();
  }
}

// #[test]
// fn after_ed25519() {

// }