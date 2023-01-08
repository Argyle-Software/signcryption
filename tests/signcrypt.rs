use signcryption::*;

// Run through the full signcrypt process
#[test]
fn signcrypt_unsigncrypt_valid_workflow() {
  let msg = "All that is gold does not glitter".as_bytes();

  for curve in [Curve::Ed25519, Curve::Ristretto255] {
    let alice_keys = Keypair::new(curve);
    let bob_keys = Keypair::new(curve);

    let ciphertext = signcrypt(
      &alice_keys, &bob_keys.public.clone(), &msg
    ).unwrap();

    let plaintext = unsigncrypt(
      ciphertext, &alice_keys.public.clone(), &bob_keys
    ).unwrap();

    assert_eq!(msg , &plaintext[..]);
  }
}

// Ensure invalid public key is rejected by scalarmult_noclamp
#[test]
fn signcrypt_invalid_public_key() {
  let msg = "All that is gold does not glitter".as_bytes();

  for curve in [Curve::Ed25519, Curve::Ristretto255] {
    let alice_keys = Keypair::new(curve);
    let bob_keys = [0u8; 32];

    assert!(
      signcrypt(
        &alice_keys, &bob_keys, &msg
      ).is_err()
    );
  }
}