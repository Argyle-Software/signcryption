use signcryption::*;

// Run through the full signcrypt workflow

#[test]
fn signcrypt_unsigncrypt_workflow() {
  let payload = b"All that is gold does not glitter";

  for curve in [Curve::Ed25519, Curve::Ristretto255] {
    let alice_keys = Keypair::new(curve);
    let bob_keys = Keypair::new(curve);

    let ciphertext = signcrypt(
      &alice_keys, &bob_keys.public.clone(), &payload[..]
    ).unwrap();

    let plaintext = unsigncrypt(
      ciphertext, &alice_keys.public.clone(), &bob_keys
    ).unwrap();

    assert_eq!(payload , &plaintext[..]);
  }
}