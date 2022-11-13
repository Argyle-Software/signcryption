use rand::{rngs::OsRng, RngCore};
use signcryption::*;
use libsodium_sys::*;

#[test]
fn signcrypt() -> Result<(),()> {
  let mut sender_pk = [0u8;  TBSBE_PUBLICKEYBYTES];
  let mut sender_sk = [0u8;  TBSBE_SECRETKEYBYTES];
  let mut recipient_pk = [0u8;  TBSBE_PUBLICKEYBYTES];
  let mut recipient_sk = [0u8;  TBSBE_SECRETKEYBYTES];
  let mut crypt_key = [0u8;  TBSBE_SHAREDBYTES];
  let mut sig = [0u8;  TBSBE_SIGNBYTES];
  let mut st = TbsbeSignState::default();
  let mut m: [u8; 4] = *b"test";
  let mut c = [0u8; 4 + crypto_secretbox_MACBYTES as usize];
  let mut nonce = [0u8; crypto_secretbox_NONCEBYTES as usize];

  // crypto_signcrypt_tbsbe_seed_keygen(&mut sender_pk, &mut sender_sk, &[1u8; TBSBE_SEEDBYTES]);
  // crypto_signcrypt_tbsbe_seed_keygen(&mut recipient_pk, &mut recipient_sk, &[42u8; TBSBE_SEEDBYTES]);

  crypto_signcrypt_tbsbe_keygen(&mut sender_pk, &mut sender_sk);
  crypto_signcrypt_tbsbe_keygen(&mut recipient_pk, &mut recipient_sk);
  
  let mut rng = OsRng;
  rng.fill_bytes(&mut nonce);


  /* sender-side */

  if (
    crypto_signcrypt_tbsbe_sign_before(
      // in this example, we simply use the encryption nonce as the info
      &mut st, &mut crypt_key, b"sender", b"recipient", &nonce, 
      &sender_sk, &recipient_pk, &m
    ).is_err() 
    || unsafe{
      let m_len = m.len() as u64;
      crypto_secretbox_easy(c.as_mut_ptr(), m.as_ptr(), m_len, nonce.as_ptr(), crypt_key.as_ptr()) != 0
    }  
    || crypto_signcrypt_tbsbe_sign_after(&mut st, &mut sig, &sender_sk, &c).is_err()) 
  {
    return Err(())
  }

  /* recipient-side */

  crypto_signcrypt_tbsbe_verify_before(
    &mut st, &mut crypt_key, &sig,   b"sender",
    b"recipient", &nonce, &sender_pk,
    &recipient_sk
  )?; 
  let secret_box = unsafe {
    crypto_secretbox_open_easy(m.as_mut_ptr(), c.as_ptr(), c.len() as u64, nonce.as_ptr(), crypt_key.as_ptr())
  };
  if secret_box != 0 {
    return Err(())
  }
  crypto_signcrypt_tbsbe_verify_after(&mut st, &sig, &sender_pk, &c)?;

  /* the sender can also be publicly verified */

  if crypto_signcrypt_tbsr_verify_public(
      &mut sig,   b"sender",
        b"recipient", &nonce, &sender_pk, &c).is_err() {
    return Err(());
  }

  return Ok(());
}