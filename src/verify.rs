use crate::*;
use libsodium_sys::*;
use subtle::ConstantTimeEq;
use std::ptr;

/// Convenience function for [`verify_before`]
pub fn ed25519_verify_before(
  st: &mut SignState, shared_key: &mut[u8; SHAREDBYTES], sig: &[u8; SIGNBYTES], 
  sender_id: &[u8], recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; BYTES], recipient_sk: &[u8; BYTES]
) -> Result<(), SignCryptError>
{
  verify_before(
    st, shared_key, sig, sender_id, recipient_id, 
    info, sender_pk, recipient_sk, Curve::Ed25519
  )
}
 
/// Convenience function for [`verify_before`]
pub fn ristretto255_verify_before(
  st: &mut SignState, shared_key: &mut[u8; SHAREDBYTES], sig: &[u8; SIGNBYTES], 
  sender_id: &[u8], recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; BYTES], recipient_sk: &[u8; BYTES]
) -> Result<(), SignCryptError>
{
  verify_before(
    st, shared_key, sig, sender_id, recipient_id, 
    info, sender_pk, recipient_sk, Curve::Ristretto255
  )
}

/// Message verification before decryption
pub fn  verify_before(
  st: &mut SignState, shared_key: &mut[u8; SHAREDBYTES], sig: &[u8; SIGNBYTES], 
  sender_id: &[u8], recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; BYTES], recipient_sk: &[u8; BYTES], curve: Curve
) -> Result<(), SignCryptError>
{
  let mut kp = [0u8; BYTES];
  let mut rs = [0u8; NONREDUCEDSCALARBYTES];

  if sender_id.len() > 0xff  || recipient_id.len() > 0xff  || info.len() > 0xff {
    return Err(SignCryptError::InvalidLength)
  }
  if !sc25519_is_canonical(&sig[BYTES..]) {
    return Err(SignCryptError::NonCanonicalSig)
  }
  rs[..SCALARBYTES].copy_from_slice(&sig[..SCALARBYTES]);

  unsafe {
    match curve {
      Curve::Ed25519 => {
        crypto_core_ed25519_scalar_reduce(rs.as_mut_ptr(), rs.as_ptr());
        if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), rs.as_ptr(), sender_pk.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
        crypto_core_ed25519_add(kp.as_mut_ptr(), sig.as_ptr(), kp.as_ptr());
        if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), recipient_sk.as_ptr(), kp.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
      }, 
      Curve::Ristretto255 => {
        if crypto_scalarmult_ristretto255(kp.as_mut_ptr(), rs.as_ptr(), sender_pk.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
        crypto_core_ristretto255_add(kp.as_mut_ptr(), sig.as_ptr(), kp.as_ptr());
        if crypto_scalarmult_ristretto255(kp.as_mut_ptr(), recipient_sk.as_ptr(), kp.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
      }
    }
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, SHAREDBYTES);
    crypto_generichash_update(&mut st.h, b"shared_key".as_ptr(),"shared_key".len() as u64);
    crypto_generichash_update(&mut st.h, kp.as_ptr(), kp.len() as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
    crypto_generichash_final(&mut st.h, shared_key.as_mut_ptr(), SHAREDBYTES);
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut st.h, sig.as_ptr(), BYTES as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
  }
  Ok(())
}


/// Message verification after decryption
pub fn verify_after(
  st: &mut SignState, sig: &[u8; SIGNBYTES], 
  sender_pk: &[u8; BYTES], c: &[u8], curve: Curve
)  -> Result<(), SignCryptError>
{
  let mut expected = [0u8; BYTES];
  let mut found = [0u8; BYTES];
  let mut nonreduced = [0u8; NONREDUCEDSCALARBYTES];

  unsafe {
    crypto_generichash_update(&mut st.h, c.as_ptr(), c.len() as u64);
    crypto_generichash_final(&mut st.h, nonreduced.as_mut_ptr(), nonreduced.len());

    match curve {
      Curve::Ed25519 => {
        crypto_core_ed25519_scalar_reduce(st.challenge.as_mut_ptr(), nonreduced.as_ptr());
  
        crypto_scalarmult_ed25519_base_noclamp(
          expected.as_mut_ptr(), sig[BYTES..].as_ptr()
        );
        crypto_core_ed25519_add(
          expected.as_mut_ptr(), expected.as_ptr(), sig.as_ptr()
        );
        if crypto_scalarmult_ed25519_noclamp(
          found.as_mut_ptr(), st.challenge.as_ptr(), sender_pk.as_ptr()
        ) != 0  {
          return Err(SignCryptError::Generic)
        }
      },
      Curve::Ristretto255 => {
        crypto_core_ristretto255_scalar_reduce(st.challenge.as_mut_ptr(), nonreduced.as_ptr());
  
        crypto_scalarmult_ristretto255_base(
          expected.as_mut_ptr(), sig[BYTES..].as_ptr()
        );
        crypto_core_ristretto255_add(
          expected.as_mut_ptr(), expected.as_ptr(), sig.as_ptr()
        );
        if crypto_scalarmult_ristretto255(
          found.as_mut_ptr(), st.challenge.as_ptr(), sender_pk.as_ptr()
        ) != 0  {
          return Err(SignCryptError::Generic)
        }
      }
    }
  }
  // Subtle constant time equality
  let eq: bool = expected[..SCALARBYTES].ct_eq(&found[..SCALARBYTES]).into();
  if !eq { return Err(SignCryptError::Mismatch) }
  Ok(())
}


/// Verifies the data was signed by a specific sender to a receiver without enabling
/// the ability to decrypt the ciphertext 
pub fn verify_public(
  sig: &[u8; SIGNBYTES],
  sender_id: &[u8],  recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; BYTES], c: &[u8], curve: Curve
) -> Result<(), SignCryptError>
{
  let mut st = SignState::default();

  if sender_id.len() > 0xff || recipient_id.len() > 0xff || info.len() > 0xff {
    return Err(SignCryptError::InvalidLength)
  }
  if !sc25519_is_canonical(&sig[BYTES..]) {
    return Err(SignCryptError::NonCanonicalSig) 
  }
  unsafe {
    crypto_generichash_init(&mut st.h, ptr::null(), 0, NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut st.h, sig.as_ptr(), BYTES as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
  }
  verify_after(&mut st, sig, sender_pk, c, curve)
}