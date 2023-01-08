use crate::*;
use libsodium_sys::*;
use std::ptr;
use rand::{RngCore, rngs::OsRng};

/// Convenience function for [`sign_before`]
pub fn ed25519_sign_before(
  state: &mut SignState,
  shared_key: &mut[u8; SHAREDBYTES], sender_id: &[u8], 
  recipient_id: &[u8], info: &[u8],
  sender_sk: &[u8; SCALARBYTES as usize],
  recipient_pk: &[u8; BYTES as usize], m: &[u8]
) -> Result<(), SignCryptError>
{
  sign_before(
    state, shared_key, sender_id, recipient_id, info, 
    sender_sk, recipient_pk, m, Curve::Ed25519
  )
}

/// Convenience function for [`sign_before`]
pub fn ristretto255_sign_before(
  state: &mut SignState,
  shared_key: &mut[u8; SHAREDBYTES], sender_id: &[u8], 
  recipient_id: &[u8], info: &[u8],
  sender_sk: &[u8; SCALARBYTES as usize],
  recipient_pk: &[u8; BYTES as usize], m: &[u8]
) -> Result<(), SignCryptError>
{
  sign_before(
    state, shared_key, sender_id, recipient_id, info, 
    sender_sk, recipient_pk, m, Curve::Ristretto255
  )
}

/// Message signing before encryption 
/// 
/// The additional associated data of `sender_id`, `recipient_id` and `info` has 
/// maximum length of 255 bytes. 
/// 
///  Example: 
/// ```
/// # use signcryption::*;
/// # 
/// let mut state = SignState::default();
/// 
/// ```
pub fn sign_before(
  state: &mut SignState,
  shared_key: &mut[u8; SHAREDBYTES], sender_id: &[u8], 
  recipient_id: &[u8], info: &[u8],
  sender_sk: &[u8; SECRETKEYBYTES],
  recipient_pk: &[u8; BYTES as usize], m: &[u8],
  curve: Curve
) -> Result<(), SignCryptError>
{
  let mut rs = [0u8; NONREDUCEDSCALARBYTES];
  let mut ks = [0u8; SCALARBYTES];
  let mut kp = [0u8; BYTES];
  let mut noise = [0u8; 32];

  if sender_id.len() > 0xff || recipient_id.len() > 0xff || info.len() > 0xff {
    return Err(SignCryptError::InvalidLength)
  }

  OsRng.fill_bytes(&mut noise);

  unsafe {
    crypto_generichash_init(&mut state.h, ptr::null(), 0, NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut state.h, b"nonce".as_ptr(), "nonce".len() as u64);
    crypto_generichash_update(&mut state.h, sender_sk.as_ptr(), SCALARBYTES as u64);
    crypto_generichash_update(&mut state.h, recipient_pk.as_ptr(), BYTES as u64);
    crypto_generichash_update(&mut state.h, noise.as_ptr(), noise.len() as u64);
    crypto_generichash_update(&mut state.h, m.as_ptr(), m.len() as u64);
    crypto_generichash_final(&mut state.h, rs.as_mut_ptr(), NONREDUCEDSCALARBYTES);
    
    match curve {
      Curve::Ed25519 => {
        crypto_core_ed25519_scalar_reduce(state.nonce.as_mut_ptr(), rs.as_ptr());
        if crypto_scalarmult_ed25519_base_noclamp(state.r.as_mut_ptr(), state.nonce.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
        rs[..SCALARBYTES].copy_from_slice(&state.r[..SCALARBYTES]);
        rs[SCALARBYTES..].fill(0);
        crypto_core_ed25519_scalar_reduce(rs.as_mut_ptr(), rs.as_ptr());
        crypto_core_ed25519_scalar_mul(ks.as_mut_ptr(), rs.as_ptr(), sender_sk.as_ptr());
        crypto_core_ed25519_scalar_add(ks.as_mut_ptr(), state.nonce.as_ptr(), ks.as_ptr());
        if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), ks.as_ptr(), recipient_pk.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
      } 
      Curve::Ristretto255 => {
        crypto_core_ristretto255_scalar_reduce(state.nonce.as_mut_ptr(), rs.as_ptr());
        if crypto_scalarmult_ristretto255_base(state.r.as_mut_ptr(), state.nonce.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
        // no reduction needed for ristretto
        rs[..BYTES].copy_from_slice(&state.r[..BYTES]);
        crypto_core_ristretto255_scalar_mul(ks.as_mut_ptr(), rs.as_ptr(), sender_sk.as_ptr());
        crypto_core_ristretto255_scalar_add(ks.as_mut_ptr(), state.nonce.as_ptr(), ks.as_ptr());
        if crypto_scalarmult_ristretto255(kp.as_mut_ptr(), ks.as_ptr(), recipient_pk.as_ptr()) != 0 {
          return Err(SignCryptError::Generic)
        }
      } 
    }
  
    crypto_generichash_init(&mut state.h, ptr::null(), 0, SHAREDBYTES);
    crypto_generichash_update(&mut state.h, b"shared_key".as_ptr(), "shared_key".len() as u64);
    crypto_generichash_update(&mut state.h, kp.as_ptr(), kp.len() as u64);
    lp_update(&mut state.h, sender_id);
    lp_update(&mut state.h, recipient_id);
    lp_update(&mut state.h, info);
    crypto_generichash_final(&mut state.h, shared_key.as_mut_ptr(), SHAREDBYTES);
  
    crypto_generichash_init(&mut state.h, ptr::null(), 0, NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut state.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut state.h, state.r.as_ptr(), BYTES as u64);
    lp_update(&mut state.h, sender_id);
    lp_update(&mut state.h, recipient_id);
    lp_update(&mut state.h, info);
  }
  Ok(())
}

/// Convenience function for [`sign_after`]
pub fn ed25519_sign_after(
  state: &mut SignState, sig: &mut[u8; SIGNBYTES],
  sender_sk: &[u8; SECRETKEYBYTES], ciphertext: &[u8]
)
{
  sign_after(state, sig, sender_sk, ciphertext, Curve::Ed25519)
}

/// Convenience function for [`sign_after`]
pub fn ristretto255_sign_after(
  state: &mut SignState, sig: &mut[u8; SIGNBYTES],
  sender_sk: &[u8; SECRETKEYBYTES], ciphertext: &[u8]
)
{
  sign_after(state, sig, sender_sk, ciphertext, Curve::Ristretto255)
}

/// Signing after encryption 
pub fn sign_after(
  state: &mut SignState, sig: &mut[u8; SIGNBYTES],
  sender_sk: &[u8; SECRETKEYBYTES], ciphertext: &[u8],
  curve: Curve
)
{
  let mut nonreduced = [0u8; NONREDUCEDSCALARBYTES];
  unsafe {
    crypto_generichash_update(&mut state.h, ciphertext.as_ptr(), ciphertext.len() as u64);
    crypto_generichash_final(&mut state.h, nonreduced.as_mut_ptr(), nonreduced.len());
    match curve {
      Curve::Ed25519 => {
        crypto_core_ed25519_scalar_reduce(state.challenge.as_mut_ptr(), nonreduced.as_ptr());
        crypto_core_ed25519_scalar_mul(
          sig[BYTES..].as_mut_ptr(), state.challenge.as_ptr(), sender_sk.as_ptr()
        );
        crypto_core_ed25519_scalar_sub(
          sig[BYTES..].as_mut_ptr(), sig[BYTES..].as_ptr(), state.nonce.as_ptr()
        );
      },
      Curve::Ristretto255 => {
        crypto_core_ristretto255_scalar_reduce(state.challenge.as_mut_ptr(), nonreduced.as_ptr());
        crypto_core_ristretto255_scalar_mul(
          sig[BYTES..].as_mut_ptr(), state.challenge.as_ptr(), sender_sk.as_ptr()
        );
        crypto_core_ristretto255_scalar_sub(
          sig[BYTES..].as_mut_ptr(), sig[BYTES..].as_ptr(), state.nonce.as_ptr()
        );
      }
    } 
    sig[..BYTES].copy_from_slice(&state.r[..BYTES]);
  }
}