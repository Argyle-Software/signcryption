use libsodium_sys::{
  crypto_generichash_state as HashState,
  crypto_core_ed25519_SCALARBYTES, 
  crypto_core_ed25519_BYTES, 
  crypto_generichash_init,
  crypto_generichash_update,
  crypto_generichash_final, crypto_core_ed25519_scalar_reduce, 
  crypto_scalarmult_ed25519_base_noclamp, crypto_core_ed25519_scalar_mul, 
  crypto_core_ed25519_scalar_add, crypto_scalarmult_ed25519_noclamp, 
  crypto_core_ed25519_add, crypto_core_ed25519_scalar_random, 
  crypto_core_ed25519_scalar_sub, crypto_core_ed25519_NONREDUCEDSCALARBYTES,
  crypto_generichash_blake2b_state,
}; 
// use curve25519_dalek::scalar::Scalar;
use std::ptr;
use rand::{RngCore, rngs::OsRng};
use subtle::ConstantTimeEq;

use crate::*;

const ED25519_SCALARBYTES: usize = crypto_core_ed25519_SCALARBYTES as usize;
const ED25519_BYTES: usize = crypto_core_ed25519_BYTES as usize;
const ED25519_NONREDUCEDSCALARBYTES: usize = crypto_core_ed25519_NONREDUCEDSCALARBYTES as usize;

// #[derive(Zeroize, ZeroizeOnDrop)]
pub struct TbsbeSignState {
  h: HashState,
  nonce: [u8; ED25519_SCALARBYTES],
  r: [u8; ED25519_BYTES],
  challenge: [u8; ED25519_SCALARBYTES]
}

impl Default for TbsbeSignState {
  fn default() -> Self {
    Self { 
      h: crypto_generichash_blake2b_state { opaque: [0u8; 384]}, 
      nonce: Default::default(), r: Default::default(), 
      challenge: Default::default() 
    }
  }
}

pub fn sc25519_is_canonical(s: &[u8]) -> bool
{
  let (mut c, mut n) = (0u8, 1u8);
  for i in (0..32).rev() {
    c |= ((s[i].wrapping_sub(L[i])).wrapping_shl(8)) & n;
    n &= ((s[i] ^ L[i]).wrapping_sub(1)).wrapping_shl(8);
  }
  c != 0
}

pub unsafe fn lp_update(h: &mut HashState, x: &[u8])
{
  let x_len = x.len() as u64;
  let x_len_u8 = x_len as u8;
  crypto_generichash_update(h, &x_len_u8, 1);
  crypto_generichash_update(h, x.as_ptr(), x_len);
  // h.update(&[x_len_u8]);
  // h.update(x);
}

pub fn crypto_signcrypt_tbsbe_sign_before(
  st: &mut TbsbeSignState,
  shared_key: &mut[u8; SHAREDBYTES], sender_id: &[u8], 
  recipient_id: &[u8], info: &[u8],
  sender_sk: &[u8; ED25519_SCALARBYTES as usize],
  recipient_pk: &[u8; ED25519_BYTES as usize], m: &[u8]
  
) -> Result<(), ()>
{
  let mut rs = [0u8; ED25519_NONREDUCEDSCALARBYTES];
  let mut ks = [0u8; ED25519_SCALARBYTES];
  let mut kp = [0u8; ED25519_BYTES];
  let mut noise = [0u8; 32];

  if sender_id.len() > 0xff || recipient_id.len() > 0xff || info.len() > 0xff {
    return Err(())
  }
  OsRng.fill_bytes(&mut noise);

  // st.h = State::new(Some(ED25519_NONREDUCEDSCALARBYTES), None)?;
  // st.h.update(b"nonce");
  // st.h.update(&sender_sk[..SCALARBYTES]);
  // st.h.update(&recipient_pk[..ED25519_BYTES]);
  // st.h.update(&noise);
  // st.h.update(&m);
  // let rs = st.h.finalize()?;

  unsafe {
    crypto_generichash_init(&mut st.h, ptr::null(), 0, ED25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"nonce".as_ptr(), "nonce".len() as u64);
    crypto_generichash_update(&mut st.h, sender_sk.as_ptr(), ED25519_SCALARBYTES as u64);
    crypto_generichash_update(&mut st.h, recipient_pk.as_ptr(), ED25519_BYTES as u64);
    crypto_generichash_update(&mut st.h, noise.as_ptr(), noise.len() as u64);
    crypto_generichash_update(&mut st.h, m.as_ptr(), m.len() as u64);
    crypto_generichash_final(&mut st.h, rs.as_mut_ptr(), ED25519_NONREDUCEDSCALARBYTES);
    crypto_core_ed25519_scalar_reduce(st.nonce.as_mut_ptr(), rs.as_ptr());
  
  
    if crypto_scalarmult_ed25519_base_noclamp(st.r.as_mut_ptr(), st.nonce.as_ptr()) != 0 {
      return Err(())
    }
    rs[..ED25519_SCALARBYTES].copy_from_slice(&st.r[..ED25519_SCALARBYTES]);
    rs[ED25519_SCALARBYTES..].fill(0);
    crypto_core_ed25519_scalar_reduce(rs.as_mut_ptr(), rs.as_ptr());
    crypto_core_ed25519_scalar_mul(ks.as_mut_ptr(), rs.as_ptr(), sender_sk.as_ptr());
    crypto_core_ed25519_scalar_add(ks.as_mut_ptr(), st.nonce.as_ptr(), ks.as_ptr());
    if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), ks.as_ptr(), recipient_pk.as_ptr()) != 0 {
      return Err(())
    }
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, SHAREDBYTES);
    crypto_generichash_update(&mut st.h, b"shared_key".as_ptr(), "shared_key".len() as u64);
    crypto_generichash_update(&mut st.h, kp.as_ptr(), kp.len() as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
    crypto_generichash_final(&mut st.h, shared_key.as_mut_ptr(), SHAREDBYTES);
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, ED25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut st.h, st.r.as_ptr(), ED25519_BYTES as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
  }

  Ok(())
}

pub fn crypto_signcrypt_tbsbe_sign_after(
  st: &mut TbsbeSignState,
  sig: &mut[u8; SIGNBYTES],
  sender_sk: &[u8; ED25519_SCALARBYTES], c: &[u8]
) -> Result<(),()>
{
  let mut nonreduced = [0u8; ED25519_NONREDUCEDSCALARBYTES];
  unsafe {
    crypto_generichash_update(&mut st.h, c.as_ptr(), c.len() as u64);
    crypto_generichash_final(&mut st.h, nonreduced.as_mut_ptr(), nonreduced.len());
    crypto_core_ed25519_scalar_reduce(st.challenge.as_mut_ptr(), nonreduced.as_ptr());
  
    crypto_core_ed25519_scalar_mul(sig[ED25519_BYTES..].as_mut_ptr(), st.challenge.as_ptr(), sender_sk.as_ptr());
    crypto_core_ed25519_scalar_sub(sig[ED25519_BYTES..].as_mut_ptr(), sig[ED25519_BYTES..].as_ptr(), st.nonce.as_ptr());
    sig[..ED25519_BYTES].copy_from_slice(&st.r[..ED25519_BYTES]);
  }
  Ok(())
}

pub fn  crypto_signcrypt_tbsbe_verify_before(
  st: &mut TbsbeSignState,
  shared_key: &mut[u8; SHAREDBYTES],
  sig: &[u8; SIGNBYTES], sender_id: &[u8],
  recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; ED25519_BYTES],
  recipient_sk: &[u8; ED25519_BYTES]
) -> Result<(),()>
{
  let mut kp = [0u8; ED25519_BYTES];
  let mut rs = [0u8; ED25519_NONREDUCEDSCALARBYTES];

  if sender_id.len() > 0xff || recipient_id.len() > 0xff || info.len() > 0xff 
    || !sc25519_is_canonical(&sig[ED25519_BYTES..]) {
    return Err(())
  }
  rs[..ED25519_SCALARBYTES].copy_from_slice(&sig[..ED25519_SCALARBYTES]);

  unsafe {
    crypto_core_ed25519_scalar_reduce(rs.as_mut_ptr(), rs.as_ptr());
    if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), rs.as_ptr(), sender_pk.as_ptr()) != 0 {
      return Err(())
    }
    crypto_core_ed25519_add(kp.as_mut_ptr(), sig.as_ptr(), kp.as_ptr());
    if crypto_scalarmult_ed25519_noclamp(kp.as_mut_ptr(), recipient_sk.as_ptr(), kp.as_ptr()) != 0 {
      return Err(())
    }
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, SHAREDBYTES);
    crypto_generichash_update(&mut st.h, b"shared_key".as_ptr(),"shared_key".len() as u64);
    crypto_generichash_update(&mut st.h, kp.as_ptr(), kp.len() as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
    crypto_generichash_final(&mut st.h, shared_key.as_mut_ptr(), SHAREDBYTES);
  
    crypto_generichash_init(&mut st.h, ptr::null(), 0, ED25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut st.h, sig.as_ptr(), ED25519_BYTES as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
  }

  Ok(())
}

pub fn crypto_signcrypt_tbsbe_verify_after(st: &mut TbsbeSignState,
                    sig: &[u8; SIGNBYTES],
                    sender_pk: &[u8; ED25519_BYTES],
                    c: &[u8]
                    )  -> Result<(),()>
{
  let mut check_expected = [0u8; ED25519_BYTES];
  let mut check_found = [0u8; ED25519_BYTES];
  let mut nonreduced = [0u8; ED25519_NONREDUCEDSCALARBYTES];
  let r = sig;

  unsafe {
    crypto_generichash_update(&mut st.h, c.as_ptr(), c.len() as u64);
    crypto_generichash_final(&mut st.h, nonreduced.as_mut_ptr(), nonreduced.len());
    crypto_core_ed25519_scalar_reduce(st.challenge.as_mut_ptr(), nonreduced.as_ptr());
  
    crypto_scalarmult_ed25519_base_noclamp(check_expected.as_mut_ptr(), sig[ED25519_BYTES..].as_ptr());
    crypto_core_ed25519_add(check_expected.as_mut_ptr(), check_expected.as_ptr(), r.as_ptr());
  
    if crypto_scalarmult_ed25519_noclamp(
      check_found.as_mut_ptr(), st.challenge.as_ptr(), sender_pk.as_ptr()
    ) != 0  {
      return Err(())
    }
  }

  
  let eq: bool = check_expected[..ED25519_SCALARBYTES].ct_eq(&check_found[..ED25519_SCALARBYTES]).into();
  if !eq { return Err(()) }
  Ok(())
}

pub fn crypto_signcrypt_tbsr_verify_public(
  sig: &mut[u8; SIGNBYTES],
  sender_id: &[u8],  recipient_id: &[u8], info: &[u8],
  sender_pk: &[u8; ED25519_BYTES], c: &[u8]
) -> Result<(),()>
{
  let mut st = TbsbeSignState::default();

  if sender_id.len() > 0xff || recipient_id.len() > 0xff || info.len() > 0xff ||
    !sc25519_is_canonical(&sig[ED25519_BYTES..]) {
    return Err(())
  }
  unsafe {
    crypto_generichash_init(&mut st.h, ptr::null(), 0, ED25519_NONREDUCEDSCALARBYTES);
    crypto_generichash_update(&mut st.h, b"sign_key".as_ptr(), "sign_key".len() as u64);
    crypto_generichash_update(&mut st.h, sig.as_ptr(), ED25519_BYTES as u64);
    lp_update(&mut st.h, sender_id);
    lp_update(&mut st.h, recipient_id);
    lp_update(&mut st.h, info);
  }

  crypto_signcrypt_tbsbe_verify_after(&mut st, sig, sender_pk, c)
}

pub fn crypto_signcrypt_tbsbe_keygen(
  pk: &mut[u8; ED25519_BYTES],
  sk: &mut[u8; ED25519_SCALARBYTES]
)
{
  unsafe {
    crypto_core_ed25519_scalar_random(sk.as_mut_ptr());
    crypto_scalarmult_ed25519_base_noclamp(pk.as_mut_ptr(), sk.as_ptr());
  }
}

pub fn crypto_signcrypt_tbsbe_seed_keygen(
  pk: &mut[u8; ED25519_BYTES],
  sk: &mut[u8; ED25519_SCALARBYTES],
  seed: &[u8; SEEDBYTES]
)
{
  unsafe {
    crypto_core_ed25519_scalar_reduce(sk.as_mut_ptr(), seed.as_ptr());
    crypto_scalarmult_ed25519_base_noclamp(pk.as_mut_ptr(), sk.as_ptr());
  }
}
